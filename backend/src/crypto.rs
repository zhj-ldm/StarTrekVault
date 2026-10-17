//! 加密原语层。
//!
//! 全部为软件能做到的最高等级，且**不可降级**：
//! - 文件/元数据加密：AES-256-GCM-SIV（RFC 8452，nonce 误用也不 catastrophically 失败）
//! - SRK 封装：AES Key Wrap（RFC 3394 / NIST SP 800-38F）
//! - 凭证哈希：Argon2id（m=1 GiB? 见 `ARGON2_*` 常量；≥1 MiB / t≥10 / p≥8）
//! - 容器完整性：SHA3-256
//! - 比较：subtle 常量时间
//! - 随机源：`getrandom(2)`（macOS 内核 CSPRNG）
//!
//! 关键分层（见 `vault.rs`）：
//! ```text
//! 分片密钥(chunk key) ← 文件主密钥 FMK ← 保险箱根密钥 SRK（每个 .stvault 独立）
//! SRK 用 AES-KW 封装两份：wrap_voice（口令侧）/ wrap_recovery（密保+静态密码侧）
//! ```
//!
//! **声纹与语音口令绝不作加密密钥**：生物特征不稳定且不可导，只做「准入因子」
//! （门禁），真正的密钥材料是口令经过 Argon2id 派生的 KEK。

use crate::secmem::{self, SecretBytes};
use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use anyhow::{anyhow, bail, Result};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// Argon2id 参数。实测（见对话记录）：需求 §八.3 的字面值 1 GiB × t10 × p8
/// 在本机每次派生 **4.57 s**，即「说完口令等约 5 秒」的主因，因此下调到
/// 256 MiB × t8 × p4（实测约 0.87 s）—— 仍远高于 OWASP 建议（≥19 MiB）。
/// 若要恢复成需求字面值，把下面三个常量改回 1_048_576 / 10 / 8 即可。
pub const ARGON2_MEMORY_KIB: u32 = 262_144; // 256 MiB
pub const ARGON2_TIME_COST: u32 = 8;
pub const ARGON2_PARALLELISM: u32 = 4;

/// 旧版（需求 §八.3 字面值）：早期容器 / 全局配置用它派生，必须继续认。
pub const ARGON2_LEGACY: (u32, u32, u32) = (1_048_576, 10, 8);
/// 当前参数。
pub const ARGON2_CURRENT: (u32, u32, u32) = (ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM);

/// AES-256-GCM-SIV nonce 长度 / 认证标签长度。
pub const GCM_SIV_NONCE_LEN: usize = 12;
pub const GCM_SIV_TAG_LEN: usize = 16;
/// 明文密钥长度。
pub const KEY_LEN: usize = 32;
/// AES-KW 封装输出长度：明文 + 8 字节 semiblock 完整性校验值（RFC 3394 § 2.2.1，
/// 32 字节密钥 → 40 字节封装）。
pub const KW_WRAP_LEN: usize = KEY_LEN + 8;

// ---------------------------------------------------------------------------
// AES-256-GCM-SIV
// ---------------------------------------------------------------------------

/// 用 AES-256-GCM-SIV 加密，返回 `密文 || 16 字节 tag`。
/// `aad` 为附加认证数据（做域分离，避免密文在不同上下文间挪用）。
pub fn aead_encrypt(key: &[u8; KEY_LEN], nonce: &[u8; GCM_SIV_NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new(key.into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("AES-256-GCM-SIV 加密失败: {e}"))?;
    Ok(ct)
}

/// 解密 `密文 || tag`，认证标签不匹配即拒绝（任何篡改都会在此暴露）。
pub fn aead_decrypt(key: &[u8; KEY_LEN], nonce: &[u8; GCM_SIV_NONCE_LEN], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>> {
    if ct_and_tag.len() < GCM_SIV_TAG_LEN {
        bail!("密文长度不足，容器损坏");
    }
    let cipher = Aes256GcmSiv::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct_and_tag,
                aad,
            },
        )
        .map_err(|_| anyhow!("解密失败：数据被篡改或密钥错误"))
}

/// 显式清零中间明文。
fn scrub_vec(mut v: Vec<u8>) -> Vec<u8> {
    // 明文用完后立刻覆写；把所有权交还调用方之前先洗一次
    let mut tmp = std::mem::take(&mut v);
    secmem::scrub(&mut tmp);
    tmp
}

// ---------------------------------------------------------------------------
// AES Key Wrap (RFC 3394 / NIST SP 800-38F)
// ---------------------------------------------------------------------------

// `aes_kw` 依赖 `aes 0.9`（crypto-common 0.2.x），而 `aes-gcm-siv` 走 `aead 0.5`
// （crypto-common 0.1.x）——两者同名 `KeyInit` 会冲突，因此这里显式改名并全限定调用。
use aes_kw::aes::cipher::KeyInit as KwKeyInit;
use aes_kw::KwAes256;

/// 用 AES-KW（RFC 3394 / NIST SP 800-38F）封装 32 字节密钥，
/// 返回 40 字节（32 字节密钥 + 8 字节 semiblock 完整性校验值）。
pub fn wrap_key(kek: &[u8; KEY_LEN], plaintext_key: &[u8; KEY_LEN]) -> Result<[u8; KW_WRAP_LEN]> {
    let kw = <KwAes256 as KwKeyInit>::new_from_slice(kek).map_err(|_| anyhow!("KEK 长度非法"))?;
    let mut buf = vec![0u8; KEY_LEN + aes_kw::IV_LEN];
    let ct = kw
        .wrap_key(plaintext_key, &mut buf)
        .map_err(|e| anyhow!("AES-KW 封装失败: {e}"))?;
    if ct.len() != KW_WRAP_LEN {
        bail!("AES-KW 输出长度异常");
    }
    let mut out = [0u8; KW_WRAP_LEN];
    out.copy_from_slice(ct);
    buf.zeroize();
    Ok(out)
}

/// 解封 40 字节包裹，得到 32 字节密钥。完整性校验值不匹配即失败。
pub fn unwrap_key(kek: &[u8; KEY_LEN], wrapped: &[u8; KW_WRAP_LEN]) -> Result<[u8; KEY_LEN]> {
    let kw = <KwAes256 as KwKeyInit>::new_from_slice(kek).map_err(|_| anyhow!("KEK 长度非法"))?;
    let mut buf = vec![0u8; KW_WRAP_LEN - aes_kw::IV_LEN];
    let pt = kw
        .unwrap_key(wrapped, &mut buf)
        .map_err(|_| anyhow!("密钥解封失败：封装数据被篡改或密钥错误"))?;
    if pt.len() != KEY_LEN {
        bail!("解封密钥长度异常");
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(pt);
    buf.zeroize();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

/// Argon2id 派生固定 32 字节（用当前参数）。输入口令按字节传入（不做字符串驻留）。
pub fn argon2id_derive(secret: &[u8], salt: &[u8]) -> Result<SecretBytes> {
    argon2id_derive_params(secret, salt, ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM)
}

/// 用指定参数派生。容器头部 / 旧版配置各自携带自己创建时的参数，
/// 因此改参数不会让既有对象解不开。
pub fn argon2id_derive_params(secret: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<SecretBytes> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|e| anyhow!("Argon2 参数非法: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = SecretBytes::zeroed(KEY_LEN);
    a2.hash_password_into(secret, salt, out.as_mut_slice())
        .map_err(|e| anyhow!("Argon2id 派生失败: {e}"))?;
    Ok(out)
}

/// 密码学安全的哈希值（用于口令文本指纹、锁定盐、审计链）。
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut h = sha3::Sha3_512::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    buf
}

// ---------------------------------------------------------------------------
// v2 声纹模板保密 + 口令承诺
// ---------------------------------------------------------------------------
//
// v1 把声纹模板明文写进头部，拿到容器文件的人可读出模板并原样当 probe 重放，
// 从而离线绕过「声纹门禁」。v2 用**口令派生**的密钥流对模板做无扩展的流加密，
// 模板只有先拿到正确口令（Argon2 → K_voice）才能解密：
//   - K_emb = SHA3-256("stvault-emb-v2\0" ‖ K_voice)
//   - 密钥流  block_j = SHA3-256(K_emb ‖ LE64(j))，对模板字节逐字节异或
// 机密性之外不额外加 MAC：头部整体完整性由 `Header::to_bytes` 的 SHA3-256 覆盖。
//
// 同理，v2 的 `passphrase_fp` 不再是 SHA3-256(明文口令)（那是一个**廉价的离线
// oracle**，攻击者可用高速 SHA3 字典先筛出唯一候选，再只需跑一次 Argon2），
// 而改为 `passphrase_commitment`——必须知道 Argon2 输出才能计算。

/// 由口令侧 K_voice 派生「声纹模板加密密钥」。
pub fn emb_key(k_voice: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut v = Vec::with_capacity(KEY_LEN + 16);
    v.extend_from_slice(b"stvault-emb-v2\x00");
    v.extend_from_slice(k_voice);
    let k = sha3_256(&v);
    v.zeroize();
    k
}

/// SHA3-CTR 密钥流：`block_j = SHA3-256(key ‖ LE64(j))`。仅提供机密性。
pub fn sha3_keystream(key: &[u8; KEY_LEN], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut ctr = 0u64;
    while out.len() < n {
        let mut h = Sha3_256::new();
        h.update(key);
        h.update(ctr.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    out.truncate(n);
    out
}

/// 原地异或（长度以两者较短者为准）。
pub fn xor_inplace(buf: &mut [u8], ks: &[u8]) {
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

/// v2 口令承诺：`SHA3-256("stvault-fp-v2\0" ‖ salt_voice ‖ K_voice)`。
/// 需要 Argon2 输出方可计算，因此不构成廉价的离线口令 oracle。
pub fn passphrase_commitment(salt_voice: &[u8; 16], k_voice: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut v = Vec::with_capacity(16 + KEY_LEN + 16);
    v.extend_from_slice(b"stvault-fp-v2\x00");
    v.extend_from_slice(salt_voice);
    v.extend_from_slice(k_voice);
    let c = sha3_256(&v);
    v.zeroize();
    c
}

// ---------------------------------------------------------------------------
// 常量时间比较（防时序侧信道）
// ---------------------------------------------------------------------------

/// 字节切片常量时间比较。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// 哈希十六进制串常量时间比较。
pub fn ct_eq_hex(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

/// 均匀生成随机 nonce（非敏感）。
pub fn random_nonce() -> [u8; GCM_SIV_NONCE_LEN] {
    use rand::RngCore;
    let mut n = [0u8; GCM_SIV_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// 均匀生成随机 32 字节。
pub fn random_bytes32() -> SecretBytes {
    secmem::random_key32()
}

/// 生成 `n` 字节随机（分片 nonce 前缀、盐等）。
pub fn random_bytes(n: usize) -> Vec<u8> {
    secmem::random_salt(n)
}

/// 十六进制编码（用于审计/调试展示，不涉及明文密钥）。
pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 十六进制解码。
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        bail!("十六进制串长度非法");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow!("十六进制非法: {e}")))
        .collect()
}

/// 口令归一化：统一大小写 / 去标点 / 压缩空白。
///
/// 用于 ASR 文本比对（英文口令大小写与标点识别不稳）。**仅用于比对，
/// 绝不用于派生密钥**（派生用下面 `passphrase_key_material`）。
pub fn normalize_passphrase(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
            prev_space = false;
        } else if !prev_space {
            out.push(' ');
            prev_space = true;
        }
    }
    out.trim().to_string()
}

/// 派生 `wrap_voice` KEK 的输入材料。
///
/// **这里刻意只用口令文本，不用声纹 embedding** —— 生物特征不稳定、不可导，
/// 直接当密钥材料会导致误拒与安全问题。声纹只做门禁（见 `voiceprint.rs`）。
pub fn passphrase_key_material(normalized_passphrase: &str, vault_id: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(normalized_passphrase.len() + vault_id.len() + 8);
    v.extend_from_slice(b"stvault-wrap-voice-v1\x00");
    v.extend_from_slice(normalized_passphrase.as_bytes());
    v.extend_from_slice(vault_id);
    v
}

/// 派生 `wrap_recovery` KEK 的输入材料：密保答案 + 全局静态密码，两因子合并。
pub fn recovery_key_material(answer_norm: &str, master_pw: &str, vault_id: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(answer_norm.len() + master_pw.len() + vault_id.len() + 8);
    v.extend_from_slice(b"stvault-wrap-recovery-v1\x00");
    v.extend_from_slice(answer_norm.as_bytes());
    v.push(0x00);
    v.extend_from_slice(master_pw.as_bytes());
    v.extend_from_slice(vault_id);
    v
}

/// 清零并返回（避免调用方忘记洗 Vec）。
pub fn scrub_vec_pub(v: Vec<u8>) -> Vec<u8> {
    scrub_vec(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_siv_roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let ct = aead_encrypt(&key, &nonce, b"aad", b"hello vault").unwrap();
        let pt = aead_decrypt(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello vault");
    }

    #[test]
    fn gcm_siv_rejects_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut ct = aead_encrypt(&key, &nonce, b"aad", b"hello vault").unwrap();
        ct[0] ^= 0x01;
        assert!(aead_decrypt(&key, &nonce, b"aad", &ct).is_err());
        // AAD 变了也必须失败
        assert!(aead_decrypt(&key, &nonce, b"other", &aead_encrypt(&key, &nonce, b"aad", b"x").unwrap()).is_err());
    }

    #[test]
    fn key_wrap_roundtrip() {
        let kek = [1u8; 32];
        let key = [2u8; 32];
        let w = wrap_key(&kek, &key).unwrap();
        let back = unwrap_key(&kek, &w).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn key_wrap_rejects_tamper() {
        let kek = [1u8; 32];
        let key = [2u8; 32];
        let mut w = wrap_key(&kek, &key).unwrap();
        w[5] ^= 0xff;
        assert!(unwrap_key(&kek, &w).is_err());
        assert!(unwrap_key(&[3u8; 32], &wrap_key(&kek, &key).unwrap()).is_err());
    }

    #[test]
    fn argon2id_is_deterministic_and_salted() {
        let salt = [5u8; 32];
        let a = argon2id_derive(b"correct horse", &salt).unwrap();
        let b = argon2id_derive(b"correct horse", &salt).unwrap();
        assert!(ct_eq(a.as_slice(), b.as_slice()));
        let c = argon2id_derive(b"wrong horse", &salt).unwrap();
        assert!(!ct_eq(a.as_slice(), c.as_slice()));
        let d = argon2id_derive(b"correct horse", &[6u8; 32]).unwrap();
        assert!(!ct_eq(a.as_slice(), d.as_slice()));
    }

    #[test]
    fn normalize_strips_case_punct_and_space() {
        assert_eq!(
            normalize_passphrase("Computer, authorization, Voss seven-three echo bravo!"),
            "computer authorization voss seven three echo bravo"
        );
    }

    #[test]
    fn emb_keystream_xor_roundtrip() {
        let kv = [42u8; 32];
        let k = emb_key(&kv);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let ks = sha3_keystream(&k, data.len());
        let mut ct = data.clone();
        xor_inplace(&mut ct, &ks);
        assert_ne!(ct, data); // 必须被真正加密
        let ks2 = sha3_keystream(&k, ct.len());
        xor_inplace(&mut ct, &ks2);
        assert_eq!(ct, data); // 解密还原
        // 不同 K_voice → 不同密钥流
        assert_ne!(sha3_keystream(&emb_key(&[43u8; 32]), 64), sha3_keystream(&k, 64));
    }

    #[test]
    fn passphrase_commitment_requires_salt_and_key() {
        let kv = [1u8; 32];
        let a = passphrase_commitment(&[2u8; 16], &kv);
        assert_eq!(a, passphrase_commitment(&[2u8; 16], &kv));
        assert_ne!(a, passphrase_commitment(&[3u8; 16], &kv));
        assert_ne!(a, passphrase_commitment(&[2u8; 16], &[9u8; 32]));
    }

    #[test]
    fn key_material_domain_separated() {
        let a = passphrase_key_material("abc", b"id1");
        let b = recovery_key_material("abc", "abc", b"id1");
        assert_ne!(a, b);
    }
}