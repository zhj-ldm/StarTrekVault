//! 全局配置（首次启动的保底解锁双因子 + 审计日志密钥 AK）。
//!
//! 文件布局（`global.stcfg`）：
//! ```text
//! off 0    magic "STVCFG01" (8)
//! off 8    version u32 = 2
//! off 12   salt_master (32)     # K_cfg  = Argon2id(master_pw, salt_cfg)
//! off 44   salt_answer (32)     # K_answ = Argon2id(answer_norm, salt_answer)
//! off 76   salt_cfg (16)
//! off 92   answer_fp (32)       # SHA3-256(K_answ) —— 密保答案的「加盐哈希」
//! off 124  created_at u64
//! off 132  question_len u32
//! off 136  question (160)       # 安全问题明文（需求 §七.1：明文保存，仅 UI 展示）
//! off 296  body_nonce (12)
//! off 308  body_len u32
//! off 312  integrity (32)       # SHA3-256(0..312)
//! off 344  body_ct (body_len)   # AES-256-GCM-SIV(K_cfg, AAD = 0..312)
//! ```
//!
//! 主密码是否正确由「K_cfg 能否解开 body」在密码学上强制，不存任何口令明文；
//! 密保答案存 Argon2id 派生的指纹（`answer_fp`），常量时间比较。
//!
//! ## 版本与 Argon2id 参数
//! `version = 1` 为旧版：使用需求 §八.3 字面参数（1 GiB / t10 / p8），
//! 派生 `salt_cfg`/`salt_answer` 两处。`version >= 2` 用 `crypto::ARGON2_CURRENT`。
//! 参数随版本走，改全局常量不会让既有 `global.stcfg` 解不开。

use crate::crypto;
use crate::secmem::SecretBytes;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const CFG_MAGIC: &[u8; 8] = b"STVCFG01";
pub const CFG_FILENAME: &str = "global.stcfg";
/// 当前写出的配置版本。`1` 为旧版（Argon2id 用需求字面参数）。
pub const CFG_VERSION: u32 = 2;

const VERSION_OFF: usize = 8;
const SALT_MASTER_OFF: usize = 12;
const SALT_ANSWER_OFF: usize = 44;
const SALT_CFG_OFF: usize = 76;
const ANSWER_FP_OFF: usize = 92;
const CREATED_OFF: usize = 124;
const QUESTION_LEN_OFF: usize = 132;
const QUESTION_OFF: usize = 136;
const QUESTION_CAP: usize = 160;
const BODY_NONCE_OFF: usize = 296;
const BODY_LEN_OFF: usize = 308;
const INTEGRITY_OFF: usize = 312;
/// integrity 结束处（= 被校验的头部长度）。
pub const HEADER_LEN: usize = 344;

#[derive(Serialize, Deserialize, Clone)]
struct CfgBody {
    /// 审计日志密钥 AK（hex）。
    audit_key: String,
}

/// 全局配置的公开部分（读取不需要主密码）。
pub struct GlobalCfg {
    pub path: PathBuf,
    pub salt_master: [u8; 32],
    pub salt_answer: [u8; 32],
    pub salt_cfg: [u8; 16],
    pub answer_fp: [u8; 32],
    pub created_at: u64,
    pub question: String,
    /// 派生本配置所依据的 Argon2id 参数 (m_kib, t, p)，由版本决定。
    pub argon: (u32, u32, u32),
}

impl GlobalCfg {
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(CFG_FILENAME)
    }

    pub fn exists(data_dir: &Path) -> bool {
        Self::path_in(data_dir).is_file()
    }

    /// 读取并校验完好性；不涉及任何口令。
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = Self::path_in(data_dir);
        let mut f = std::fs::File::open(&path).with_context(|| format!("打开全局配置失败: {}", path.display()))?;
        let mut head = vec![0u8; HEADER_LEN];
        f.read_exact(&mut head).context("全局配置头部不完整")?;
        if &head[0..8] != CFG_MAGIC {
            bail!("全局配置格式非法（magic 不匹配）");
        }
        let version = u32::from_le_bytes(head[VERSION_OFF..VERSION_OFF + 4].try_into().unwrap());
        // v1 用需求字面参数派生，v>=2 用当前参数；参数随版本自持，改常量不废旧配置。
        let argon = if version <= 1 {
            crypto::ARGON2_LEGACY
        } else {
            crypto::ARGON2_CURRENT
        };
        let body_len = u32::from_le_bytes(head[BODY_LEN_OFF..BODY_LEN_OFF + 4].try_into().unwrap()) as usize;
        let mut body = vec![0u8; body_len];
        f.read_exact(&mut body).context("全局配置加密体不完整")?;
        // 完整性：头部自校验（篡改 → 拒绝加载）
        let expect = crypto::sha3_256(&head[..INTEGRITY_OFF]);
        if !crypto::ct_eq(&expect, &head[INTEGRITY_OFF..INTEGRITY_OFF + 32]) {
            bail!("全局配置头部校验失败：文件被篡改或损坏");
        }
        let mut salt_master = [0u8; 32];
        let mut salt_answer = [0u8; 32];
        let mut salt_cfg = [0u8; 16];
        let mut answer_fp = [0u8; 32];
        salt_master.copy_from_slice(&head[SALT_MASTER_OFF..SALT_MASTER_OFF + 32]);
        salt_answer.copy_from_slice(&head[SALT_ANSWER_OFF..SALT_ANSWER_OFF + 32]);
        salt_cfg.copy_from_slice(&head[SALT_CFG_OFF..SALT_CFG_OFF + 16]);
        answer_fp.copy_from_slice(&head[ANSWER_FP_OFF..ANSWER_FP_OFF + 32]);
        let created_at = u64::from_le_bytes(head[CREATED_OFF..CREATED_OFF + 8].try_into().unwrap());
        let qlen = u32::from_le_bytes(head[QUESTION_LEN_OFF..QUESTION_LEN_OFF + 4].try_into().unwrap()) as usize;
        if qlen > QUESTION_CAP {
            bail!("全局配置问题字段长度非法");
        }
        let question = String::from_utf8_lossy(&head[QUESTION_OFF..QUESTION_OFF + qlen]).into_owned();
        Ok(Self {
            path,
            salt_master,
            salt_answer,
            salt_cfg,
            answer_fp,
            created_at,
            question,
            argon,
        })
    }

    /// 首次启动初始化：生成盐、密保答案指纹、审计密钥，并写出加密配置。
    /// 返回 `(配置, K_cfg, AK)`：调用方可把 K_cfg 缓存在内存里，避免重复派生。
    pub fn init(data_dir: &Path, question: &str, answer_norm: &str, master: &str) -> Result<(Self, SecretBytes, [u8; 32])> {
        if question.trim().is_empty() || answer_norm.trim().is_empty() || master.is_empty() {
            bail!("安全问题、答案与静态主密码都不能为空");
        }
        if question.as_bytes().len() > QUESTION_CAP {
            bail!("安全问题过长");
        }
        let salt_master = crypto::random_bytes(32);
        let salt_answer = crypto::random_bytes(32);
        let salt_cfg = crypto::random_bytes(16);
        let mut sm = [0u8; 32];
        let mut sa = [0u8; 32];
        let mut sc = [0u8; 16];
        sm.copy_from_slice(&salt_master);
        sa.copy_from_slice(&salt_answer);
        sc.copy_from_slice(&salt_cfg);

        // 密保答案：Argon2id 加盐派生 → 只存输出的 SHA3-256 指纹
        let (m_kib, t_cost, p_cost) = crypto::ARGON2_CURRENT;
        let k_answer = crypto::argon2id_derive_params(answer_norm.as_bytes(), &sa, m_kib, t_cost, p_cost)?;
        let answer_fp = crypto::sha3_256(k_answer.as_slice());

        // 静态主密码：Argon2id 加盐派生 K_cfg，作为配置加密体密钥
        let k_cfg = crypto::argon2id_derive_params(master.as_bytes(), &sc, m_kib, t_cost, p_cost)?;

        let audit_key: [u8; 32] = {
            let v = crypto::random_bytes(32);
            v.try_into().unwrap()
        };
        let body = serde_json::to_vec(&CfgBody { audit_key: crypto::hex(&audit_key) })?;

        // 密文长度 = 明文 + 16 字节 AEAD 标签；读取侧按 BODY_LEN 整体读入。
        let ct_len = body.len() + crypto::GCM_SIV_TAG_LEN;
        let mut head = vec![0u8; HEADER_LEN + ct_len];
        head[0..8].copy_from_slice(CFG_MAGIC);
        head[VERSION_OFF..VERSION_OFF + 4].copy_from_slice(&CFG_VERSION.to_le_bytes());
        head[SALT_MASTER_OFF..SALT_MASTER_OFF + 32].copy_from_slice(&sm);
        head[SALT_ANSWER_OFF..SALT_ANSWER_OFF + 32].copy_from_slice(&sa);
        head[SALT_CFG_OFF..SALT_CFG_OFF + 16].copy_from_slice(&sc);
        head[ANSWER_FP_OFF..ANSWER_FP_OFF + 32].copy_from_slice(&answer_fp);
        head[CREATED_OFF..CREATED_OFF + 8].copy_from_slice(&crate::now_unix().to_le_bytes());
        let qb = question.as_bytes();
        head[QUESTION_LEN_OFF..QUESTION_LEN_OFF + 4].copy_from_slice(&(qb.len() as u32).to_le_bytes());
        head[QUESTION_OFF..QUESTION_OFF + qb.len()].copy_from_slice(qb);

        let nonce = crypto::random_nonce();
        head[BODY_NONCE_OFF..BODY_NONCE_OFF + 12].copy_from_slice(&nonce);
        head[BODY_LEN_OFF..BODY_LEN_OFF + 4].copy_from_slice(&(ct_len as u32).to_le_bytes());
        let integrity = crypto::sha3_256(&head[..INTEGRITY_OFF]);
        head[INTEGRITY_OFF..INTEGRITY_OFF + 32].copy_from_slice(&integrity);

        let k_cfg_arr = k_cfg.to_array32();
        let ct = crypto::aead_encrypt(&k_cfg_arr, &nonce, &head[..INTEGRITY_OFF], &body)?;
        head[HEADER_LEN..HEADER_LEN + ct_len].copy_from_slice(&ct);

        std::fs::create_dir_all(data_dir)?;
        let path = Self::path_in(data_dir);
        write_file_atomic(&path, &head)?;
        let cfg = Self {
            path,
            salt_master: sm,
            salt_answer: sa,
            salt_cfg: sc,
            answer_fp,
            created_at: crate::now_unix(),
            question: question.to_string(),
            argon: crypto::ARGON2_CURRENT,
        };
        Ok((cfg, k_cfg, audit_key))
    }

    /// 校验静态主密码：能解开 body 即正确。返回 K_cfg（可缓存）与 body。
    pub fn verify_master(&self, master: &str) -> Result<(SecretBytes, [u8; 32])> {
        let mut f = std::fs::File::open(&self.path)?;
        f.seek(SeekFrom::Start(0))?;
        let mut head = vec![0u8; HEADER_LEN];
        f.read_exact(&mut head)?;
        let body_len = u32::from_le_bytes(head[BODY_LEN_OFF..BODY_LEN_OFF + 4].try_into().unwrap()) as usize;
        let mut body = vec![0u8; body_len];
        f.read_exact(&mut body)?;
        let k_cfg = crypto::argon2id_derive_params(
            master.as_bytes(),
            &self.salt_cfg,
            self.argon.0,
            self.argon.1,
            self.argon.2,
        )?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&head[BODY_NONCE_OFF..BODY_NONCE_OFF + 12]);
        let k_cfg_arr = k_cfg.to_array32();
        let pt = crypto::aead_decrypt(&k_cfg_arr, &nonce, &head[..INTEGRITY_OFF], &body)
            .map_err(|_| anyhow!("MASTER PASSWORD REJECTED"))?;
        let parsed: CfgBody = serde_json::from_slice(&pt).map_err(|_| anyhow!("全局配置内容损坏"))?;
        let raw = crypto::unhex(&parsed.audit_key).unwrap_or_default();
        let mut ak = [0u8; 32];
        if raw.len() == 32 {
            ak.copy_from_slice(&raw);
        }
        Ok((k_cfg, ak))
    }

    /// 校验密保答案（常量时间比较 Argon2id 指纹）。
    pub fn verify_answer(&self, answer_norm: &str) -> Result<bool> {
        let k = crypto::argon2id_derive_params(
            answer_norm.as_bytes(),
            &self.salt_answer,
            self.argon.0,
            self.argon.1,
            self.argon.2,
        )?;
        let fp = crypto::sha3_256(k.as_slice());
        Ok(crypto::ct_eq(&fp, &self.answer_fp))
    }
}

/// 原子写入（先写临时文件再 rename），避免掉电留下半个配置。
fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// 3 轮随机覆写后删除（System Wipe 用）。
pub fn erase_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = std::fs::metadata(path)?.len() as usize;
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; 1024 * 1024];
    for _ in 0..3 {
        f.seek(SeekFrom::Start(0))?;
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len());
            crate::secmem::fill_random(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            left -= n;
        }
        f.sync_all()?;
    }
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}
