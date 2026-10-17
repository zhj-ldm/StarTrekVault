//! `.stvault` 加密容器 + 容器内虚拟文件系统（VFS）。
//!
//! ## 容器布局
//! ```text
//! off 0    magic "STVAULT1" (8)
//! off 8    version u32 = 1
//! off 12   vault_id (16)
//! off 28   created_at u64
//! off 36   argon2 m_cost u32 | t_cost u32 | p_cost u32          (-> 48)
//! off 48   salt_voice (16)
//! off 64   salt_recovery (16)
//! off 80   passphrase_fp (32)                 # v2: 口令承诺（需 Argon2 输出方可算）
//! off 112  emb_dim u32 | emb_count u32 | threshold_milli u32   (-> 124)
//! off 124  emb_slots = 3 * emb_dim * f32      # 声纹模板（3 个槽位固定，取最大相似度）
//!                                              # v1: 明文；v2: 口令派生密钥流加密
//!          wrap_voice (40)                    # AES-KWP(SRK) —— 口令通路
//!          wrap_recovery (40)                 # AES-KWP(SRK) —— 密保+静态密码通路
//!          meta_nonce (12)
//!          meta_len u32
//!          integrity (32)                     # SHA3-256(本字段之前的全部字节)
//!          -- 补齐到 HEADER_REGION = 8192 --
//! HEADER_REGION (8192)     元数据区： meta_ct(meta_len) 补齐到 META_REGION = 2 MiB
//! DATA_OFF (8192 + 2 MiB)  数据区：每条分片记录 u32 ct_len ‖ nonce(12) ‖ ct‖tag，off 相对 DATA_OFF
//! ```
//! 头部与数据区偏移全部由**固定常量**决定，因此元数据增长不会搬动任何分片。
//!
//! ## 删除 = 真实物理擦除
//! ① 该文件全部分片原地 CSPRNG 覆写 3 轮 + `fsync`；② 元数据移除；
//! ③ 碎片整理（存活分片按序前移重写）→ 腾出的尾部覆写 3 轮 → `ftruncate` 收缩实际占用。

use crate::crypto::{self, KEY_LEN};
use crate::secmem::{self, SecretBytes};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"STVAULT1";
/// 当前容器版本。v2 = 声纹模板加密 + 口令承诺（无廉价离线 oracle）；v1 为
/// 旧版（模板明文 + SHA3-256(明文口令) 指纹），仍可读取以兼容既有容器。
pub const VERSION: u32 = 2;
/// 兼容读取的历史版本。
pub const VERSION_LEGACY: u32 = 1;
/// 头部区固定长度（含头部字段与补齐）。
pub const HEADER_REGION: u64 = 8192;
/// 元数据区固定长度（加密元数据 JSON 的容身上限）。
pub const META_REGION: u64 = 2 * 1024 * 1024;
/// 数据区起点，常量。
pub const DATA_OFF: u64 = HEADER_REGION + META_REGION;
/// 分片大小。
pub const CHUNK_SIZE: u32 = 1024 * 1024;
/// 声纹槽位数（注册最多 3 遍）。
pub const EMB_SLOTS: usize = 3;

const OFF_VERSION: usize = 8;
const OFF_VAULT_ID: usize = 12;
const OFF_CREATED: usize = 28;
const OFF_ARGON2: usize = 36;
const OFF_SALT_VOICE: usize = 48;
const OFF_SALT_REC: usize = 64;
const OFF_PASS_FP: usize = 80;
const OFF_EMB: usize = 112;
const OFF_EMB_SLOTS: usize = 124;
/// AES-KW 封装输出长度（RFC 3394：明文 + 8 字节 semiblock）。
const WRAP: usize = crypto::KW_WRAP_LEN;
/// 头部 integrity 字段相对头部长度的偏移（= emb 槽 + 两份 wrap + nonce + len）。
const fn integrity_off(emb_dim: usize) -> usize {
    OFF_EMB_SLOTS + EMB_SLOTS * emb_dim * 4 + WRAP + WRAP + 12 + 4
}
const fn header_used(emb_dim: usize) -> usize {
    integrity_off(emb_dim) + 32
}

// ---------------------------------------------------------------------------
// 元数据
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct ChunkRec {
    /// 分片记录起点（相对 DATA_OFF）。
    pub off: u64,
    /// 密文长度（含 16 字节标签）。
    pub ct: u32,
    /// 明文长度。
    pub plain: u32,
    /// nonce（hex，仅存档用；实际解密用 meta 之外不用它，密文里自带）。
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct FileRec {
    pub size: u64,
    pub modified: String,
    pub kind: String,
    pub file_id: String,
    pub fmk: String,
    pub chunks: Vec<ChunkRec>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DirRec {
    pub modified: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Meta {
    pub name: String,
    pub chunk_size: u32,
    pub next_off: u64,
    /// 保留字段：本实现删除后立即做碎片整理，因此长期为空。
    pub free: Vec<(u64, u64)>,
    /// AES-KWP(SRK, AK)：解锁后可取出审计密钥。
    pub audit_wrap: String,
    pub dirs: BTreeMap<String, DirRec>,
    pub files: BTreeMap<String, FileRec>,
}

impl Meta {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            chunk_size: CHUNK_SIZE,
            next_off: 0,
            free: Vec::new(),
            audit_wrap: String::new(),
            dirs: BTreeMap::new(),
            files: BTreeMap::new(),
        }
    }
}

/// 目录键归一化：`""` 表示根；其余一律带尾部 `/`。
pub fn norm_dir(dir: &str) -> String {
    let d = dir.trim_start_matches('/');
    if d.is_empty() {
        String::new()
    } else if d.ends_with('/') {
        d.to_string()
    } else {
        format!("{d}/")
    }
}

fn now_stamp() -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(crate::now_unix() as i64, 0) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M").to_string(),
        _ => String::new(),
    }
}

/// 预览/展示用的类型判定（只影响 UI 图标与预览方式，与加密无关）。
pub fn kind_of(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "heic" | "svg" | "ico" => "image",
        "mp4" | "mov" | "mkv" | "webm" | "avi" | "m4v" => "video",
        "mp3" | "wav" | "m4a" | "aac" | "flac" | "ogg" | "aiff" => "audio",
        "txt" | "md" | "json" | "xml" | "html" | "htm" | "css" | "js" | "ts" | "rs" | "py"
        | "c" | "h" | "cpp" | "hpp" | "java" | "go" | "sh" | "yml" | "yaml" | "toml" | "csv"
        | "ini" | "conf" | "log" | "sql" | "php" | "swift" | "kt" => "text",
        _ => "binary",
    }
}

/// VFS 列表项（与 fm.html 期望的字段一致）。
#[derive(Serialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub is_dir: bool,
    pub modified: String,
}

// ---------------------------------------------------------------------------
// 头部
// ---------------------------------------------------------------------------

pub struct Header {
    pub version: u32,
    pub vault_id: [u8; 16],
    pub created_at: u64,
    /// 本容器创建时的 Argon2id 参数（头部自带，改全局参数不影响既有容器）。
    pub argon_m: u32,
    pub argon_t: u32,
    pub argon_p: u32,
    pub salt_voice: [u8; 16],
    pub salt_recovery: [u8; 16],
    pub passphrase_fp: [u8; 32],
    pub emb_dim: usize,
    pub emb_count: usize,
    pub threshold_milli: u32,
    /// 头部声纹槽位的**磁盘原始字节**（v1 明文 / v2 密文）。`to_bytes` 原样写回。
    pub emb_raw: Vec<u8>,
    /// 声纹模板明文。v1 由 `read` 直接解析；v2 需在 unlock 用 K_voice 解密后才填充。
    pub embeddings: Vec<Vec<f32>>,
    pub wrap_voice: [u8; crypto::KW_WRAP_LEN],
    pub wrap_recovery: [u8; crypto::KW_WRAP_LEN],
    pub meta_nonce: [u8; 12],
    pub meta_len: usize,
    pub meta_ct: Vec<u8>,
}

impl Header {
    /// 读取头部与元数据区（不需要任何口令）。头部完整性立即校验。
    pub fn read(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path).with_context(|| format!("打开容器失败: {}", path.display()))?;
        let mut hb = vec![0u8; HEADER_REGION as usize];
        f.read_exact(&mut hb).context("容器头部不完整（文件被截断）")?;
        if &hb[0..8] != MAGIC {
            bail!("不是有效的 .stvault 容器");
        }
        let version = u32::from_le_bytes(hb[OFF_VERSION..OFF_VERSION + 4].try_into().unwrap());
        if version != VERSION && version != VERSION_LEGACY {
            bail!("容器版本不支持: {version}");
        }
        let emb_dim = u32::from_le_bytes(hb[OFF_EMB..OFF_EMB + 4].try_into().unwrap()) as usize;
        if emb_dim == 0 || emb_dim > 4096 {
            bail!("容器声纹维度非法");
        }
        let used = header_used(emb_dim);
        if used > HEADER_REGION as usize {
            bail!("容器头部长度非法");
        }
        let io = integrity_off(emb_dim);
        let expect = crypto::sha3_256(&hb[..io]);
        if !crypto::ct_eq(&expect, &hb[io..io + 32]) {
            bail!("容器头部完整性校验失败：文件被篡改或损坏");
        }

        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&hb[OFF_VAULT_ID..OFF_VAULT_ID + 16]);
        let argon_m = u32::from_le_bytes(hb[OFF_ARGON2..OFF_ARGON2 + 4].try_into().unwrap());
        let argon_t = u32::from_le_bytes(hb[OFF_ARGON2 + 4..OFF_ARGON2 + 8].try_into().unwrap());
        let argon_p = u32::from_le_bytes(hb[OFF_ARGON2 + 8..OFF_ARGON2 + 12].try_into().unwrap());
        let mut salt_voice = [0u8; 16];
        salt_voice.copy_from_slice(&hb[OFF_SALT_VOICE..OFF_SALT_VOICE + 16]);
        let mut salt_recovery = [0u8; 16];
        salt_recovery.copy_from_slice(&hb[OFF_SALT_REC..OFF_SALT_REC + 16]);
        let mut passphrase_fp = [0u8; 32];
        passphrase_fp.copy_from_slice(&hb[OFF_PASS_FP..OFF_PASS_FP + 32]);
        let emb_count = u32::from_le_bytes(hb[OFF_EMB + 4..OFF_EMB + 8].try_into().unwrap()) as usize;
        let threshold_milli = u32::from_le_bytes(hb[OFF_EMB + 8..OFF_EMB + 12].try_into().unwrap());

        let mut embeddings = Vec::new();
        let n = emb_count.min(EMB_SLOTS);
        // 声纹槽位原始字节（v1 明文 / v2 密文），固定 3 * emb_dim * f32。
        let slots_len = EMB_SLOTS * emb_dim * 4;
        let emb_raw = hb[OFF_EMB_SLOTS..OFF_EMB_SLOTS + slots_len].to_vec();
        if version == VERSION_LEGACY {
            // 旧版明文：无需口令即可解析。
            for i in 0..n {
                embeddings.push(decode_slot(&emb_raw, i, emb_dim));
            }
        }

        let wv_off = OFF_EMB_SLOTS + EMB_SLOTS * emb_dim * 4;
        let wr_off = wv_off + WRAP;
        let mut wrap_voice = [0u8; WRAP];
        let mut wrap_recovery = [0u8; WRAP];
        wrap_voice.copy_from_slice(&hb[wv_off..wv_off + WRAP]);
        wrap_recovery.copy_from_slice(&hb[wr_off..wr_off + WRAP]);
        let mut meta_nonce = [0u8; 12];
        meta_nonce.copy_from_slice(&hb[wr_off + WRAP..wr_off + WRAP + 12]);
        let meta_len = u32::from_le_bytes(hb[wr_off + WRAP + 12..wr_off + WRAP + 16].try_into().unwrap()) as usize;
        if meta_len as u64 > META_REGION {
            bail!("容器元数据长度超出预留区");
        }
        let mut meta_ct = vec![0u8; meta_len];
        // 元数据区固定位于 HEADER_REGION
        f.read_exact_at(&mut meta_ct, HEADER_REGION)
            .context("容器元数据区不完整")?;

        Ok(Self {
            version,
            vault_id,
            created_at: u64::from_le_bytes(hb[OFF_CREATED..OFF_CREATED + 8].try_into().unwrap()),
            argon_m,
            argon_t,
            argon_p,
            salt_voice,
            salt_recovery,
            passphrase_fp,
            emb_dim,
            emb_count: n,
            threshold_milli,
            emb_raw,
            embeddings,
            wrap_voice,
            wrap_recovery,
            meta_nonce,
            meta_len,
            meta_ct,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let used = header_used(self.emb_dim);
        let mut hb = vec![0u8; HEADER_REGION as usize];
        hb[0..8].copy_from_slice(MAGIC);
        hb[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&self.version.to_le_bytes());
        hb[OFF_VAULT_ID..OFF_VAULT_ID + 16].copy_from_slice(&self.vault_id);
        hb[OFF_CREATED..OFF_CREATED + 8].copy_from_slice(&self.created_at.to_le_bytes());
        hb[OFF_ARGON2..OFF_ARGON2 + 4].copy_from_slice(&self.argon_m.to_le_bytes());
        hb[OFF_ARGON2 + 4..OFF_ARGON2 + 8].copy_from_slice(&self.argon_t.to_le_bytes());
        hb[OFF_ARGON2 + 8..OFF_ARGON2 + 12].copy_from_slice(&self.argon_p.to_le_bytes());
        hb[OFF_SALT_VOICE..OFF_SALT_VOICE + 16].copy_from_slice(&self.salt_voice);
        hb[OFF_SALT_REC..OFF_SALT_REC + 16].copy_from_slice(&self.salt_recovery);
        hb[OFF_PASS_FP..OFF_PASS_FP + 32].copy_from_slice(&self.passphrase_fp);
        hb[OFF_EMB..OFF_EMB + 4].copy_from_slice(&(self.emb_dim as u32).to_le_bytes());
        hb[OFF_EMB + 4..OFF_EMB + 8].copy_from_slice(&(self.emb_count as u32).to_le_bytes());
        hb[OFF_EMB + 8..OFF_EMB + 12].copy_from_slice(&self.threshold_milli.to_le_bytes());
        let slots_len = EMB_SLOTS * self.emb_dim * 4;
        let n = self.emb_raw.len().min(slots_len);
        hb[OFF_EMB_SLOTS..OFF_EMB_SLOTS + n].copy_from_slice(&self.emb_raw[..n]);
        let wv_off = OFF_EMB_SLOTS + EMB_SLOTS * self.emb_dim * 4;
        let wr_off = wv_off + WRAP;
        hb[wv_off..wv_off + WRAP].copy_from_slice(&self.wrap_voice);
        hb[wr_off..wr_off + WRAP].copy_from_slice(&self.wrap_recovery);
        hb[wr_off + WRAP..wr_off + WRAP + 12].copy_from_slice(&self.meta_nonce);
        hb[wr_off + WRAP + 12..wr_off + WRAP + 16].copy_from_slice(&(self.meta_len as u32).to_le_bytes());
        let io = integrity_off(self.emb_dim);
        let integrity = crypto::sha3_256(&hb[..io]);
        hb[io..io + 32].copy_from_slice(&integrity);
        debug_assert_eq!(io + 32, used);
        hb
    }
}

// ---------------------------------------------------------------------------
// 声纹槽位编码 / v2 加密（口令派生密钥流）
// ---------------------------------------------------------------------------

/// 从槽位原始字节解析一个 f32 向量（越界返回空表）。
fn decode_slot(raw: &[u8], slot: usize, emb_dim: usize) -> Vec<f32> {
    let base = slot * emb_dim * 4;
    if emb_dim == 0 || base + emb_dim * 4 > raw.len() {
        return Vec::new();
    }
    let mut v = Vec::with_capacity(emb_dim);
    for j in 0..emb_dim {
        let o = base + j * 4;
        v.push(f32::from_le_bytes(raw[o..o + 4].try_into().unwrap()));
    }
    v
}

/// 把模板序列化为定长槽位字节块（EMB_SLOTS 槽，零补齐）。
fn encode_slots(embs: &[Vec<f32>], emb_dim: usize) -> Vec<u8> {
    let mut raw = vec![0u8; EMB_SLOTS * emb_dim * 4];
    for (i, e) in embs.iter().take(EMB_SLOTS).enumerate() {
        let base = i * emb_dim * 4;
        for (j, x) in e.iter().take(emb_dim).enumerate() {
            raw[base + j * 4..base + j * 4 + 4].copy_from_slice(&x.to_le_bytes());
        }
    }
    raw
}

/// v2：用 K_voice 派生的密钥流异或整块槽位（原地；流密码自反，加解密同一操作）。
fn xor_slots(raw: &mut [u8], k_voice: &[u8; KEY_LEN]) {
    let ks = crypto::sha3_keystream(&crypto::emb_key(k_voice), raw.len());
    crypto::xor_inplace(raw, &ks);
}

/// v2：解密槽位并解析出 `emb_count` 个模板。
fn decrypt_slots(raw: &[u8], emb_dim: usize, emb_count: usize, k_voice: &[u8; KEY_LEN]) -> Vec<Vec<f32>> {
    let mut buf = raw.to_vec();
    xor_slots(&mut buf, k_voice);
    let n = emb_count.min(EMB_SLOTS);
    (0..n).map(|i| decode_slot(&buf, i, emb_dim)).collect()
}

// ---------------------------------------------------------------------------
// 打开状态
// ---------------------------------------------------------------------------

pub struct OpenVault {
    pub path: PathBuf,
    pub header: Header,
    pub srk: SecretBytes,
    pub meta_key: [u8; KEY_LEN],
    pub meta: Meta,
    f: std::fs::File,
}

/// 解锁结果。
pub struct Unlocked {
    pub vault: OpenVault,
    pub audit_key: Option<[u8; 32]>,
}

impl OpenVault {
    pub fn name(&self) -> &str {
        &self.meta.name
    }

    /// 元数据写回（重新加密并写入元数据区，同步头部 meta_len/meta_nonce/integrity）。
    pub fn save_meta(&mut self) -> Result<()> {
        let json = serde_json::to_vec(&self.meta)?;
        // meta_len 记录的是**密文**长度（明文 + 16 字节 AEAD 标签），与读取侧一致。
        let ct_len = json.len() + crypto::GCM_SIV_TAG_LEN;
        if ct_len as u64 > META_REGION {
            bail!("容器元数据超出预留区（{}/{} 字节）", ct_len, META_REGION);
        }
        let nonce = crypto::random_nonce();
        let io = integrity_off(self.header.emb_dim);
        // AAD = 头部（不含 meta 相关字段的新值），改 meta_len 后重算头部完整性
        let old_nonce = self.header.meta_nonce;
        let old_len = self.header.meta_len;
        self.header.meta_nonce = nonce;
        self.header.meta_len = ct_len;
        let hb = self.header.to_bytes();
        let aad = &hb[..io];
        let ct = crypto::aead_encrypt(&self.meta_key, &nonce, aad, &json)?;
        if ct.len() != json.len() + crypto::GCM_SIV_TAG_LEN {
            // GCM-SIV 密文 = 明文 + tag
            self.header.meta_nonce = old_nonce;
            self.header.meta_len = old_len;
            bail!("元数据加密长度异常");
        }
        if ct.len() as u64 > META_REGION {
            self.header.meta_nonce = old_nonce;
            self.header.meta_len = old_len;
            bail!("容器元数据密文超出预留区");
        }
        // 元数据区：密文 + 清零补齐
        let mut region = vec![0u8; META_REGION as usize];
        region[..ct.len()].copy_from_slice(&ct);
        self.f.write_all_at(&region, HEADER_REGION)?;
        self.f.write_all_at(&hb, 0)?;
        self.f.sync_data()?;
        Ok(())
    }

    fn load_meta(header: &Header, meta_key: &[u8; KEY_LEN]) -> Result<Meta> {
        let io = integrity_off(header.emb_dim);
        let hb = header.to_bytes();
        let aad = &hb[..io];
        let pt = crypto::aead_decrypt(meta_key, &header.meta_nonce, aad, &header.meta_ct)
            .map_err(|_| anyhow!("容器元数据解密失败：文件被篡改或 SRK 不匹配"))?;
        let meta: Meta = serde_json::from_slice(&pt).map_err(|e| anyhow!("容器元数据解析失败: {e}"))?;
        Ok(meta)
    }

    /// 列出目录下的直接子项。
    pub fn list(&self, dir: &str) -> Vec<FileEntry> {
        let d = norm_dir(dir);
        let mut out = Vec::new();
        for (k, v) in &self.meta.dirs {
            if k.starts_with(&d) && k[..k.len() - 1].len() > d.len() {
                let rest = &k[d.len()..k.len() - 1];
                if !rest.contains('/') {
                    out.push(FileEntry {
                        name: rest.to_string(),
                        size: 0,
                        kind: "dir".to_string(),
                        is_dir: true,
                        modified: v.modified.clone(),
                    });
                }
            }
        }
        for (k, v) in &self.meta.files {
            if k.starts_with(&d) && k.len() > d.len() {
                let rest = &k[d.len()..];
                if !rest.contains('/') {
                    out.push(FileEntry {
                        name: rest.to_string(),
                        size: v.size,
                        kind: v.kind.clone(),
                        is_dir: false,
                        modified: v.modified.clone(),
                    });
                }
            }
        }
        out
    }

    /// 搜索：`dir` 之下、路径中包含 `q`（不区分大小写）的文件；`name` 为相对 `dir` 的路径。
    pub fn search(&self, dir: &str, q: &str) -> Vec<FileEntry> {
        let d = norm_dir(dir);
        let ql = q.to_lowercase();
        let mut out = Vec::new();
        for (k, v) in &self.meta.files {
            if !k.starts_with(&d) {
                continue;
            }
            let rel = &k[d.len()..];
            if rel.to_lowercase().contains(&ql) {
                out.push(FileEntry {
                    name: rel.to_string(),
                    size: v.size,
                    kind: v.kind.clone(),
                    is_dir: false,
                    modified: v.modified.clone(),
                });
            }
        }
        out
    }

    pub fn read_file(&self, vpath: &str) -> Result<Vec<u8>> {
        let rec = self
            .meta
            .files
            .get(vpath)
            .ok_or_else(|| anyhow!("文件不存在: {vpath}"))?;
        let fmk = crypto::unhex(&rec.fmk).map_err(|_| anyhow!("容器元数据损坏（fmk）"))?;
        if fmk.len() != KEY_LEN {
            bail!("容器元数据损坏（fmk 长度）");
        }
        let mut fmk_arr = [0u8; KEY_LEN];
        fmk_arr.copy_from_slice(&fmk);
        let file_id = crypto::unhex(&rec.file_id).unwrap_or_default();
        let mut out = Vec::with_capacity(rec.size as usize);
        for (i, ch) in rec.chunks.iter().enumerate() {
            let ck = crypto::sha3_256(&chunk_key_material(&fmk_arr, &file_id, i as u32));
            // 记录布局：[u32 ct_len][nonce(12)][ct‖tag]。`ch.ct` 已含 16 字节标签。
            let total = 12 + ch.ct as usize;
            let mut recb = vec![0u8; total];
            self.f
                .read_exact_at(&mut recb, DATA_OFF + ch.off + 4)
                .context("读取分片失败（容器被截断）")?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&recb[..12]);
            let pt = crypto::aead_decrypt(&ck, &nonce, &chunk_aad(&self.header.vault_id, &file_id, i as u32), &recb[12..])
                .map_err(|_| anyhow!("分片 {} 校验失败：数据被篡改", i))?;
            out.extend_from_slice(&pt);
        }
        if out.len() as u64 != rec.size {
            bail!("文件长度不一致：容器元数据与数据区不匹配");
        }
        Ok(out)
    }

    /// 写入（或覆盖）一个文件。
    pub fn write_file(&mut self, dir: &str, name: &str, data: &[u8]) -> Result<()> {
        let d = norm_dir(dir);
        let vpath = format!("{d}{name}");
        if self.meta.files.contains_key(&vpath) {
            self.remove_file(&vpath)?;
        }
        let file_id = crypto::random_bytes(16);
        let fmk = crypto::random_bytes(KEY_LEN);
        let mut fmk_arr = [0u8; KEY_LEN];
        fmk_arr.copy_from_slice(&fmk);
        let mut chunks = Vec::new();
        let chunk_size = self.meta.chunk_size as usize;
        let total_chunks = if data.is_empty() { 0 } else { (data.len() + chunk_size - 1) / chunk_size };
        for i in 0..total_chunks {
            let s = i * chunk_size;
            let e = (s + chunk_size).min(data.len());
            let plain = &data[s..e];
            let ck = crypto::sha3_256(&chunk_key_material(&fmk_arr, &file_id, i as u32));
            let nonce = crypto::random_nonce();
            let ct = crypto::aead_encrypt(&ck, &nonce, &chunk_aad(&self.header.vault_id, &file_id, i as u32), plain)?;
            let total = 4 + 12 + ct.len();
            let off = self.alloc(total as u64);
            let mut recb = Vec::with_capacity(total);
            recb.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            recb.extend_from_slice(&nonce);
            recb.extend_from_slice(&ct);
            self.f.write_all_at(&recb, DATA_OFF + off)?;
            chunks.push(ChunkRec {
                off,
                ct: ct.len() as u32,
                plain: plain.len() as u32,
                nonce: crypto::hex(&nonce),
            });
            self.meta.next_off = off + total as u64;
        }
        self.meta.files.insert(
            vpath,
            FileRec {
                size: data.len() as u64,
                modified: now_stamp(),
                kind: kind_of(name).to_string(),
                file_id: crypto::hex(&file_id),
                fmk: crypto::hex(&fmk),
                chunks,
            },
        );
        self.save_meta()?;
        Ok(())
    }

    /// 数据区空间分配：先按首次适配复用空闲区，否则追加到尾部。
    fn alloc(&mut self, total: u64) -> u64 {
        for i in 0..self.meta.free.len() {
            let (off, len) = self.meta.free[i];
            if len >= total {
                if len == total {
                    self.meta.free.remove(i);
                } else {
                    self.meta.free[i] = (off + total, len - total);
                }
                return off;
            }
        }
        let off = self.meta.next_off;
        self.meta.next_off += total;
        off
    }

    /// 移除单个文件记录（不擦数据）；返回回收的字节数。
    fn remove_file(&mut self, vpath: &str) -> Result<u64> {
        let rec = match self.meta.files.remove(vpath) {
            Some(r) => r,
            None => return Ok(0),
        };
        let total: u64 = rec.chunks.iter().map(|c| 4 + 12 + c.ct as u64).sum();
        // ① 原地物理擦除：3 轮 CSPRNG 覆写 + fsync（先擦再改元数据）
        for c in &rec.chunks {
            let len = 4 + 12 + c.ct as usize;
            let mut buf = vec![0u8; len];
            for _ in 0..3 {
                secmem::fill_random(&mut buf);
                self.f.write_all_at(&buf, DATA_OFF + c.off)?;
                self.f.sync_data()?;
            }
            // ② 标记空间空闲（供后续首次适配复用）
            self.meta.free.push((c.off, 4 + 12 + c.ct as u64));
        }
        self.meta.free.sort_unstable();
        Ok(total)
    }

    /// 删除若干项（文件或目录，目录递归），随后碎片整理 + 收缩容器。
    pub fn delete(&mut self, dir: &str, names: &[String]) -> Result<u64> {
        let d = norm_dir(dir);
        let mut reclaimed = 0u64;
        for name in names {
            let key = format!("{d}{name}");
            let as_dir = norm_dir(&key);
            // 目录用前缀匹配；同名普通文件需精确匹配（其键不带尾部 `/`）。
            let sub_files: Vec<String> = self
                .meta
                .files
                .keys()
                .filter(|k| k.as_str() == key.as_str() || k.starts_with(&as_dir))
                .cloned()
                .collect();
            for f in sub_files {
                reclaimed += self.remove_file(&f)?;
            }
            let sub_dirs: Vec<String> = self
                .meta
                .dirs
                .keys()
                .filter(|k| k.starts_with(&as_dir))
                .cloned()
                .collect();
            for k in sub_dirs {
                self.meta.dirs.remove(&k);
            }
        }
        self.compact()?;
        Ok(reclaimed)
    }

    /// 碎片整理：把存活分片按原顺序前移重写 → 覆写腾出的尾部 3 轮 → ftruncate 收缩。
    pub fn compact(&mut self) -> Result<()> {
        // 按当前物理位置排序所有存活分片
        let mut live: Vec<(String, usize, u64)> = Vec::new();
        for (k, rec) in &self.meta.files {
            for (i, c) in rec.chunks.iter().enumerate() {
                live.push((k.clone(), i, c.off));
            }
        }
        live.sort_by_key(|x| x.2);

        let mut cursor = 0u64;
        for (k, i, old_off) in &live {
            let rec_len = {
                let rec = &self.meta.files[k];
                let c = &rec.chunks[*i];
                4 + 12 + c.ct as u64
            };
            if *old_off != cursor {
                let mut buf = vec![0u8; rec_len as usize];
                self.f.read_exact_at(&mut buf, DATA_OFF + old_off)?;
                self.f.write_all_at(&buf, DATA_OFF + cursor)?;
                self.meta.files.get_mut(k).unwrap().chunks[*i].off = cursor;
            }
            cursor += rec_len;
        }
        self.f.sync_data()?;

        // 覆写并收缩尾部
        let file_len = self.f.metadata()?.len();
        let new_len = DATA_OFF + cursor;
        if file_len > new_len {
            let chunk = 1024 * 1024u64;
            let mut buf = vec![0u8; chunk as usize];
            for _pass in 0..3 {
                let mut left = file_len - new_len;
                let mut pos = new_len;
                while left > 0 {
                    let n = left.min(chunk) as usize;
                    secmem::fill_random(&mut buf[..n]);
                    self.f.write_all_at(&buf[..n], pos)?;
                    pos += n as u64;
                    left -= n as u64;
                }
                self.f.sync_data()?;
            }
            self.f.set_len(new_len)?;
            self.f.sync_data()?;
        }
        self.meta.next_off = cursor;
        self.meta.free.clear();
        self.save_meta()?;
        Ok(())
    }

    pub fn mkdir(&mut self, dir: &str, name: &str) -> Result<()> {
        let key = norm_dir(&format!("{}{}", norm_dir(dir), name));
        if key.is_empty() {
            bail!("目录名非法");
        }
        if self.meta.dirs.contains_key(&key) || self.meta.files.contains_key(&key) {
            bail!("同名目录/文件已存在");
        }
        self.meta
            .dirs
            .insert(key, DirRec { modified: now_stamp() });
        self.save_meta()
    }

    pub fn rename(&mut self, dir: &str, old_name: &str, new_name: &str) -> Result<()> {
        if new_name.trim().is_empty() || new_name.contains('/') {
            bail!("新名称非法");
        }
        let d = norm_dir(dir);
        let old_key = format!("{d}{old_name}");
        let new_key = format!("{d}{new_name}");
        if self.meta.files.contains_key(&old_key) {
            if self.meta.files.contains_key(&new_key) {
                bail!("同名文件已存在");
            }
            let mut rec = self.meta.files.remove(&old_key).unwrap();
            rec.kind = kind_of(new_name).to_string();
            rec.modified = now_stamp();
            self.meta.files.insert(new_key, rec);
            return self.save_meta();
        }
        let old_dir = norm_dir(&old_key);
        let new_dir = norm_dir(&new_key);
        if !self.meta.dirs.contains_key(&old_dir) {
            bail!("目标不存在");
        }
        let fkeys: Vec<String> = self.meta.files.keys().filter(|k| k.starts_with(&old_dir)).cloned().collect();
        for k in fkeys {
            let rec = self.meta.files.remove(&k).unwrap();
            self.meta.files.insert(format!("{new_dir}{}", &k[old_dir.len()..]), rec);
        }
        let dkeys: Vec<String> = self.meta.dirs.keys().filter(|k| k.starts_with(&old_dir)).cloned().collect();
        for k in dkeys {
            let rec = self.meta.dirs.remove(&k).unwrap();
            self.meta.dirs.insert(format!("{new_dir}{}", &k[old_dir.len()..]), rec);
        }
        self.save_meta()
    }

    /// 容器内移动（只改元数据键，不重写分片）。
    pub fn mv(&mut self, src_dir: &str, src_name: &str, dest_dir: &str) -> Result<()> {
        let sd = norm_dir(src_dir);
        let dd = norm_dir(dest_dir);
        let src_key = format!("{sd}{src_name}");
        let dest_key = format!("{dd}{src_name}");
        if src_key == dest_key {
            return Ok(());
        }
        if self.meta.files.contains_key(&src_key) {
            if self.meta.files.contains_key(&dest_key) {
                bail!("目标目录已有同名文件");
            }
            let rec = self.meta.files.remove(&src_key).unwrap();
            self.meta.files.insert(dest_key, rec);
            return self.save_meta();
        }
        let src_dkey = norm_dir(&src_key);
        if !self.meta.dirs.contains_key(&src_dkey) {
            bail!("目标不存在");
        }
        if dd.starts_with(&src_dkey) {
            bail!("不能把目录移动到自身子目录");
        }
        let dest_dkey = norm_dir(&dest_key);
        let fkeys: Vec<String> = self.meta.files.keys().filter(|k| k.starts_with(&src_dkey)).cloned().collect();
        for k in fkeys {
            let rec = self.meta.files.remove(&k).unwrap();
            self.meta.files.insert(format!("{dest_dkey}{}", &k[src_dkey.len()..]), rec);
        }
        let dkeys: Vec<String> = self.meta.dirs.keys().filter(|k| k.starts_with(&src_dkey)).cloned().collect();
        for k in dkeys {
            let rec = self.meta.dirs.remove(&k).unwrap();
            self.meta.dirs.insert(format!("{dest_dkey}{}", &k[src_dkey.len()..]), rec);
        }
        self.meta.dirs.remove(&src_dkey);
        self.save_meta()
    }

    /// 复制（重新加密写入新分片，绝不共享分片——否则删除时会连坐）。
    pub fn copy_within(&mut self, src_dir: &str, dest_dir: &str, names: &[String]) -> Result<()> {
        let sd = norm_dir(src_dir);
        for n in names {
            let key = format!("{sd}{n}");
            let is_dir = self.meta.dirs.contains_key(&norm_dir(&key));
            if is_dir {
                let sub: Vec<String> = self
                    .meta
                    .files
                    .keys()
                    .filter(|k| k.starts_with(&norm_dir(&key)))
                    .cloned()
                    .collect();
                for f in sub {
                    let rel = f[key.len()..].to_string();
                    let rel_dir = {
                        let p = rel.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
                        if p.is_empty() { String::new() } else { format!("{p}/") }
                    };
                    let base = rel.rsplit('/').next().unwrap().to_string();
                    let target_dir = format!("{}{}", norm_dir(dest_dir), rel_dir);
                    // 目录结构
                    let mut acc = String::new();
                    for part in rel_dir.split('/').filter(|s| !s.is_empty()) {
                        acc = format!("{acc}{part}/");
                        let dk = format!("{}{}", norm_dir(dest_dir), acc);
                        self.meta.dirs.entry(dk).or_insert(DirRec { modified: now_stamp() });
                    }
                    let data = self.read_file(&f)?;
                    self.write_file(&target_dir, &base, &data)?;
                }
            } else {
                let data = self.read_file(&key)?;
                self.write_file(dest_dir, n, &data)?;
            }
        }
        Ok(())
    }

    /// 递归导入一个宿主文件或目录（保持相对结构）。
    pub fn import_path(&mut self, dest_dir: &str, host: &Path) -> Result<u64> {
        let md = std::fs::metadata(host).with_context(|| format!("读取失败: {}", host.display()))?;
        if md.is_file() {
            let data = std::fs::read(host)?;
            let name = host
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unnamed".into());
            self.write_file(dest_dir, &name, &data)?;
            return Ok(1);
        }
        // 目录：以目录自身为根，递归保持相对结构
        let root = norm_dir(dest_dir);
        let name = host.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let base = if name.is_empty() { root.clone() } else { format!("{root}{name}/") };
        if !base.is_empty() && base != root {
            self.meta.dirs.entry(base.clone()).or_insert(DirRec { modified: now_stamp() });
        }
        self.import_dir_recursive(host, &base)
    }

    fn import_dir_recursive(&mut self, host: &Path, vdir: &str) -> Result<u64> {
        let mut count = 0u64;
        for ent in std::fs::read_dir(host)? {
            let ent = ent?;
            let p = ent.path();
            let ft = ent.file_type()?;
            let name = ent.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                let sub = format!("{vdir}{name}/");
                self.meta.dirs.entry(sub.clone()).or_insert(DirRec { modified: now_stamp() });
                count += self.import_dir_recursive(&p, &sub)?;
            } else if ft.is_file() {
                let data = std::fs::read(&p)?;
                self.write_file(vdir, &name, &data)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// 导出到宿主路径（主进程已用保存对话框选定）。
    pub fn export_to(&self, vpath: &str, dest: &Path) -> Result<()> {
        let data = self.read_file(vpath)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut f = std::fs::File::create(dest)?;
        f.write_all(&data)?;
        f.sync_all()?;
        Ok(())
    }

    /// 解锁后从元数据里取出审计密钥。
    pub fn audit_key(&self) -> Option<[u8; 32]> {
        let raw = crypto::unhex(&self.meta.audit_wrap).ok()?;
        if raw.len() != WRAP {
            return None;
        }
        let mut w = [0u8; WRAP];
        w.copy_from_slice(&raw);
        let srk = self.srk.to_array32();
        let ak = crypto::unwrap_key(&srk, &w).ok()?;
        Some(ak)
    }
}

impl Drop for OpenVault {
    fn drop(&mut self) {
        // 关闭容器：清空内存全部明文（密钥、元数据缓存）
        self.meta_key = [0u8; KEY_LEN];
        // srk 是 SecretBytes，Drop 时自动随机覆写
    }
}

fn chunk_key_material(fmk: &[u8; KEY_LEN], file_id: &[u8], i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + file_id.len() + 4 + 8);
    v.extend_from_slice(b"stvault-chunk-v1\x00");
    v.extend_from_slice(fmk);
    v.extend_from_slice(file_id);
    v.extend_from_slice(&i.to_le_bytes());
    v
}

fn chunk_aad(vault_id: &[u8; 16], file_id: &[u8], i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + file_id.len() + 4);
    v.extend_from_slice(vault_id);
    v.extend_from_slice(file_id);
    v.extend_from_slice(&i.to_le_bytes());
    v
}

// ---------------------------------------------------------------------------
// 创建 / 解锁
// ---------------------------------------------------------------------------

pub struct CreateArgs<'a> {
    pub path: &'a Path,
    pub name: &'a str,
    pub passphrase_norm: &'a str,
    pub embeddings: Vec<Vec<f32>>,
    pub answer_norm: &'a str,
    pub master: &'a str,
    pub threshold_milli: u32,
    pub audit_key: Option<[u8; 32]>,
}

/// 创建容器：每个容器独立随机 SRK / 独立盐 / 独立口令与声纹模板。
/// **声纹与口令只做准入因子**，解的是 SRK 包装包，绝不当加密密钥材料。
pub fn create(a: CreateArgs) -> Result<()> {
    let emb_dim = a.embeddings.first().map(|e| e.len()).unwrap_or(0);
    if emb_dim == 0 {
        bail!("声纹模板为空，无法创建容器");
    }
    let emb_count = a.embeddings.len().min(EMB_SLOTS);
    if a.passphrase_norm.trim().is_empty() {
        bail!("语音授权口令为空，无法创建容器");
    }

    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&crypto::random_bytes(16));
    let srk = crypto::random_bytes32();

    let sv = crypto::random_bytes(16);
    let sr = crypto::random_bytes(16);
    let mut salt_voice = [0u8; 16];
    let mut salt_recovery = [0u8; 16];
    salt_voice.copy_from_slice(&sv);
    salt_recovery.copy_from_slice(&sr);

    let k_voice = crypto::argon2id_derive(
        &crypto::passphrase_key_material(a.passphrase_norm, &vault_id),
        &salt_voice,
    )?;
    let kv = k_voice.to_array32();
    let k_rec = crypto::argon2id_derive(
        &crypto::recovery_key_material(a.answer_norm, a.master, &vault_id),
        &salt_recovery,
    )?;
    let srk_arr = srk.to_array32();
    let wrap_voice = crypto::wrap_key(&kv, &srk_arr)?;
    let wrap_recovery = crypto::wrap_key(&k_rec.to_array32(), &srk_arr)?;

    let meta_key = crypto::sha3_256(&[srk.as_slice(), b"meta".as_slice()].concat());
    let audit_wrap = match a.audit_key {
        Some(ak) => crypto::hex(&crypto::wrap_key(&srk_arr, &ak)?),
        None => String::new(),
    };

    let mut meta = Meta::new(a.name);
    meta.audit_wrap = audit_wrap;

    // v2：声纹模板加密存储（须先拿到口令）；口令承诺替代明文指纹。
    let emb_vec: Vec<Vec<f32>> = a.embeddings.into_iter().take(EMB_SLOTS).collect();
    let mut emb_raw = encode_slots(&emb_vec, emb_dim);
    xor_slots(&mut emb_raw, &kv);

    let mut header = Header {
        version: VERSION,
        vault_id,
        created_at: crate::now_unix(),
        argon_m: crypto::ARGON2_MEMORY_KIB,
        argon_t: crypto::ARGON2_TIME_COST,
        argon_p: crypto::ARGON2_PARALLELISM,
        salt_voice,
        salt_recovery,
        passphrase_fp: crypto::passphrase_commitment(&salt_voice, &kv),
        emb_dim,
        emb_count,
        threshold_milli: a.threshold_milli,
        emb_raw,
        embeddings: emb_vec,
        wrap_voice,
        wrap_recovery,
        meta_nonce: crypto::random_nonce(),
        meta_len: 0,
        meta_ct: Vec::new(),
    };
    header.meta_len = 0;

    if a.path.exists() {
        bail!("目标文件已存在: {}", a.path.display());
    }
    let f = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(a.path)
        .with_context(|| format!("创建容器失败: {}", a.path.display()))?;
    // 头部 + 元数据预留区 + 数据区起点，一次性建出定长骨架
    f.set_len(DATA_OFF)?;

    let mut open = OpenVault {
        path: a.path.to_path_buf(),
        header,
        srk,
        meta_key,
        meta,
        f,
    };
    open.save_meta()?; // 写入元数据并同步头部（此时 meta_len 等才最终确定）
    Ok(())
}

/// 建档后的容器头部（用于 vault.list 快速展示，不需要口令）。
pub struct VaultInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub created: u64,
    pub has_voiceprint: bool,
    pub emb_dim: usize,
}

pub fn peek(path: &Path) -> Result<VaultInfo> {
    let h = Header::read(path)?;
    let size = std::fs::metadata(path)?.len();
    Ok(VaultInfo {
        path: path.to_path_buf(),
        name: path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "VAULT".into()),
        size,
        created: h.created_at,
        has_voiceprint: h.emb_count > 0,
        emb_dim: h.emb_dim,
    })
}

/// 声纹解锁：口令文本 + 声纹双校验，两者都过才算通过。
///
/// 失败一律返回同一句 `AUTHORIZATION DENIED`，不区分「口令错 / 声纹错」。
/// 为了不产生时序侧信道，两条校验通路都会**无条件**跑完（不短路）。
pub fn unlock(path: &Path, passphrase_norm: &str, embedding: &[f32], threshold_milli: u32) -> Result<Unlocked> {
    let mut header = Header::read(path)?;

    // 通路一：口令文本 → K_voice → 解 SRK 包装包
    let k_voice = crypto::argon2id_derive_params(
        &crypto::passphrase_key_material(passphrase_norm, &header.vault_id),
        &header.salt_voice,
        header.argon_m,
        header.argon_t,
        header.argon_p,
    )?;
    let kv = k_voice.to_array32();
    // v1（旧容器）：明文指纹（廉价的离线 oracle）；v2：口令承诺，需 Argon2 输出方可计算。
    let fp_ok = if header.version >= VERSION {
        crypto::ct_eq(&crypto::passphrase_commitment(&header.salt_voice, &kv), &header.passphrase_fp)
    } else {
        crypto::ct_eq(&crypto::sha3_256(passphrase_norm.as_bytes()), &header.passphrase_fp)
    };
    let srk_res = crypto::unwrap_key(&kv, &header.wrap_voice);
    let srk_arr = match &srk_res {
        Ok(k) => *k,
        Err(_) => [0u8; KEY_LEN],
    };

    // 通路二：声纹 1:1 余弦相似度（多槽位取最大）。
    // v2 模板已加密，须先用 K_voice 解出；口令错 → K_emb 错 → 解出的是伪随机数 → 相似度≈0。
    let embs = if header.version >= VERSION {
        decrypt_slots(&header.emb_raw, header.emb_dim, header.emb_count, &kv)
    } else {
        header.embeddings.clone()
    };
    let sim = max_similarity(embedding, &embs, header.emb_dim);
    let voice_ok = sim >= (threshold_milli as f32 / 1000.0);

    if !(fp_ok && srk_res.is_ok() && voice_ok) {
        bail!("AUTHORIZATION DENIED");
    }
    if header.version >= VERSION {
        header.embeddings = embs; // 保持解锁后头部内部一致
    }

    let meta_key = crypto::sha3_256(&[&srk_arr[..], b"meta".as_slice()].concat());
    let meta = OpenVault::load_meta(&header, &meta_key)?;

    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let srk = SecretBytes::from_slice(&srk_arr);
    let v = OpenVault {
        path: path.to_path_buf(),
        header,
        srk,
        meta_key,
        meta,
        f,
    };
    let ak = v.audit_key();
    Ok(Unlocked { vault: v, audit_key: ak })
}

/// 用「密保答案 + 静态主密码」解 SRK 包装包（Recovery 通路）。
pub fn unlock_with_recovery(path: &Path, answer_norm: &str, master: &str) -> Result<Unlocked> {
    let header = Header::read(path)?;
    let k_rec = crypto::argon2id_derive_params(
        &crypto::recovery_key_material(answer_norm, master, &header.vault_id),
        &header.salt_recovery,
        header.argon_m,
        header.argon_t,
        header.argon_p,
    )?;
    let srk_arr = crypto::unwrap_key(&k_rec.to_array32(), &header.wrap_recovery)
        .map_err(|_| anyhow!("RECOVERY CREDENTIALS REJECTED"))?;
    let meta_key = crypto::sha3_256(&[&srk_arr[..], b"meta".as_slice()].concat());
    let meta = OpenVault::load_meta(&header, &meta_key)?;
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let srk = SecretBytes::from_slice(&srk_arr);
    let v = OpenVault {
        path: path.to_path_buf(),
        header,
        srk,
        meta_key,
        meta,
        f,
    };
    let ak = v.audit_key();
    Ok(Unlocked { vault: v, audit_key: ak })
}

/// 清除旧声纹模板并录入新的（Recovery 通过后调用）。
/// 文件数据一律保留：只改头部里的声纹槽位、口令指纹与 wrap_voice 包装包。
pub fn reset_voiceprint(
    vault: &mut OpenVault,
    passphrase_norm: &str,
    embeddings: Vec<Vec<f32>>,
    threshold_milli: u32,
) -> Result<()> {
    if embeddings.is_empty() || passphrase_norm.trim().is_empty() {
        bail!("新的声纹模板或授权口令为空");
    }
    let dim = embeddings[0].len();
    if dim != vault.header.emb_dim {
        bail!(
            "声纹模型维度不匹配（容器 {}，当前 {}）：请使用同一套模型重新录入",
            vault.header.emb_dim,
            dim
        );
    }
    let srk_arr = vault.srk.to_array32();
    // 新盐：旧口令通路彻底作废
    let sv = crypto::random_bytes(16);
    let mut salt_voice = [0u8; 16];
    salt_voice.copy_from_slice(&sv);
    vault.header.salt_voice = salt_voice;
    let k_voice = crypto::argon2id_derive_params(
        &crypto::passphrase_key_material(passphrase_norm, &vault.header.vault_id),
        &salt_voice,
        vault.header.argon_m,
        vault.header.argon_t,
        vault.header.argon_p,
    )?;
    let kv = k_voice.to_array32();
    vault.header.wrap_voice = crypto::wrap_key(&kv, &srk_arr)?;
    // v2：承诺 + 加密模板；同时把旧容器升级到 v2（等价于一次安全加固重写）
    vault.header.version = VERSION;
    vault.header.passphrase_fp = crypto::passphrase_commitment(&salt_voice, &kv);
    vault.header.emb_count = embeddings.len().min(EMB_SLOTS);
    let emb_vec: Vec<Vec<f32>> = embeddings.into_iter().take(EMB_SLOTS).collect();
    let mut emb_raw = encode_slots(&emb_vec, vault.header.emb_dim);
    xor_slots(&mut emb_raw, &kv);
    vault.header.emb_raw = emb_raw;
    vault.header.embeddings = emb_vec;
    vault.header.threshold_milli = threshold_milli;
    // 头部重写 + 元数据重加密（AAD 变了）
    vault.save_meta()?;
    let hb = vault.header.to_bytes();
    vault.f.write_all_at(&hb, 0)?;
    vault.f.sync_all()?;
    Ok(())
}

/// 余弦相似度：多槽位取最大（注册 3 遍时只要与任一遍接近即视为本人）。
pub fn max_similarity(a: &[f32], slots: &[Vec<f32>], dim: usize) -> f32 {
    if a.len() != dim {
        return 0.0;
    }
    let mut best = -1.0f32;
    for s in slots {
        let mut dot = 0f64;
        let mut na = 0f64;
        let mut nb = 0f64;
        for i in 0..dim {
            dot += (a[i] as f64) * (s[i] as f64);
            na += (a[i] as f64) * (a[i] as f64);
            nb += (s[i] as f64) * (s[i] as f64);
        }
        if na <= 0.0 || nb <= 0.0 {
            continue;
        }
        let c = (dot / (na.sqrt() * nb.sqrt())) as f32;
        if c > best {
            best = c;
        }
    }
    best.max(0.0)
}

/// System Wipe：整容器 3 轮 CSPRNG 覆写后删除。
pub fn wipe_container(path: &Path) -> Result<()> {
    crate::config::erase_file(path)
}

/// 临时明文（拖出到 Finder 用）：3 轮覆写后删除。
pub fn release_temp(temp: &Path, tmp_dir: &Path) -> Result<()> {
    let canon_tmp = tmp_dir.canonicalize().unwrap_or_else(|_| tmp_dir.to_path_buf());
    let canon = temp.canonicalize().unwrap_or_else(|_| temp.to_path_buf());
    if !canon.starts_with(&canon_tmp) {
        bail!("拒绝清理非临时目录内的文件: {}", temp.display());
    }
    crate::config::erase_file(&canon)
}

/// 把容器内某个文件解密到临时目录，供 `webContents.startDrag` 使用。
pub fn prepare_drag(vault: &OpenVault, vpath: &str, tmp_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(tmp_dir)?;
    let data = vault.read_file(vpath)?;
    let name = vpath.rsplit('/').next().unwrap_or("file");
    let safe: String = name
        .chars()
        .map(|c| if c == '/' || c == '\\' || c == ':' { '_' } else { c })
        .collect();
    let dest = tmp_dir.join(format!("{}.{}", crypto::hex(&crypto::random_bytes(4)), safe));
    let mut f = std::fs::File::create(&dest)?;
    f.write_all(&data)?;
    f.sync_all()?;
    Ok(dest)
}

/// 临时目录整体清空（锁定 / 退出时调用）。
pub fn purge_temp_dir(tmp_dir: &Path) -> Result<()> {
    if !tmp_dir.is_dir() {
        return Ok(());
    }
    for ent in std::fs::read_dir(tmp_dir)? {
        let p = ent?.path();
        let _ = release_temp(&p, tmp_dir);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stvault-test-{tag}-{}.stvault", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn create_test_vault(path: &Path, emb: &[Vec<f32>]) {
        create(CreateArgs {
            path,
            name: "TEST",
            passphrase_norm: "open the pod bay doors",
            embeddings: emb.to_vec(),
            answer_norm: "fluffy",
            master: "master-pw",
            threshold_milli: 650,
            audit_key: None,
        })
        .unwrap();
    }

    #[test]
    fn v2_voiceprint_encrypted_and_unlock_roundtrip() {
        let path = tmp_path("rt");
        // 用较高维度贴近真实声纹模型，避免低维随机向量偶然高相似。
        let dim = 64usize;
        let e0: Vec<f32> = (0..dim).map(|i| ((i as f32) * 0.10).sin()).collect();
        let e1: Vec<f32> = (0..dim).map(|i| ((i as f32) * 0.20).cos()).collect();
        let emb = vec![e0.clone(), e1.clone()];
        create_test_vault(&path, &emb);

        let h = Header::read(&path).unwrap();
        assert_eq!(h.version, VERSION);
        // 磁盘上的声纹槽位不得等于明文（v1 的明文泄漏已修复）。
        let plain = encode_slots(&emb, h.emb_dim);
        assert_ne!(&h.emb_raw[..], &plain[..], "声纹模板必须以密文存储");

        // 正确口令 + 正确的第一条声纹 → 解锁成功。
        assert_eq!(unlock(&path, "open the pod bay doors", &e0, 650).unwrap().vault.name(), "TEST");

        // 错误口令 / 声纹方向相反（余弦 -1）→ 均拒绝。
        assert!(unlock(&path, "wrong phrase", &e0, 650).is_err());
        let opposite: Vec<f32> = e0.iter().map(|x| -x).collect();
        assert!(unlock(&path, "open the pod bay doors", &opposite, 650).is_err());

        // 回归：把磁盘上的（密文）槽位原样当 probe 重放，即使口令正确也不应通过。
        let mut replay = Vec::with_capacity(h.emb_dim);
        for j in 0..h.emb_dim {
            replay.push(f32::from_le_bytes(h.emb_raw[j * 4..j * 4 + 4].try_into().unwrap()));
        }
        assert!(unlock(&path, "open the pod bay doors", &replay, 650).is_err());

        // Recovery 通路仍可用；错误主密码被拒。
        assert_eq!(unlock_with_recovery(&path, "fluffy", "master-pw").unwrap().vault.name(), "TEST");
        assert!(unlock_with_recovery(&path, "fluffy", "bad").is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reset_voiceprint_reencrypts_and_preserves_data() {
        let path = tmp_path("reset");
        let dim = 64usize;
        let e0: Vec<f32> = (0..dim).map(|i| ((i as f32) * 0.10).sin()).collect();
        create_test_vault(&path, &[e0.clone()]);

        let mut u = unlock(&path, "open the pod bay doors", &e0, 650).unwrap();
        let new_emb: Vec<f32> = (0..dim).map(|i| ((i as f32) * 0.30).cos()).collect();
        reset_voiceprint(&mut u.vault, "new passphrase", vec![new_emb.clone()], 650).unwrap();
        drop(u);

        // 新声纹可解锁；旧声纹 / 旧口令不再有效。
        assert_eq!(unlock(&path, "new passphrase", &new_emb, 650).unwrap().vault.name(), "TEST");
        assert!(unlock(&path, "open the pod bay doors", &e0, 650).is_err());

        let _ = std::fs::remove_file(&path);
    }
}
