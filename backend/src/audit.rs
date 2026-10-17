//! 审计日志：独立加密的哈希链日志。
//!
//! 文件布局（`audit.stlog`）：
//! ```text
//! off 0  magic "STVAUDT1" (8)
//! off 8  version u32 = 1
//! 之后为连续记录： u32 ct_len ‖ nonce(12) ‖ AES-256-GCM-SIV(AK, AAD=序号 u64) 密文
//! ```
//! 记录明文 = `json ‖ hash(32)`，其中 `json` 含 `prev` 字段，`hash = SHA3-256(prev ‖ json)`。
//! 删除/篡改/插入任意一条都会破坏整链 → 校验失败。
//!
//! AK（审计密钥）随全局配置加密体保存（`config.rs`）：只有「静态主密码验证成功」或
//! 「某个容器解锁（SRK → audit_wrap）」时才拿得到。拿不到 AK 时事件先进内存待发队列，
//! 一旦 AK 可用立即按序落盘（时间戳不变）。

use crate::crypto;
use anyhow::{bail, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const AUDIT_MAGIC: &[u8; 8] = b"STVAUDT1";
pub const AUDIT_FILENAME: &str = "audit.stlog";

fn now_rfc3339(unix: u64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(unix as i64, 0) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => unix.to_string(),
    }
}

#[derive(serde::Serialize)]
struct RawEntry<'a> {
    at: u64,
    event: &'a str,
    detail: &'a str,
    prev: String,
}

/// 一条对外展示的日志。
#[derive(serde::Serialize, Clone)]
pub struct Entry {
    pub at: String,
    pub at_unix: u64,
    pub event: String,
    pub detail: String,
    pub hash: String,
}

pub struct Audit {
    path: PathBuf,
    ak: Option<[u8; 32]>,
    last_hash: [u8; 32],
    count: u64,
    /// 还没有 AK 时暂存的事件（时间戳已固定）。
    pending: Vec<(u64, String, String)>,
}

impl Audit {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(AUDIT_FILENAME),
            ak: None,
            last_hash: [0u8; 32],
            count: 0,
            pending: Vec::new(),
        }
    }

    pub fn ready(&self) -> bool {
        self.ak.is_some()
    }

    /// 装载 AK：若首次装载且文件已存在，先做一次整链扫描拿到链尾哈希。
    pub fn set_key(&mut self, ak: [u8; 32]) -> Result<()> {
        if self.ak.is_none() {
            self.ak = Some(ak);
            if self.path.is_file() {
                let (last, n) = self.scan_chain()?;
                self.last_hash = last;
                self.count = n;
            }
            let pending = std::mem::take(&mut self.pending);
            for (at, ev, detail) in pending {
                self.write_entry(at, &ev, &detail)?;
            }
        }
        Ok(())
    }

    /// 记录一条事件。AK 未就绪时进待发队列。
    pub fn append(&mut self, event: &str, detail: &str) {
        let at = crate::now_unix();
        if self.ak.is_some() {
            if let Err(e) = self.write_entry(at, event, detail) {
                eprintln!("[audit] 写入失败: {e}");
                self.pending.push((at, event.to_string(), detail.to_string()));
            }
        } else {
            self.pending.push((at, event.to_string(), detail.to_string()));
        }
    }

    fn write_entry(&mut self, at: u64, event: &str, detail: &str) -> Result<()> {
        let ak = match self.ak {
            Some(k) => k,
            None => bail!("审计日志未解锁"),
        };
        let raw = RawEntry {
            at,
            event,
            detail,
            prev: crypto::hex(&self.last_hash),
        };
        let json = serde_json::to_vec(&raw)?;
        let mut hh = Vec::with_capacity(32 + json.len());
        hh.extend_from_slice(&self.last_hash);
        hh.extend_from_slice(&json);
        let hash = crypto::sha3_256(&hh);

        let mut plain = Vec::with_capacity(json.len() + 32);
        plain.extend_from_slice(&json);
        plain.extend_from_slice(&hash);

        let nonce = crypto::random_nonce();
        let aad = self.count.to_le_bytes();
        let ct = crypto::aead_encrypt(&ak, &nonce, &aad, &plain)?;

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.path)?;
        if f.metadata()?.len() == 0 {
            f.write_all(AUDIT_MAGIC)?;
            f.write_all(&1u32.to_le_bytes())?;
        }
        f.seek(SeekFrom::End(0))?;
        f.write_all(&(ct.len() as u32).to_le_bytes())?;
        f.write_all(&nonce)?;
        f.write_all(&ct)?;
        f.sync_all()?;

        self.last_hash = hash;
        self.count += 1;
        crate::secmem::scrub(&mut plain);
        Ok(())
    }

    /// 从头到尾解密并校验哈希链。任何一条被抽掉/篡改都会失败。
    fn scan_chain(&self) -> Result<([u8; 32], u64)> {
        let ak = match self.ak {
            Some(k) => k,
            None => bail!("审计日志未解锁"),
        };
        let mut f = std::fs::File::open(&self.path)?;
        let mut head = [0u8; 12];
        if f.read_exact(&mut head).is_err() {
            return Ok(([0u8; 32], 0));
        }
        if &head[0..8] != AUDIT_MAGIC {
            bail!("审计日志格式非法（magic 不匹配）");
        }
        let mut prev = [0u8; 32];
        let mut n = 0u64;
        loop {
            let mut lenb = [0u8; 4];
            match f.read_exact(&mut lenb) {
                Ok(_) => {}
                Err(_) => break, // 正常结尾
            }
            let ct_len = u32::from_le_bytes(lenb) as usize;
            if ct_len < 17 || ct_len > 64 * 1024 * 1024 {
                bail!("审计日志记录长度非法（文件被截断或篡改）");
            }
            let mut nonce = [0u8; 12];
            f.read_exact(&mut nonce)?;
            let mut ct = vec![0u8; ct_len];
            f.read_exact(&mut ct)?;
            let aad = n.to_le_bytes();
            let plain = crypto::aead_decrypt(&ak, &nonce, &aad, &ct).map_err(|_| {
                anyhow::anyhow!("审计日志第 {} 条解密失败：条目被篡改/替换（哈希链断裂）", n + 1)
            })?;
            if plain.len() < 33 {
                bail!("审计日志记录内容非法");
            }
            let json = &plain[..plain.len() - 32];
            let hash = &plain[plain.len() - 32..];
            let mut hh = Vec::with_capacity(32 + json.len());
            hh.extend_from_slice(&prev);
            hh.extend_from_slice(json);
            let expect = crypto::sha3_256(&hh);
            if !crypto::ct_eq(&expect, hash) {
                bail!("审计日志哈希链校验失败：第 {} 条与上一条不连续（条目被删除或插入）", n + 1);
            }
            prev.copy_from_slice(hash);
            n += 1;
        }
        Ok((prev, n))
    }

    /// 完整解密并返回全部条目（校验链）。
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let ak = match self.ak {
            Some(k) => k,
            None => bail!("AUDIT LOG LOCKED — MASTER PASSWORD REQUIRED"),
        };
        let mut out = Vec::new();
        if !self.path.is_file() {
            return Ok(out);
        }
        let mut f = std::fs::File::open(&self.path)?;
        let mut head = [0u8; 12];
        if f.read_exact(&mut head).is_err() {
            return Ok(out);
        }
        let mut prev = [0u8; 32];
        let mut n = 0u64;
        loop {
            let mut lenb = [0u8; 4];
            if f.read_exact(&mut lenb).is_err() {
                break;
            }
            let ct_len = u32::from_le_bytes(lenb) as usize;
            if ct_len < 17 || ct_len > 64 * 1024 * 1024 {
                bail!("审计日志记录长度非法（文件被截断或篡改）");
            }
            let mut nonce = [0u8; 12];
            f.read_exact(&mut nonce)?;
            let mut ct = vec![0u8; ct_len];
            f.read_exact(&mut ct)?;
            let plain = crypto::aead_decrypt(&ak, &nonce, &n.to_le_bytes(), &ct)
                .map_err(|_| anyhow::anyhow!("AUDIT LOG CORRUPTED — CHAIN BROKEN AT ENTRY {}", n + 1))?;
            let json = &plain[..plain.len() - 32];
            let hash = &plain[plain.len() - 32..];
            let mut hh = Vec::with_capacity(32 + json.len());
            hh.extend_from_slice(&prev);
            hh.extend_from_slice(json);
            if !crypto::ct_eq(&crypto::sha3_256(&hh), hash) {
                bail!("AUDIT CHAIN BROKEN — ENTRY {} DISCONTINUOUS", n + 1);
            }
            let v: serde_json::Value = serde_json::from_slice(json)?;
            out.push(Entry {
                at: now_rfc3339(v["at"].as_u64().unwrap_or(0)),
                at_unix: v["at"].as_u64().unwrap_or(0),
                event: v["event"].as_str().unwrap_or("").to_string(),
                detail: v["detail"].as_str().unwrap_or("").to_string(),
                hash: crypto::hex(hash),
            });
            prev.copy_from_slice(hash);
            n += 1;
        }
        Ok(out)
    }

    /// System Wipe：整文件 3 轮覆写后删除。
    pub fn destroy(&mut self) -> Result<()> {
        self.ak = None;
        self.pending.clear();
        self.last_hash = [0u8; 32];
        self.count = 0;
        crate::config::erase_file(&self.path)
    }
}
