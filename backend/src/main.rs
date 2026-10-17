//! StarTrek Vault 后端 —— 单可执行文件（`stvault-backend`），JSON-RPC over stdio。
//!
//! 职责：把 [`vault`]（.stvault 容器 + VFS）、[`config`]（全局配置 + AK）、[`audit`]（加密哈希链日志）、
//! [`voice`]（cpal 常驻采集 + Silero VAD + sherpa-onnx ASR/声纹）串成一组 RPC 方法，供 Electron 主进程调用。
//!
//! 协议：stdin 逐行 JSON 请求 `{"id","method","params"}` → stdout 单行 `{"id","result"}` 或
//! `{"id","error":{"message"}}`；stderr 为日志。
//!
//! 命令行：`--root <dir>`（模型根，缺省取 `STAR_TREK_ROOT`）`--data-dir <dir>`（数据目录）。

mod audit;
mod config;
mod crypto;
mod secmem;
mod vault;
mod voice;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// 时间
// ---------------------------------------------------------------------------

/// 当前 Unix 秒（各模块共用，`config.rs` / `audit.rs` / `vault.rs` 都通过 `crate::now_unix()` 取值）。
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 锁定状态机（§七：fail 0→4 播 warning；第 5 次锁定 5 分钟，持久化）
// ---------------------------------------------------------------------------

const MAX_FAILS: u32 = 5;
const LOCK_MS: u64 = 5 * 60 * 1000;
/// 默认声纹相似度阈值（毫千），与 UI 滑杆缺省 0.65 对齐。
const DEFAULT_THRESHOLD_MILLI: u32 = 650;

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct LockRec {
    fails: u32,
    locked_until_ms: u64,
}

/// `vaults.index` 中的一条：容器路径 + 展示名（创建时由 UI 提供）。
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct IndexEntry {
    path: String,
    name: String,
}

fn default_language() -> String {
    "en".to_string()
}

/// Normalise an incoming language tag to one of the supported UI languages.
fn normalize_language(value: &str) -> String {
    if value.eq_ignore_ascii_case("zh") {
        "zh".to_string()
    } else {
        "en".to_string()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Settings {
    threshold_milli: u32,
    #[serde(default = "default_language")]
    language: String,
}

// ---------------------------------------------------------------------------
// 全局状态
// ---------------------------------------------------------------------------

struct AppState {
    data_dir: PathBuf,
    voice: voice::Voice,
    cfg: Option<config::GlobalCfg>,
    ak: Option<[u8; 32]>,
    audit: audit::Audit,
    open: Option<vault::OpenVault>,
    open_path: Option<PathBuf>,
    /// fm.html 解锁面板的目标容器（由 `vault.select` 设定）。
    selected: Option<PathBuf>,
    threshold_milli: u32,
    /// UI language tag: `"en"` (default) or `"zh"`.
    language: String,
    /// 主密码与密保答案的运行期缓存：创建容器时需要它们派生 Recovery 包装包。
    answer_norm: Option<String>,
    master: Option<secmem::SecretBytes>,
    locks: HashMap<String, LockRec>,
}

impl AppState {
    fn new(root: PathBuf, data_dir: PathBuf) -> Self {
        let mut st = Self {
            voice: voice::Voice::new(&root),
            cfg: config::GlobalCfg::load(&data_dir).ok(),
            ak: None,
            audit: audit::Audit::new(&data_dir),
            open: None,
            open_path: None,
            selected: None,
            threshold_milli: DEFAULT_THRESHOLD_MILLI,
            language: default_language(),
            answer_norm: None,
            master: None,
            locks: HashMap::new(),
            data_dir,
        };
        st.load_settings();
        st.load_locks();
        st
    }

    fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("drag-tmp")
    }
    fn locks_path(&self) -> PathBuf {
        self.data_dir.join("locks.json")
    }
    fn index_path(&self) -> PathBuf {
        self.data_dir.join("vaults.index")
    }
    fn settings_path(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }

    fn load_settings(&mut self) {
        if let Ok(raw) = std::fs::read_to_string(self.settings_path()) {
            if let Ok(s) = serde_json::from_str::<Settings>(&raw) {
                self.threshold_milli = s.threshold_milli.min(1000);
                self.language = normalize_language(&s.language);
            }
        }
    }

    fn save_settings(&self) {
        let s = Settings {
            threshold_milli: self.threshold_milli,
            language: self.language.clone(),
        };
        if let Ok(txt) = serde_json::to_string(&s) {
            let _ = std::fs::write(self.settings_path(), txt);
        }
    }

    fn load_locks(&mut self) {
        if let Ok(raw) = std::fs::read_to_string(self.locks_path()) {
            if let Ok(m) = serde_json::from_str::<HashMap<String, LockRec>>(&raw) {
                self.locks = m;
            }
        }
    }

    fn save_locks(&self) {
        if let Ok(txt) = serde_json::to_string(&self.locks) {
            let _ = std::fs::write(self.locks_path(), txt);
        }
    }

    fn index(&self) -> Vec<IndexEntry> {
        std::fs::read_to_string(self.index_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<IndexEntry>>(&raw).ok())
            .unwrap_or_default()
    }

    fn index_add(&self, path: &Path, name: &str) {
        let p = path.to_string_lossy().into_owned();
        let mut list = self.index();
        if let Some(e) = list.iter_mut().find(|e| e.path == p) {
            e.name = name.to_string();
        } else {
            list.push(IndexEntry { path: p, name: name.to_string() });
        }
        if let Ok(txt) = serde_json::to_string(&list) {
            let _ = std::fs::write(self.index_path(), txt);
        }
    }

    fn index_remove(&self, path: &Path) {
        let p = path.to_string_lossy().into_owned();
        let list: Vec<IndexEntry> = self.index().into_iter().filter(|e| e.path != p).collect();
        if let Ok(txt) = serde_json::to_string(&list) {
            let _ = std::fs::write(self.index_path(), txt);
        }
    }

    fn name_for(&self, path: &Path) -> String {
        let p = path.to_string_lossy().into_owned();
        self.index()
            .into_iter()
            .find(|e| e.path == p)
            .map(|e| e.name)
            .or_else(|| {
                path.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "VAULT".into())
    }

    fn require_open(&self) -> Result<&vault::OpenVault> {
        self.open
            .as_ref()
            .ok_or_else(|| anyhow!("VAULT NOT UNLOCKED"))
    }

    fn require_open_mut(&mut self) -> Result<&mut vault::OpenVault> {
        self.open
            .as_mut()
            .ok_or_else(|| anyhow!("VAULT NOT UNLOCKED"))
    }

    // -----------------------------------------------------------------------
    // RPC 分发
    // -----------------------------------------------------------------------

    async fn handle(&mut self, method: &str, p: &Value) -> Result<Value> {
        match method {
            "ping" => Ok(json!({ "ok": true })),
            "status" => Ok(self.status_json()),
            "global.status" => Ok(json!({
                "configured": self.cfg.is_some(),
                "question": self.cfg.as_ref().map(|c| c.question.clone()).unwrap_or_default(),
            })),
            "global.init" => self.m_global_init(p),

            "vault.list" => self.m_vault_list(),
            "vault.select" => self.m_vault_select(p),
            "vault.create" => self.m_vault_create(p),
            "vault.unlock" => self.m_vault_unlock(p),
            "vault.lock" => self.m_vault_lock(),
            "vault.delete" => self.m_vault_delete(p),

            "recovery.begin" => self.m_recovery_begin(p),
            "recovery.set_voiceprint" => self.m_recovery_set_voiceprint(p),

            "wipe.execute" => self.m_wipe_execute(p),

            "voice.listen_once" => self.m_voice_listen_once(p).await,
            "voice.listen_begin" => self.m_voice_listen_begin(p).await,
            "voice.listen_end" => self.m_voice_listen_end().await,
            "voice.listen_cancel" => self.m_voice_listen_cancel().await,
            "voice.reinit" => {
                let (mic_alive, cap_ok) = self.voice.reinit();
                Ok(json!({ "mic_alive": mic_alive, "cap_ok": cap_ok }))
            }
            "voice.playback" => {
                let active = p.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                self.voice.set_playback(active);
                Ok(json!({ "ok": true }))
            }

            "settings.get" => Ok(json!({
                "similarity_threshold": self.threshold_milli as f64 / 1000.0,
                "language": self.language,
            })),
            "settings.set" => self.m_settings_set(p),

            "audit.list" => self.m_audit_list(p),

            "vfs.list" => self.vfs_list(p),
            "vfs.read" => self.vfs_read(p),
            "vfs.media" => self.vfs_media(p),
            "vfs.export" => self.vfs_export(p),
            "vfs.import" => self.vfs_import(p),
            "vfs.prepare_drag" => self.vfs_prepare_drag(p),
            "vfs.release_temp" => self.vfs_release_temp(p),
            "vfs.mkdir" => self.vfs_mkdir(p),
            "vfs.delete" => self.vfs_delete(p),
            "vfs.rename" => self.vfs_rename(p),
            "vfs.paste" => self.vfs_paste(p),
            "vfs.move" => self.vfs_move(p),
            "vfs.search" => self.vfs_search(p),

            other => bail!("UNKNOWN METHOD: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // status / 全局配置
    // -----------------------------------------------------------------------

    fn status_json(&self) -> Value {
        let (mic_alive, cap_ok, vad_ready, asr_ready, spk_ready) = self.voice.status();
        let (fail_count, locked_until) = match &self.selected {
            Some(pth) => {
                let k = pth.to_string_lossy().into_owned();
                let lk = self.locks.get(&k).cloned().unwrap_or_default();
                let until = if lk.locked_until_ms > now_ms() { lk.locked_until_ms / 1000 } else { 0 };
                (lk.fails, until)
            }
            None => (0, 0),
        };
        json!({
            "mic_alive": mic_alive,
            "cap_ok": cap_ok,
            "vad_ready": vad_ready,
            "asr_ready": asr_ready,
            "spk_ready": spk_ready,
            "global_configured": self.cfg.is_some(),
            "vault_open": self.open.is_some(),
            "fail_count": fail_count,
            "locked_until": locked_until,
        })
    }

    fn m_global_init(&mut self, p: &Value) -> Result<Value> {
        if self.cfg.is_some() {
            bail!("GLOBAL CONFIGURATION ALREADY INITIALIZED");
        }
        let question = req_str(p, "question")?;
        let answer = req_str(p, "answer")?;
        let master = req_str(p, "master")?;
        let answer_norm = crypto::normalize_passphrase(&answer);
        let (cfg, _k_cfg, ak) =
            config::GlobalCfg::init(&self.data_dir, &question, &answer_norm, &master)?;
        self.cfg = Some(cfg);
        self.ak = Some(ak);
        self.audit.set_key(ak)?;
        self.answer_norm = Some(answer_norm);
        self.master = Some(secmem::SecretBytes::from_slice(master.as_bytes()));
        self.audit.append("GLOBAL_INIT", "global configuration initialized");
        Ok(json!({ "ok": true }))
    }

    // -----------------------------------------------------------------------
    // vault.*
    // -----------------------------------------------------------------------

    fn m_vault_list(&self) -> Result<Value> {
        let now = now_ms();
        let mut out = Vec::new();
        for e in self.index() {
            let path = PathBuf::from(&e.path);
            if !path.is_file() {
                continue;
            }
            let (size, created, has_voiceprint) = match vault::peek(&path) {
                Ok(i) => (i.size, i.created, i.has_voiceprint),
                Err(_) => (0u64, 0u64, false),
            };
            let lk = self.locks.get(&e.path).cloned().unwrap_or_default();
            let locked = lk.locked_until_ms > now;
            out.push(json!({
                "path": e.path,
                "name": e.name,
                "size": size,
                "created": created,
                "locked": locked,
                "locked_until": if locked { lk.locked_until_ms / 1000 } else { 0 },
                "fail_count": lk.fails,
                "has_voiceprint": has_voiceprint,
            }));
        }
        Ok(json!({ "vaults": out }))
    }

    fn m_vault_select(&mut self, p: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(p, "path")?);
        if !path.is_file() {
            bail!("CONTAINER NOT FOUND");
        }
        let name = self.name_for(&path);
        self.selected = Some(path);
        Ok(json!({ "ok": true, "name": name }))
    }

    fn m_vault_create(&mut self, p: &Value) -> Result<Value> {
        if self.cfg.is_none() {
            bail!("GLOBAL CONFIGURATION NOT INITIALIZED");
        }
        let path = PathBuf::from(req_str(p, "path")?);
        let name = req_str(p, "name")?;
        let passphrase_norm = crypto::normalize_passphrase(&req_str(p, "passphrase_norm")?);
        let embeddings = parse_embeddings(p)?;
        if embeddings.is_empty() {
            bail!("VOICEPRINT TEMPLATE REQUIRED");
        }
        // Recovery 包装包需要「密保答案 + 静态主密码」。优先用运行期缓存（首启 global.init 或
        // recovery.begin 会写入），也允许调用方显式传入。
        let (answer_norm, master) = match (self.answer_norm.clone(), self.master.as_ref()) {
            (Some(a), Some(m)) => (a, String::from_utf8_lossy(m.as_slice()).into_owned()),
            _ => match (p_str(p, "answer"), p_str(p, "master")) {
                (Some(a), Some(m)) => (crypto::normalize_passphrase(&a), m),
                _ => bail!("MASTER PASSWORD REQUIRED - VERIFY RECOVERY CREDENTIALS FIRST"),
            },
        };
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        let args = vault::CreateArgs {
            path: &path,
            name: &name,
            passphrase_norm: &passphrase_norm,
            embeddings,
            answer_norm: &answer_norm,
            master: &master,
            threshold_milli: self.threshold_milli,
            audit_key: self.ak,
        };
        vault::create(args)?;
        self.index_add(&path, &name);
        self.selected = Some(path.clone());
        self.audit
            .append("VAULT_CREATE", &format!("container created: {}", path.display()));
        Ok(json!({ "ok": true }))
    }

    fn m_vault_unlock(&mut self, p: &Value) -> Result<Value> {
        let path = match p_str(p, "path") {
            Some(s) => PathBuf::from(s),
            None => self
                .selected
                .clone()
                .ok_or_else(|| anyhow!("NO CONTAINER SELECTED"))?,
        };
        let key = path.to_string_lossy().into_owned();
        let now = now_ms();
        let lk = self.locks.get(&key).cloned().unwrap_or_default();
        if lk.locked_until_ms > now {
            return Ok(json!({
                "ok": false,
                "error": "LOCKED OUT",
                "remaining": 0,
                "locked_until": lk.locked_until_ms / 1000,
            }));
        }

        let passphrase_norm = crypto::normalize_passphrase(&req_str(p, "passphrase_norm")?);
        let embedding = parse_embedding(p)?;
        match vault::unlock(&path, &passphrase_norm, &embedding, self.threshold_milli) {
            Ok(u) => {
                self.locks.remove(&key);
                self.save_locks();
                self.selected = Some(path.clone());
                if u.audit_key.is_some() {
                    self.ak = u.audit_key;
                }
                if let Some(ak) = self.ak {
                    let _ = self.audit.set_key(ak);
                }
                self.open_path = Some(path.clone());
                self.open = Some(u.vault);
                self.audit
                    .append("UNLOCK", &format!("container unlocked: {}", path.display()));
                Ok(json!({ "ok": true, "remaining": MAX_FAILS }))
            }
            Err(_) => {
                // 统一失败文案；按次累计，第 5 次锁定 5 分钟（重启仍生效）。
                let rec = self.locks.entry(key).or_default();
                rec.fails = rec.fails.saturating_add(1);
                let remaining = MAX_FAILS.saturating_sub(rec.fails);
                let mut locked_until = 0u64;
                if rec.fails >= MAX_FAILS {
                    rec.locked_until_ms = now + LOCK_MS;
                    locked_until = rec.locked_until_ms / 1000;
                }
                let fail_count = rec.fails;
                self.save_locks();
                self.audit
                    .append("UNLOCK_FAILED", &format!("denied for {}", path.display()));
                Ok(json!({
                    "ok": false,
                    "error": "AUTHORIZATION DENIED",
                    "remaining": remaining,
                    "locked_until": locked_until,
                    "fail_count": fail_count,
                }))
            }
        }
    }

    fn m_vault_lock(&mut self) -> Result<Value> {
        self.voice.set_playback(false);
        let _ = vault::purge_temp_dir(&self.tmp_dir());
        if self.open.is_some() {
            self.audit.append("LOCK", "container locked");
        }
        self.open = None;
        self.open_path = None;
        Ok(json!({ "ok": true }))
    }

    fn m_vault_delete(&mut self, p: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(p, "path")?);
        if self.open_path.as_deref() == Some(path.as_path()) {
            self.open = None;
            self.open_path = None;
        }
        vault::wipe_container(&path)?;
        self.index_remove(&path);
        self.locks.remove(&path.to_string_lossy().into_owned());
        self.save_locks();
        if self.selected.as_deref() == Some(path.as_path()) {
            self.selected = None;
        }
        self.audit
            .append("VAULT_DELETE", &format!("container wiped: {}", path.display()));
        Ok(json!({ "ok": true }))
    }

    // -----------------------------------------------------------------------
    // recovery.*
    // -----------------------------------------------------------------------

    /// 校验「密保答案 + 静态主密码」双因子并解出容器 SRK。
    fn verify_recovery(&self, answer_norm: &str, master: &str, path: &Path) -> Result<vault::Unlocked> {
        {
            let cfg = self
                .cfg
                .as_ref()
                .ok_or_else(|| anyhow!("GLOBAL CONFIGURATION NOT INITIALIZED"))?;
            if !cfg.verify_answer(answer_norm)? {
                bail!("RECOVERY CREDENTIALS REJECTED");
            }
            cfg.verify_master(master)
                .map_err(|_| anyhow!("RECOVERY CREDENTIALS REJECTED"))?;
        }
        vault::unlock_with_recovery(path, answer_norm, master)
    }

    fn m_recovery_begin(&mut self, p: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(p, "path")?);
        let answer_norm = crypto::normalize_passphrase(&req_str(p, "answer")?);
        let master = req_str(p, "master")?;
        let u = self.verify_recovery(&answer_norm, &master, &path)?;
        let ak = u.audit_key;

        self.answer_norm = Some(answer_norm);
        self.master = Some(secmem::SecretBytes::from_slice(master.as_bytes()));
        if ak.is_some() {
            self.ak = ak;
        }
        if let Some(k) = self.ak {
            let _ = self.audit.set_key(k);
        }
        self.selected = Some(path.clone());
        self.open_path = Some(path);
        self.open = Some(u.vault);
        self.audit
            .append("RECOVERY_BEGIN", "recovery credentials verified");
        Ok(json!({
            "ok": true,
            "question": self.cfg.as_ref().map(|c| c.question.clone()).unwrap_or_default(),
        }))
    }

    fn m_recovery_set_voiceprint(&mut self, p: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(p, "path")?);
        let answer_norm = crypto::normalize_passphrase(&req_str(p, "answer")?);
        let master = req_str(p, "master")?;
        let passphrase_norm = crypto::normalize_passphrase(&req_str(p, "passphrase_norm")?);
        let embeddings = parse_embeddings(p)?;
        if embeddings.is_empty() {
            bail!("VOICEPRINT TEMPLATE REQUIRED");
        }

        let mut u = self.verify_recovery(&answer_norm, &master, &path)?;
        vault::reset_voiceprint(&mut u.vault, &passphrase_norm, embeddings, self.threshold_milli)?;
        let ak = u.audit_key;

        self.answer_norm = Some(answer_norm);
        self.master = Some(secmem::SecretBytes::from_slice(master.as_bytes()));
        if ak.is_some() {
            self.ak = ak;
        }
        if let Some(k) = self.ak {
            let _ = self.audit.set_key(k);
        }
        self.selected = Some(path.clone());
        self.open_path = Some(path);
        self.open = Some(u.vault);
        self.audit
            .append("RECOVERY_RESET_VOICEPRINT", "voiceprint re-enrolled, file data preserved");
        Ok(json!({ "ok": true }))
    }

    // -----------------------------------------------------------------------
    // wipe.execute
    // -----------------------------------------------------------------------

    fn m_wipe_execute(&mut self, p: &Value) -> Result<Value> {
        if !p.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false) {
            bail!("CONFIRMATION REQUIRED");
        }
        self.open = None;
        self.open_path = None;
        self.selected = None;

        for e in self.index() {
            let _ = vault::wipe_container(&PathBuf::from(&e.path));
        }
        let _ = config::erase_file(&config::GlobalCfg::path_in(&self.data_dir));
        let _ = self.audit.destroy();
        let _ = config::erase_file(&self.index_path());
        let _ = config::erase_file(&self.locks_path());
        let _ = config::erase_file(&self.settings_path());
        let _ = vault::purge_temp_dir(&self.tmp_dir());

        self.cfg = None;
        self.ak = None;
        self.answer_norm = None;
        self.master = None;
        self.locks.clear();
        self.threshold_milli = DEFAULT_THRESHOLD_MILLI;

        Ok(json!({ "ok": true }))
    }

    // -----------------------------------------------------------------------
    // voice.* / settings.* / audit.*
    // -----------------------------------------------------------------------

    async fn m_voice_listen_once(&mut self, p: &Value) -> Result<Value> {
        let max_secs = p
            .get("max_secs")
            .and_then(|v| v.as_f64())
            .map(|x| x as f32)
            .unwrap_or(12.0);
        let silence_secs = p
            .get("silence_secs")
            .and_then(|v| v.as_f64())
            .map(|x| x as f32)
            .unwrap_or(voice::DEFAULT_SILENCE_SECS);
        let ignore_playback = p
            .get("ignore_playback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let out = self.voice.listen_once(max_secs, silence_secs, ignore_playback).await?;
        Ok(serde_json::to_value(out)?)
    }

    async fn m_voice_listen_begin(&self, p: &Value) -> Result<Value> {
        let max_secs = p
            .get("max_secs")
            .and_then(|v| v.as_f64())
            .map(|x| x as f32)
            .unwrap_or(30.0);
        let ignore_playback = p
            .get("ignore_playback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        self.voice.listen_begin(max_secs, ignore_playback).await?;
        Ok(json!({ "ok": true }))
    }

    async fn m_voice_listen_end(&self) -> Result<Value> {
        let out = self.voice.listen_end().await?;
        Ok(serde_json::to_value(out)?)
    }

    async fn m_voice_listen_cancel(&self) -> Result<Value> {
        self.voice.listen_cancel().await?;
        Ok(json!({ "ok": true }))
    }

    fn m_settings_set(&mut self, p: &Value) -> Result<Value> {
        // Both parameters are optional so the UI can update one field at a time.
        if let Some(v) = p.get("similarity_threshold").and_then(|x| x.as_f64()) {
            self.threshold_milli = (v.clamp(0.0, 1.0) * 1000.0).round() as u32;
        }
        if let Some(l) = p.get("language").and_then(|x| x.as_str()) {
            self.language = normalize_language(l);
        }
        self.save_settings();
        Ok(json!({
            "ok": true,
            "similarity_threshold": self.threshold_milli as f64 / 1000.0,
            "language": self.language,
        }))
    }

    fn m_audit_list(&mut self, p: &Value) -> Result<Value> {
        let master = req_str(p, "master")?;
        let ak = {
            let cfg = self
                .cfg
                .as_ref()
                .ok_or_else(|| anyhow!("GLOBAL CONFIGURATION NOT INITIALIZED"))?;
            match cfg.verify_master(&master) {
                Ok((_k, ak)) => ak,
                Err(_) => bail!("MASTER PASSWORD REJECTED"),
            }
        };
        self.ak = Some(ak);
        self.audit.set_key(ak)?;
        let entries = self.audit.entries()?;
        Ok(json!({ "entries": entries }))
    }

    // -----------------------------------------------------------------------
    // vfs.*
    // -----------------------------------------------------------------------

    fn vfs_list(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        Ok(json!({ "files": v.list(&dir) }))
    }

    fn vfs_search(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        let q = p_str(p, "q").unwrap_or_default();
        Ok(json!({ "files": v.search(&dir, &q) }))
    }

    fn vfs_read(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        let file = req_str(p, "file")?;
        let vpath = format!("{}{}", vault::norm_dir(&dir), file);
        let kind = v
            .meta
            .files
            .get(&vpath)
            .map(|r| r.kind.clone())
            .ok_or_else(|| anyhow!("FILE NOT FOUND"))?;
        match kind.as_str() {
            "image" | "video" | "audio" => {
                let url = format!(
                    "stvault://media?path={}&file={}",
                    urlencode(&dir),
                    urlencode(&file)
                );
                Ok(json!({ "type": kind, "url": url }))
            }
            "text" => {
                let data = v.read_file(&vpath)?;
                const LIMIT: usize = 100 * 1024;
                let truncated = data.len() > LIMIT;
                let take = data.len().min(LIMIT);
                let text = String::from_utf8_lossy(&data[..take]).into_owned();
                Ok(json!({ "type": "text", "text": text, "truncated": truncated }))
            }
            _ => Ok(json!({ "type": "binary" })),
        }
    }

    fn vfs_media(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        let file = req_str(p, "file")?;
        let vpath = format!("{}{}", vault::norm_dir(&dir), file);
        let data = v.read_file(&vpath)?;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok(json!({ "ok": true, "b64": b64 }))
    }

    fn vfs_export(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        let file = req_str(p, "file")?;
        let dest = PathBuf::from(req_str(p, "dest")?);
        let vpath = format!("{}{}", vault::norm_dir(&dir), file);
        v.export_to(&vpath, &dest)?;
        Ok(json!({ "ok": true }))
    }

    fn vfs_import(&mut self, p: &Value) -> Result<Value> {
        let dir = p_str(p, "path").unwrap_or_default();
        let sources = parse_strs(p, "sources");
        if sources.is_empty() {
            bail!("NO SOURCE FILES");
        }
        let v = self.require_open_mut()?;
        let mut imported = 0u64;
        for s in &sources {
            imported += v.import_path(&dir, Path::new(s))?;
        }
        Ok(json!({ "ok": true, "imported": imported }))
    }

    fn vfs_prepare_drag(&self, p: &Value) -> Result<Value> {
        let v = self.require_open()?;
        let dir = p_str(p, "path").unwrap_or_default();
        let file = req_str(p, "file")?;
        let vpath = format!("{}{}", vault::norm_dir(&dir), file);
        let temp = vault::prepare_drag(v, &vpath, &self.tmp_dir())?;
        Ok(json!({ "ok": true, "temp_path": temp.to_string_lossy() }))
    }

    fn vfs_release_temp(&self, p: &Value) -> Result<Value> {
        let temp = PathBuf::from(req_str(p, "temp_path")?);
        vault::release_temp(&temp, &self.tmp_dir())?;
        Ok(json!({ "ok": true }))
    }

    fn vfs_mkdir(&mut self, p: &Value) -> Result<Value> {
        let dir = p_str(p, "path").unwrap_or_default();
        let name = req_str(p, "name")?;
        self.require_open_mut()?.mkdir(&dir, &name)?;
        Ok(json!({ "ok": true }))
    }

    fn vfs_delete(&mut self, p: &Value) -> Result<Value> {
        let dir = p_str(p, "path").unwrap_or_default();
        let names = parse_strs(p, "names");
        if names.is_empty() {
            bail!("NO NAMES PROVIDED");
        }
        let reclaimed = self.require_open_mut()?.delete(&dir, &names)?;
        Ok(json!({ "ok": true, "reclaimed_bytes": reclaimed }))
    }

    fn vfs_rename(&mut self, p: &Value) -> Result<Value> {
        let dir = p_str(p, "path").unwrap_or_default();
        let old_name = req_str(p, "old_name")?;
        let new_name = req_str(p, "new_name")?;
        self.require_open_mut()?.rename(&dir, &old_name, &new_name)?;
        Ok(json!({ "ok": true }))
    }

    fn vfs_paste(&mut self, p: &Value) -> Result<Value> {
        let dest = req_str(p, "dest")?;
        let src = req_str(p, "src")?;
        let action_type = req_str(p, "action_type")?;
        let names = parse_strs(p, "names");
        if names.is_empty() {
            bail!("NO NAMES PROVIDED");
        }
        let v = self.require_open_mut()?;
        if action_type == "copy" {
            v.copy_within(&src, &dest, &names)?;
        } else {
            for n in &names {
                v.mv(&src, n, &dest)?;
            }
        }
        Ok(json!({ "ok": true }))
    }

    fn vfs_move(&mut self, p: &Value) -> Result<Value> {
        let src_path = req_str(p, "src_path")?;
        let src_name = req_str(p, "src_name")?;
        let dest_path = req_str(p, "dest_path")?;
        self.require_open_mut()?.mv(&src_path, &src_name, &dest_path)?;
        Ok(json!({ "ok": true }))
    }
}

// ---------------------------------------------------------------------------
// 参数辅助
// ---------------------------------------------------------------------------

fn p_str(p: &Value, k: &str) -> Option<String> {
    p.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn req_str(p: &Value, k: &str) -> Result<String> {
    p_str(p, k).ok_or_else(|| anyhow!("MISSING PARAMETER: {k}"))
}

fn parse_embedding(p: &Value) -> Result<Vec<f32>> {
    let a = p
        .get("embedding")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("MISSING PARAMETER: embedding"))?;
    Ok(a.iter().filter_map(|x| x.as_f64().map(|f| f as f32)).collect())
}

fn parse_embeddings(p: &Value) -> Result<Vec<Vec<f32>>> {
    let a = p
        .get("embeddings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("MISSING PARAMETER: embeddings"))?;
    Ok(a.iter()
        .map(|row| {
            row.as_array()
                .map(|r| r.iter().filter_map(|x| x.as_f64().map(|f| f as f32)).collect())
                .unwrap_or_default()
        })
        .collect())
}

fn parse_strs(p: &Value, k: &str) -> Vec<String> {
    p.get(k)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// `encodeURIComponent` 等价实现（用于自定义协议查询串）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    secmem::harden_process();
    let mut root: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => {
                if let Some(v) = args.next() {
                    root = Some(PathBuf::from(v));
                }
            }
            "--data-dir" => {
                if let Some(v) = args.next() {
                    data_dir = Some(PathBuf::from(v));
                }
            }
            _ => {}
        }
    }

    let models_root = voice::models_root(root);
    let data = data_dir.unwrap_or_else(|| {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".StarTrekVault"))
            .unwrap_or_else(|_| PathBuf::from(".stvault-data"))
    });
    let _ = std::fs::create_dir_all(&data);
    let _ = std::fs::create_dir_all(data.join("drag-tmp"));

    eprintln!("[stvault] models root = {}", models_root.display());
    eprintln!("[stvault] data dir    = {}", data.display());

    let mut st = AppState::new(models_root, data);

    // stdin 逐行读取放到独立线程，避免阻塞 tokio 运行时（`listen_once` 依赖定时器驱动）。
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        let mut buf = String::new();
        loop {
            buf.clear();
            match lock.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    let line = buf.trim_end_matches(['\n', '\r']).to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if tx.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let stdout = std::io::stdout();
    eprintln!("[stvault] ready");

    while let Some(line) = rx.recv().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[stvault] invalid json: {e}");
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        let resp = match st.handle(&method, &params).await {
            Ok(result) => json!({ "id": id, "result": result }),
            Err(e) => json!({ "id": id, "error": { "message": format!("{e:#}") } }),
        };

        let mut out = stdout.lock();
        let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()));
        let _ = out.flush();
    }

    // 退出清理：临时明文一律擦除；已解锁容器自然 Drop（密钥随机覆写）。
    let _ = st.handle("vault.lock", &json!({})).await;
    let _ = vault::purge_temp_dir(&st.tmp_dir());
    let _ = std::fs::remove_dir_all(st.tmp_dir());
}
