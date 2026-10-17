//! 安全内存原语：mlock 锁页（禁止换出到 macOS swap）+ 离开作用域覆写归零。
//!
//! 为什么必须做：
//! - macOS 上未 `mlock` 的内存可以被换出到 swap 文件，明文密钥会落盘。
//! - 普通 `Vec<u8>` / `[u8;32]` 在 `free()` 之后内容仍在堆里，后续分配可能读到。
//! - 二进制被 core dump / panic 回显时会带上栈上的明文。
//!
//! 因此所有密钥、声纹向量、临时明文一律走 [`SecretBytes`]。

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// 一段驻留锁定内存的敏感字节。
///
/// - 分配时 `mlock`（macOS 上最多锁 32 MB / 进程，够用），失败不致命但会记录。
/// - `Drop` 时用系统安全随机覆写全部字节后再 `munlock` + 释放。
/// - `clone_from` / `clone` 同样走锁定分配，绝不出现「未锁定的密钥副本」。
pub struct SecretBytes {
    buf: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    /// 分配 `len` 字节锁定内存。
    pub fn zeroed(len: usize) -> Self {
        // 先在未锁定内存里造出全零缓冲，再整体复制进锁定页，避免锁定页里出现
        // 分配器写入的中间态内容被观测到。
        let mut v = vec![0u8; len];
        let mut s = Self {
            buf: Vec::new(),
            locked: false,
        };
        s.buf.resize(len, 0);
        if s.try_lock() {
            s.buf.copy_from_slice(&v);
            s.locked = true;
        } else {
            s.buf.copy_from_slice(&v);
        }
        v.zeroize();
        s
    }

    /// 从字节切片构造（调用方应尽快清掉自己的副本）。
    pub fn from_slice(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.buf.copy_from_slice(src);
        s
    }

    /// 从系统安全随机源填充 n 字节（macOS 上 rand::rngs::OsRng → getrandom(2)，
    /// 内核 CSPRNG，不是自实现 PRNG）。
    pub fn random(n: usize) -> Self {
        use rand::RngCore;
        let mut s = Self::zeroed(n);
        rand::rngs::OsRng.fill_bytes(&mut s.buf);
        s
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// 导出为定长数组（仅用于 crate 内部的锁页密钥槽）。
    pub fn to_array32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.buf[..32]);
        out
    }

    fn try_lock(&mut self) -> bool {
        if self.buf.is_empty() {
            return true;
        }
        // macOS / Linux：mlock 把页锁在物理内存，禁止换出。
        let r = unsafe { libc::mlock(self.buf.as_ptr() as *const libc::c_void, self.buf.len()) };
        if r != 0 {
            eprintln!(
                "[secmem] mlock 失败（errno={}），敏感数据仍会在内存中但可能被换出",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
            return false;
        }
        // 禁止该区域进入 core dump。
        // macOS 的 `madvise` 没有 `MADV_DONTDUMP`（只有 MADV_FREE/ZERO_WIRED_PAGES 等），
        // 因此 macOS 侧改为进程级关闭 core dump（见 `harden_process`）。
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(
                self.buf.as_ptr() as *mut libc::c_void,
                self.buf.len(),
                libc::MADV_DONTDUMP,
            );
        }
        true
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            use rand::RngCore;
            // 系统 CSPRNG 覆写（不是 memset 0：编译器可能把 memset 0 优化掉，
            // 且旧 SSD / COW 页里可能还留着上一次的内容）。
            rand::rngs::OsRng.fill_bytes(&mut self.buf);
            self.buf.zeroize();
            if self.locked {
                unsafe {
                    libc::munlock(self.buf.as_ptr() as *const libc::c_void, self.buf.len());
                }
                self.locked = false;
            }
        }
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(&self.buf)
    }
}

/// 便捷别名：32 字节密钥。
pub type Key32 = SecretBytes;

/// 生成一个随机 32 字节密钥并锁定内存。
pub fn random_key32() -> Key32 {
    SecretBytes::random(32)
}

/// 生成 n 字节随机盐（Argon2id 用）。
pub fn random_salt(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

/// 把一段敏感缓冲覆写归零后释放（用于预览/打开文件后的明文）。
pub fn scrub(buf: &mut [u8]) {
    use rand::RngCore;
    if !buf.is_empty() {
        rand::rngs::OsRng.fill_bytes(buf);
        buf.zeroize();
    }
}

/// 用系统安全随机（`getrandom(2)` / 内核 CSPRNG）填充整段缓冲。
/// 用于「删除 = 真实物理擦除」（分片原地覆写）与 System Wipe（整容器覆写）。
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    if !buf.is_empty() {
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

/// 进程级安全加固：关闭 core dump（`RLIMIT_CORE = 0`）。
///
/// macOS 没有 `MADV_DONTDUMP`，因此这是 macOS 上防止密钥随崩溃转储落盘的唯一手段；
/// Linux 上二者叠加（分区域 DONTDUMP + 进程级禁 dump）。启动时调用一次即可。
pub fn harden_process() {
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            eprintln!(
                "[secmem] 关闭 core dump 失败（errno={}）",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
        }
    }
}