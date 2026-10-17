# Star Trek Vault

**An offline, voiceprint-authorized, encrypted vault.**
Electron (UI) + a single Rust backend binary. Every container is a self-contained,
authenticated-encrypted file whose key material is derived with memory-hard KDFs and
protected by modern AEAD + key-wrapping primitives.

> Encryption here is not decorative or a toy demo. The design targets
> **production-grade, at-rest confidentiality and integrity**, built only on
> standardized, non-degradable cryptographic primitives. The concrete guarantees and
> the threat model are documented below, and every claim maps to code you can read.

---

## 1. What this is

- A **local-only** encrypted vault (`.stvault` containers) that stores files inside a
  virtual file system (VFS) written straight into one authenticated-encrypted file.
- Two independent unlock paths:
  1. **Voice path** — spoken passphrase **+** speaker voiceprint (both required).
  2. **Recovery path** — security answer **+** static master password.
- A native **file manager** (LCARS-styled) to import / export / preview / delete files.
- **No network access of any kind.** No telemetry, no CDN, no remote models — the app
  runs fully offline; all models, sounds and assets ship inside the bundle.

---

## 2. Cryptographic primitives

All primitives are standard and are used in standard modes. Nothing here is a
home-made cipher; the only custom construction is a keystream for template
confidentiality, derived from SHA3 (see §5), which is a well-understood hash-CTR style
construction.

| Purpose | Algorithm | Standard |
|---|---|---|
| File chunks & metadata (AEAD) | **AES-256-GCM-SIV** | RFC 8452 (nonce-misuse resistant) |
| Root-key wrapping (KEK/DEK) | **AES Key Wrap, 256-bit** | RFC 3394 / NIST SP 800-38F |
| Passphrase / answer KDF | **Argon2id** (memory-hard) | RFC 9106 |
| Integrity & hashing | **SHA3-256 / SHA3-512** | FIPS 202 |
| Constant-time comparison | `subtle` | — |
| Secret zeroization / page-lock | `zeroize` + `mlock` | — |
| Randomness | `getrandom` (OS CSPRNG) | macOS kernel CSPRNG |

**Argon2id parameters.** Current containers: `m = 256 MiB, t = 8, p = 4` (well above the
OWASP minimum of ≥19 MiB). Legacy containers created with the original parameters
`m = 1 GiB, t = 10, p = 8` remain readable — parameters travel **inside** each container
header, so raising or lowering the global constants never invalidates existing files.

---

## 3. Key hierarchy

Keys are layered so that no single key ever directly protects the raw file bytes:

```
chunk key   ←  FMK (file master key, per file)
            ←  SRK (vault root key, 256-bit random, unique per container)
                    │
                    ├── wrap_voice    = AES-KW( K_voice ,  SRK )   # voice path
                    └── wrap_recovery = AES-KW( K_recovery, SRK )  # recovery path
```

- **SRK** is generated from the OS CSPRNG and is unique per container. It is never
  stored in the clear; it only ever exists wrapped.
- **K_voice** is derived: `K_voice = Argon2id(passphrase ‖ vault_id, salt_voice)`.
- **K_recovery** is derived: `K_recovery = Argon2id(answer ‖ master ‖ vault_id, salt_recovery)`.
- **meta_key** = `SHA3-256(SRK ‖ "meta")`; **chunk_key** = `SHA3-256(domain ‖ FMK ‖ file_id ‖ index)`.

Domain-separation prefixes (`stvault-wrap-voice-v1`, `stvault-wrap-recovery-v1`, …)
guarantee the recovery and voice derivations can never collide.

> **The voiceprint is never key material.** Biometrics are unstable and
> non-derivable, so they are used strictly as an *admission factor* (a gate), never as
> a key. The actual key material is always the passphrase, hardened by Argon2id.

---

## 4. Container format (`.stvault`, version 2)

```
off 0      magic "STVAULT1" (8)
off 8      version u32 = 2
off 12     vault_id (16)                 # per-container domain separator
off 36     argon2 m / t / p
off 48     salt_voice (16)   off 64 salt_recovery (16)
off 80     passphrase_fp (32)            # v2: keyed commitment (needs Argon2 output)
off 112    emb_dim | emb_count | threshold
off 124    emb_slots = 3 * emb_dim * f32 # v2: voiceprint templates, ENCRYPTED
off ...    wrap_voice (40)  wrap_recovery (40)  meta_nonce (12)  meta_len (4)  integrity (32)
-- padding to HEADER_REGION = 8192 --
HEADER_REGION (8192)        metadata region (encrypted meta JSON), padded to META_REGION = 2 MiB
DATA_OFF (8192 + 2 MiB)     data region: chunk records  u32 ct_len ‖ nonce(12) ‖ ct‖tag
```

- All region offsets are **fixed constants**, so metadata growth never moves chunks.
- The header carries a `SHA3-256` integrity tag over the whole header; any tampering is
  rejected before any key is derived.
- Metadata is encrypted with `AES-256-GCM-SIV` under `meta_key`, with AAD = the header
  prefix (so the header and body are cryptographically bound).

---

## 5. Hardening (v2 security revision)

The current container version (`v2`) closes three real vulnerabilities found in the
earlier design. Old `v1` containers remain readable; every newly created container, and
any container whose voiceprint is re-enrolled, is upgraded to `v2`.

1. **Voiceprint templates are now encrypted at rest.**
   In `v1`, the speaker templates were stored in the header in the clear, so anyone who
   stole the container file could read a template and replay it as a probe to satisfy the
   voice gate offline. In `v2` the templates are masked with a keystream derived from the
   passphrase:
   `K_emb = SHA3-256("stvault-emb-v2" ‖ K_voice)`, `keystream_j = SHA3-256(K_emb ‖ LE64(j))`.
   Without the correct passphrase the decrypt yields pseudorandom values and the
   similarity check cannot pass.

2. **No cheap offline passphrase oracle.**
   In `v1`, `passphrase_fp = SHA3-256(plaintext passphrase)` was stored in the header,
   letting an attacker use a fast SHA3 dictionary to find the right candidate *before*
   paying for Argon2. In `v2` it is replaced by a **keyed commitment**
   `SHA3-256("stvault-fp-v2" ‖ salt_voice ‖ K_voice)`, which cannot be computed without
   first running Argon2. Offline guessing now costs a full Argon2id per candidate.

3. **The recovery path is rate-limited and lockout-persisted.**
   Both unlock paths now count failures and lock out after **5 failed attempts for 5
   minutes**, persisted to `locks.json` so a restart does not reset the counter.

---

## 6. Erasure model

Deletion is a real physical-erasure pipeline, not a metadata flag:

1. Every chunk of the file is overwritten **in place** with CSPRNG bytes for **3 rounds**,
   each followed by `fsync`.
2. The file is removed from the metadata (which is then re-encrypted).
3. The data region is **compacted** (surviving chunks rewritten in order), the freed tail
   is overwritten 3 rounds again, and the file is shrunk with `ftruncate` to the actual
   used size.

A system-wide wipe (panic feature) overwrites every container, the global config, the
audit log, the index and the lock/settings files, then deletes them.

---

## 7. Threat model

**Designed to protect against:**
- Theft of the container file / disk at rest.
- Offline brute force of the passphrase (Argon2id + no cheap oracle + lockout).
- Tampering with ciphertext or headers (AEAD tags + header SHA3 integrity).
- Replay of stored biometric templates (encrypted templates, v2).
- Post-deletion data recovery from the medium (multi-round overwrite + compaction).

**Explicitly out of scope:**
- A fully compromised OS (keyloggers, memory scrapers, malicious firmware).
- Coercion / "evil maid" with administrative access while the vault is open.
- Hardware side-channel or cold-boot attacks.
- Weak user-chosen passphrases or security answers.

**Honest note:** the design follows established standards and best practices and the
tests in this repository exercise it, but this codebase has **not** undergone a
third-party security audit. Treat it as strong engineering, and audit it yourself
before relying on it for high-value secrets.

---

## 8. Architecture

```
Electron main process (electron/main.js)
  │  spawns & talks JSON-RPC over stdio
  ▼
Rust backend  `stvault-backend` (backend/src/)
  ├── crypto.rs   primitives (AEAD, AES-KW, Argon2id, SHA3, ct_eq)
  ├── vault.rs    .stvault container + VFS + erasure
  ├── config.rs   global config, recovery factors, audit key
  ├── audit.rs    encrypted hash-chained audit log
  ├── voice.rs    cpal capture + Silero VAD + sherpa-onnx ASR/voiceprint (offline)
  └── secmem.rs   SecretBytes (mlock + zeroize)
```

Renderer is plain HTML/CSS/JS (LCARS theme). The renderer never sees raw keys; it only
invokes backend RPC methods.

---

## 9. Build

Requirements: Rust (stable) and Node.js. Voice models (ASR / voiceprint / VAD) are
bundled under `resources/` and are used entirely offline.

```bash
# 1) build the Rust backend
bash tools/build.sh          # or: (cd backend && cargo build --release)

# 2) install JS deps
npm install

# 3) run in development
npm start

# 4) package a macOS app + DMG
npm run dist                 # node tools/mkicon.js && electron-builder --mac
```

If you have a local prebuilt sherpa-onnx static library, point
`SHERPA_ONNX_LIB_DIR` at its `lib/` directory to avoid re-downloading it; otherwise the
build fetches the prebuilt library automatically.

---

## 10. License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).

---

## 中文要点

- **算法全部是标准而非自创**：AES-256-GCM-SIV（RFC 8452）、AES Key Wrap（RFC 3394 /
  NIST SP 800-38F）、Argon2id（RFC 9106，当前 256 MiB / t8 / p4）、SHA3-256/512（FIPS 202）、
  `subtle` 常量时间比较、`zeroize` + `mlock`、OS CSPRNG。
- **密钥分层**：分片密钥 ← 文件主密钥 FMK ← 保险箱根密钥 SRK（每容器独立随机，
  仅以 AES-KW 封装两份）；声纹只作「门禁」，绝不当密钥材料。
- **v2 安全加固（已修复三个真实漏洞）**：① 声纹模板改为口令派生密钥流加密，杜绝
  离线重放；② 口令指纹改为「需 Argon2 才能计算」的承诺，消除廉价离线 oracle；
  ③ 备用保险（密保答案 + 主密码）通路加上失败计数与锁定（5 次 / 5 分钟，持久化）。
- **删除是真擦除**：3 轮 CSPRNG 原地覆写 + `fsync`，碎片整理后收缩文件。
- **完全离线**：无任何网络请求。
- 坦率说明：设计遵循标准与最佳实践，但**尚未经过第三方安全审计**。
