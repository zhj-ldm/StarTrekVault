# StarTrek Vault — 设计说明（实现契约）

> 源码依据：`~/Doubao/chats/2026-10-17/new-chat-1/StarTrek-Vault-完整开发提示词.md`
> 音频链路依据：`~/Desktop/Star Trek 音频输入链路实现与复用指南.md`（+ 参考实现 `~/Desktop/备份/star-trek-assistant`）
> 本文件 = 实现契约 + 交付验证清单。

## 0. 磁盘节省策略（用户要求）

| 资源 | 处理 |
|---|---|
| `renderer/sounds/*` 5 个音效 | 真复制（370 KB） |
| `renderer/fm.html` | 真复制（由 index.php 抽取，已去 PHP） |
| `node_modules` | **软链** → `~/Desktop/备份/star-trek-assistant/ui/node_modules`（Electron 31.7.7 + electron-builder 已装） |
| `backend/target` | **软链** → `~/Desktop/备份/star-trek-assistant/target`（复用已编译 sherpa-onnx/cpal/tokio，release profile 已对齐：`lto="thin" opt-level=2 strip=true`） |
| `sherpa-onnx` C 库 | `backend/.cargo/config.toml` 指向 `~/Projects/funasr-cli/rust-asr/target/sherpa-onnx-prebuilt/sherpa-onnx-v1.13.8-osx-arm64-static-lib`（免下载 21 MB） |
| `silero_vad.onnx` | **软链** → 既有项目 `resources/models/silero-vad/silero_vad.onnx` |
| ASR 模型 | 下载 `sherpa-onnx-zipformer-small-en-2023-06-26.tar.bz2`，**只保留 int8 推理所需文件**，其余解包后即删 |
| 声纹模型 | 下载 `nemo_en_titanet_small.onnx`（40 MB，ECAPA/TitaNet 系） |

## 1. 目录结构

```
Desktop/StarTrekVault/
├── package.json                     # electron + electron-builder，main = electron/main.js
├── electron/
│   ├── main.js                      # spawn 后端 / stdio JSON-RPC / 自定义协议 / 对话框 / 拖出 startDrag / 麦克风
│   └── preload.js                   # contextBridge IPC + fm.html 透明改接层（XHR shim）+ 拖拽桥
├── renderer/
│   ├── fm.html                      # ① LCARS 文件管理器（零改动；仅改文字 + shim 注入）
│   ├── app.html                     # ② 新增 LCARS 页面（首启/FM保险箱列表/创建+录入/SETTINGS/RECOVERY/WIPE/AUDIT）
│   ├── lcars.css                    # 新增页面样式（LCARS 配色/圆角长条/grid 三列条）
│   ├── app.js                       # 新增页面逻辑（全部经由 preload 的 IPC）
│   └── sounds/                      # 5 个音效（fm.html 相对路径引用）
├── resources/
│   ├── models/{silero-vad, asr-en, spk}/
│   ├── sounds/                      # 5 个音效（打包源）
│   └── assets/                      # 拖拽图标等
├── backend/
│   ├── Cargo.toml                   # 单一 crate → 单一可执行 stvault-backend
│   ├── .cargo/config.toml           # sherpa-onnx 预编译静态库路径
│   └── src/main.rs                  # ★ 单文件后端（全部逻辑）
├── tools/
│   ├── build.sh                     # cargo build --release + 复制二进制到 resources/
│   ├── run.sh                       # 开发态启动 electron
│   └── mkicon.js                    # 生成拖拽图标 PNG
└── docs/DESIGN.md                   # 本文件
```

`STAR_TREK_ROOT`：打包态 = `.app/Contents/Resources`；开发态 = `<项目>/resources`。
后端取模型根：`--root <dir>` 参数优先，其次 `STAR_TREK_ROOT` 环境变量。
数据目录：`--data-dir <dir>`（Electron 传 `app.getPath('userData')`），存放 `global.stcfg` / `audit.stlog` / `vaults.index` / `drag-tmp/`。

## 2. 密钥分层（§八.2 硬约束）

```
准入因子（绝不当密钥）: 声纹 embedding / 语音口令 / 密保答案 / 静态密码
      │  仅用于解开 SRK 包装包
      ▼
K_voice  = Argon2id(norm(ASR 口令文本), salt_voice)     → wrap_voice  = AES-KWP(K_voice, SRK)
K_rec    = Argon2id(answer_norm ++ "\0" ++ master, salt_recovery) → wrap_recovery = AES-KWP(K_rec, SRK)
      ▼
SRK (32B, 每容器独立随机)  ← AES-KWP（NIST SP800-38F）解封
      ▼
meta_key = SHA3-256(SRK ‖ "meta")        → 加密容器元数据（目录树/文件名/大小/分片索引）
FMK (每文件 32B 随机) ← 由 meta 内的 fmk 字段提供（受 SRK 保护）
      ▼
chunk_key(i) = SHA3-256(FMK ‖ file_id ‖ i)   → AEAD 加密第 i 片（每片独立 12B 随机 nonce + 认证标签）

AK (审计日志密钥, 32B 随机)：随全局配置加密体保存（K_cfg 保护），并 AES-KWP 包装后放进每个容器元数据
```

- **Argon2id 参数**：`memory_cost = 1,048,576 KiB (1 GiB) / iterations = 10 / parallelism = 8`，按需求 §八.3 字面值，不可降级（常量 `ARGON2_*`，构建时确认单次派生耗时）。
- 口令文本**不以明文存进容器**：容器头部只存 `passphrase_fp = SHA3-256(norm 文本)`；解锁时用「本次识别文本」现算 K_voice，包装包解不开即判定口令不匹配 —— 文本匹配由密码学强制，同时再比对 `passphrase_fp` 常量时间。
- 全部密钥比较用常量时间比较；失败统一返回 `AUTHORIZATION DENIED`。

## 3. `.stvault` 容器格式（单文件）

```
off 0     magic "STVAULT1" (8)
off 8     version u32 = 1
off 12    vault_id (16)
off 28    created_at u64
off 36    argon2 m_cost u32 | t_cost u32 | p_cost u32        (off 48)
off 48    salt_voice (16)
off 64    salt_recovery (16)
off 80    passphrase_fp (32)
off 112   emb_dim u32 | emb_count u32 | threshold_milli u32  (off 124)
off 124   embeddings (emb_dim * emb_count * f32 LE)
   ...    wrap_voice (40)            # AES-KWP 包裹的 SRK（32 + 8 字节 semiblock）
   ...    wrap_recovery (40)         # AES-KWP 包裹的 SRK（Recovery 通路）
   ...    meta_nonce (12)
   ...    meta_len u32               # 密文长度（明文 + 16 字节 AEAD 标签）
   ...    integrity (32)             # SHA3-256(前面全部字节)
   ...    补齐到 header_region = 8192
header_region (8192)  元数据区：meta_ciphertext (meta_len) 补齐到 meta_region = 2 MiB
data_off = 8192 + 2 MiB              # 固定，元数据增长不搬动任何分片
```
数据区每条分片记录：`u32 ct_len ‖ nonce(12) ‖ ciphertext‖tag`，`off` 相对 `data_off`。
元数据 JSON（加密）：

```json
{"name":"VAULT","chunk_size":1048576,"next_off":0,"free":[[0,0]],
 "audit_wrap":"<hex80>",
 "dirs":{"docs/":{"modified":"..."}},
 "files":{"docs/a.txt":{"size":10,"modified":"...","kind":"text","file_id":"<hex16>",
    "fmk":"<hex32>","chunks":[{"off":0,"ct":26,"plain":10,"nonce":"<hex12>"}]}}}
```

**删除 = 真实物理擦除**：① 该文件全部分片原地 CSPRNG 覆写 3 轮 + `fsync`；② 元数据移除并标记空闲；③ 碎片整理（把存活分片按序下移重写）→ 覆写腾出的尾部 3 轮 → `ftruncate` 收缩容器文件实际占用。System Wipe 同理对整文件 3 轮覆写后 `unlink`。

## 4. JSON-RPC（stdio，逐行 JSON；请求 `{"id","method","params"}` → `{"id","result"}` / `{"id","error":{"message"}}`；stderr 为日志）

| 方法 | 参数 | 返回 |
|---|---|---|
| `ping` | `{}` | `{ok}` |
| `status` | `{}` | `{mic_alive,cap_ok,vad_ready,asr_ready,spk_ready,global_configured,vault_open,fail_count,locked_until}` |
| `global.status` | `{}` | `{configured, question}` |
| `global.init` | `{question,answer,master}` | `{ok}` |
| `vault.list` | `{}` | `{vaults:[{path,name,size,created,locked,locked_until,fail_count,has_voiceprint}]}` |
| `vault.select` | `{path}` | `{ok, name}`  → 供 fm.html 解锁面板使用 |
| `vault.create` | `{path,name,passphrase_norm,embeddings:[[f32]]}` | `{ok}` |
| `vault.unlock` | `{passphrase_norm,embedding:[f32]}` | `{ok,remaining,locked_until?}` / `{error:"AUTHORIZATION DENIED",remaining,locked_until?}` |
| `vault.lock` | `{}` | `{ok}` |
| `vault.delete` | `{path}` | `{ok}` |
| `recovery.begin` | `{path,answer,master}` | `{ok,question}` |
| `recovery.set_voiceprint` | `{path,answer,master,passphrase_norm,embeddings}` | `{ok}` |
| `wipe.execute` | `{confirm:true}` | `{ok}` |
| `voice.listen_once` | `{max_secs?,silence_secs?,ignore_playback?}` | `{text,text_norm,embedding:[f32],rms,end_reason,duration}` |
| `voice.reinit` | `{}` | `{mic_alive,cap_ok}` |
| `voice.playback` | `{active}` | `{ok}`（回声门） |
| `settings.get` / `settings.set` | `{similarity_threshold?}` | `{similarity_threshold,...}` |
| `audit.list` | `{master}` | `{entries:[{at,event,detail,hash}]}` |
| `vfs.list` | `{path}` | `{files:[{name,size,type,is_dir,modified}]}` |
| `vfs.read` | `{path,file}` | `{type:"image"丨"video"丨"audio"丨"text"丨"binary", url?, text?, truncated?}` |
| `vfs.media` | `{path,file}` | `{ok, b64}`（`stvault://` 协议用，预览流式取数） |
| `vfs.export` | `{path,file,dest}` | `{ok}`（dest 由主进程保存对话框选定） |
| `vfs.import` | `{path,sources:[absPath]}` | `{ok,imported}`（目录递归、保持相对结构） |
| `vfs.prepare_drag` | `{path,file}` | `{ok,temp_path}`（解密到 `data-dir/drag-tmp/`，供 `webContents.startDrag`） |
| `vfs.release_temp` | `{temp_path}` | `{ok}`（3 轮覆写 + 删除） |
| `vfs.mkdir` | `{path,name}` | `{ok}` |
| `vfs.delete` | `{path,names:[..]}` | `{ok,reclaimed_bytes}` |
| `vfs.rename` | `{path,old_name,new_name}` | `{ok}` |
| `vfs.paste` | `{dest,src,action_type,names:[..]}` | `{ok}` |
| `vfs.move` | `{src_path,src_name,dest_path}` | `{ok}` |
| `vfs.search` | `{path,q}` | `{files:[...]}` |

## 5. 文件管理器（renderer/fm.html + renderer/fm.js）

文件管理器页面与主界面同为自研 LCARS 页面：同一套 `renderer/lcars.css`、同一套 `renderer/i18n.js`，**不再有 XHR shim**。`fm.js` 通过 `window.stvault.invoke` 直接调用后端 JSON-RPC：

| 界面操作 | 后端 |
|---|---|
| 列目录 / 刷新 / 面包屑跳转 / UP | `vfs.list{path}` |
| 打开目录 / 双击 | `vfs.list`（文件则 `vfs.read` → 预览模态） |
| 预览（图片/音视频） | `vfs.read` 返回 `url` → `stvault://media?...` 自定义协议 |
| 下载选中 / 预览内下载 | `IPC export-file` → 保存对话框 → `vfs.export` |
| 上传 | `IPC pick-files`（`dialog.showOpenDialog` 多选）→ `vfs.import` |
| 新建目录 / 删除 / 重命名 / 复制 / 粘贴 / 搜索 | `vfs.mkdir` / `vfs.delete` / `vfs.rename` / `vfs.paste` / `vfs.search` |
| 保险箱内拖拽到目录行 | `vfs.move` |

解锁面板是页面自身的 `#lock-overlay`（LCARS 风格）：点击 `SPEAK & VERIFY` / 回车 → beep → `voice.listen_once{silence_secs:1.5}` → `vault.unlock`；剩余次数用 `#lock-error` 展示。成功后播 `verify` + 隐藏遮罩 + 刷新列表。
导航栏按钮：`UPLOAD / DOWNLOAD / REFRESH / UP / NEW DIRECTORY / DELETE / RENAME / COPY / PASTE / SEARCH / SORT`，下方分组追加 `SETTINGS / RECOVERY / AUDIT / LOCK VAULT`（后者 `vault.lock` 后返回 `app.html`；前三个返回 `app.html?view=…&from=fm`）。

## 6. 拖入 / 拖出（用户新增需求，解锁后可用）

| 方向 | 实现 |
|---|---|
| **Finder → 保险箱** | `fm.js` 在 `document` 上挂 `dragover`(preventDefault) + `drop`：读 `e.dataTransfer.files` 的 `file.path`（Electron ≤31 提供）→ `vfs.import` 到当前目录，或鼠标悬停的目录行（由 `dragover` 记录 `data-isdir` 行） |
| **保险箱 → Finder** | `fm.js` 捕获行 `dragstart`：按住 ⌥/⌘ 时 `preventDefault()` → IPC `drag.begin{path,file}` → 主进程 `vfs.prepare_drag` 解密到临时文件 → `webContents.startDrag({file:temp,icon})` |
| 缓存清理 | 窗口失焦 / 锁定 / 退出 → `vfs.release_temp`（3 轮覆写 + 删除）；临时明文仅存在于 `data-dir/drag-tmp/` |
| 保险箱内部移动 | 普通拖拽（未按 ⌥/⌘）落到目录行 → `vfs.move` |

## 7. 音效 / 锁定状态机（§九）

`beep`(computer_beep_1) 解锁/录入开始 → `verify`(command_code_verify) 全部校验通过 → `error`(error.wav) 任一失败 → `warning`(warning.wav) 第 4 次失败（剩 1 次）→ 第 5 次失败：`error` + 锁定 5 分钟（持久化，重启仍生效）。`chirp` 沿用既有操作反馈。
计数规则：`fail 0→1→2→3→4`（播 warning）`→5`（锁定）。解锁成功后计数归零。

## 8. 交付验证清单（§十.4）

1. 首次启动 → LCARS 设置页 → 设置安全问题/答案/静态主密码 → 生成加密全局配置。
2. 创建保险箱 → 选位置命名 → 【录入声纹授权码】→ beep → 朗读口令（2~3 遍平均）→ 生成 `.stvault`。
3. 正确口令 + 正确声纹 → 成功（verify 音效）→ 进入 LCARS 文件管理器。
4. 错误口令 / 他人声纹 → 失败（error 音效）+ `VOICEPRINT MISMATCH — AUTHORIZATION DENIED`。
5. 第 4 次失败 → warning 音效；第 5 次 → 锁定 5 分钟（重启仍生效）。
6. 容器在外部编辑器/十六进制查看器不可读（无文件名/目录/大小信息）。
7. 保险箱内删除文件 → 容器**实际体积收缩**（`ls -l` 前后对比）。
8. `.stvault` 头部任意字节篡改 → 拒绝加载。
9. Recovery：设置页 `RECOVERY ACCESS` 双因子通过 → 清除旧声纹模板 → 重新录入 → 文件数据保留。
10. System Wipe → 3 轮覆写后删除全部容器 + 全局配置 + 审计日志 → 恢复出厂初始状态。
11. 麦克风未授权 → UI 正确提示并引导授权；授权后 `voice.reinit` 成功才置 listening。
12. 解锁后拖入（Finder → 保险箱）与拖出（保险箱 → Finder）均可用，且临时明文被清除。
13. 审计日志哈希链：抽掉/篡改任一条 → 整链校验失败。
