//! 音频输入链路：**唯一一路** cpal 常驻采集（16 kHz / 单声道 / f32）
//! + Silero VAD + FunASR Paraformer-zh ASR + 声纹 embedding。
//!
//! 硬规则（违反必出问题，见《Star Trek 音频输入链路实现与复用指南》踩坑结论）：
//! 1. 只允许一条 cpal 常驻采集流，消费者通过 `tokio::broadcast` 订阅；任何模块不得再开第二路。
//! 2. 采集统一重采样到 16 kHz / 单声道 / f32（三个模型都强制 16k）。
//! 3. 降采样前必须加抗混叠低通（fc = 7 kHz），且重采样相位跨回调保留。
//! 4. CPU 阻塞推理（ASR / 声纹）一律走 `spawn_blocking`，不占 async 线程。
//! 5. VAD：Silero v5，`max_speech_duration` 必须 > 0；每次录音前 `reset()`；push 后清空上游段落队列。
//! 6. 回声控制：录音前若有播报，先等播报结束 + 400 ms 余音窗口，再 `discard()` 清空采集缓冲。

use anyhow::{anyhow, bail, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use sherpa_onnx::{
    OfflineParaformerModelConfig, OfflineRecognizer, OfflineRecognizerConfig, SileroVadModelConfig,
    SpeakerEmbeddingExtractor, SpeakerEmbeddingExtractorConfig, VadModelConfig,
    VoiceActivityDetector,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{broadcast, oneshot};

pub const SAMPLE_RATE: i32 = 16000;
/// 说完话后连续多少秒无人声判定录音结束（1.5 s：说完静默即尽快提交）。
pub const DEFAULT_SILENCE_SECS: f32 = 1.5;
/// 短于此长度的有效语音视为误触发。
pub const MIN_SPEECH_SECS: f32 = 0.4;
/// 一直没人说话时的放弃时间。
const NO_SPEECH_LIMIT_SECS: f32 = 8.0;

// ---------------------------------------------------------------------------
// cpal 采集（含抗混叠低通 + 相位连续重采样）
// ---------------------------------------------------------------------------

/// cpal 0.15 把 `Stream` 保守标记为 !Send/!Sync，实际底层是引用计数的
/// AudioObjectID，跨线程移动安全；用这个包装让 `Voice` 能放进全局状态。
struct StreamKeep(#[allow(dead_code)] Option<cpal::Stream>);
unsafe impl Send for StreamKeep {}
unsafe impl Sync for StreamKeep {}

/// 二阶 Butterworth 低通（抽取前抗混叠）。
struct Biquad {
    b0: f32,
    b1: f32,
    b2: f32,
    a1: f32,
    a2: f32,
    x1: f32,
    x2: f32,
    y1: f32,
    y2: f32,
}

impl Biquad {
    fn lowpass(fs: f32, fc: f32) -> Self {
        let w0 = 2.0 * std::f32::consts::PI * fc / fs;
        let (sin_w0, cos_w0) = w0.sin_cos();
        let alpha = sin_w0 / (2.0 * std::f32::consts::FRAC_1_SQRT_2);
        let a0 = 1.0 + alpha;
        Self {
            b0: ((1.0 - cos_w0) / 2.0) / a0,
            b1: (1.0 - cos_w0) / a0,
            b2: ((1.0 - cos_w0) / 2.0) / a0,
            a1: (-2.0 * cos_w0) / a0,
            a2: (1.0 - alpha) / a0,
            x1: 0.0,
            x2: 0.0,
            y1: 0.0,
            y2: 0.0,
        }
    }
    fn step(&mut self, x: f32) -> f32 {
        let y = self.b0 * x + self.b1 * self.x1 + self.b2 * self.x2 - self.a1 * self.y1 - self.a2 * self.y2;
        self.x2 = self.x1;
        self.x1 = x;
        self.y2 = self.y1;
        self.y1 = y;
        y
    }
}

/// 相位连续的线性插值抽取器（`pos` 跨回调保留，避免每次回调重开相位）。
struct Resampler {
    step: f64,
    pos: f64,
    last: f32,
    has_last: bool,
}

impl Resampler {
    fn new(ratio: f64) -> Self {
        Self {
            step: ratio.max(1.0),
            pos: 0.0,
            last: 0.0,
            has_last: false,
        }
    }
    fn process(&mut self, data: &[f32], out: &mut Vec<f32>) {
        let n = data.len() as f64;
        let mut i = self.pos;
        while i < n {
            let i0 = i.floor();
            let frac = (i - i0) as f32;
            let (a, b) = if i0 < 0.0 {
                if !self.has_last {
                    i += self.step;
                    continue;
                }
                (self.last, data.first().copied().unwrap_or(0.0))
            } else {
                let k = i0 as usize;
                (data[k], data.get(k + 1).copied().unwrap_or(data[k]))
            };
            out.push(a + (b - a) * frac);
            i += self.step;
        }
        self.pos = i - n;
        if let Some(l) = data.last() {
            self.last = *l;
            self.has_last = true;
        }
    }
}

struct CapState {
    buffer: Vec<f32>,
    lp: Option<Biquad>,
    rs: Resampler,
    mono: Vec<f32>,
    out: Vec<f32>,
}

/// 常驻采集：保留最近 `window_secs` 秒的 16k 单声道 f32，并向订阅者扇出。
pub struct AudioCapture {
    state: Arc<Mutex<CapState>>,
    _stream: Option<StreamKeep>,
}

impl AudioCapture {
    fn new(alive: Arc<AtomicBool>, tx: broadcast::Sender<Vec<f32>>) -> Result<Self> {
        let host = cpal::default_host();
        let device = host.default_input_device().context("未找到输入设备（麦克风）")?;
        let default = device.default_input_config().context("读取默认输入配置失败")?;
        let input_rate = default.sample_rate().0 as f64;
        let channels = default.channels() as usize;
        let config = cpal::StreamConfig {
            channels: default.channels(),
            sample_rate: default.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        };
        let ratio = input_rate / SAMPLE_RATE as f64;
        let lp = if ratio > 1.05 {
            Some(Biquad::lowpass(input_rate as f32, 7000.0))
        } else {
            None
        };
        let state: Arc<Mutex<CapState>> = Arc::new(Mutex::new(CapState {
            buffer: Vec::with_capacity(SAMPLE_RATE as usize * 32),
            lp,
            rs: Resampler::new(ratio),
            mono: Vec::new(),
            out: Vec::new(),
        }));

        let err_fn = |e| eprintln!("[audio] 采集错误: {e}");
        let state_ref = state.clone();
        let alive_ref = alive.clone();
        let stream = device
            .build_input_stream(
                &config,
                move |data: &[f32], _| {
                    // macOS 未授权时回调仍在跑但样本恒为 0：用「出现非零样本」判断真实可用
                    if !alive_ref.load(Ordering::SeqCst) && data.iter().any(|s| s.abs() > 1e-4) {
                        alive_ref.store(true, Ordering::SeqCst);
                    }
                    let mut st = state_ref.lock().unwrap();
                    let CapState { buffer, lp, rs, mono, out } = &mut *st;
                    mono.clear();
                    if channels <= 1 {
                        mono.extend_from_slice(data);
                    } else {
                        let mut i = 0;
                        while i + channels <= data.len() {
                            let sum: f32 = data[i..i + channels].iter().sum();
                            mono.push(sum / channels as f32);
                            i += channels;
                        }
                    }
                    if let Some(lp) = lp.as_mut() {
                        for s in mono.iter_mut() {
                            *s = lp.step(*s);
                        }
                    }
                    out.clear();
                    rs.process(mono, out);
                    buffer.extend_from_slice(out);
                    let len = buffer.len();
                    let cap = SAMPLE_RATE as usize * 32;
                    if len > cap {
                        buffer.drain(0..(len - cap));
                    }
                    if tx.receiver_count() > 0 {
                        let _ = tx.send(out.clone());
                    }
                },
                err_fn,
                None,
            )
            .context("创建输入流失败（麦克风不可用）")?;
        stream.play().context("启动输入流失败")?;
        Ok(Self {
            state,
            _stream: Some(StreamKeep(Some(stream))),
        })
    }

    fn discard(&self) {
        self.state.lock().unwrap().buffer.clear();
    }
}

// ---------------------------------------------------------------------------
// Silero VAD
// ---------------------------------------------------------------------------

struct Vad {
    det: VoiceActivityDetector,
}

impl Vad {
    fn new(model: &Path) -> Result<Self> {
        let mut config = VadModelConfig::default();
        config.silero_vad = SileroVadModelConfig {
            model: Some(model.to_string_lossy().into_owned()),
            threshold: 0.5,
            min_speech_duration: 0.1,
            min_silence_duration: 0.2,
            window_size: 512,
            // 必须 > 0：为 0 时上游会恒定切到激进分支，人声几乎检测不到
            max_speech_duration: 60.0,
        };
        config.sample_rate = SAMPLE_RATE;
        config.num_threads = 1;
        config.provider = Some("cpu".into());
        let det = VoiceActivityDetector::create(&config, 60.0).context("创建 Silero VAD 失败")?;
        Ok(Self { det })
    }
    fn reset(&self) {
        self.det.reset();
    }
    fn push(&self, samples: &[f32]) -> bool {
        self.det.accept_waveform(samples);
        // 只用布尔判定，立即丢弃已结算段落，避免长录音时队列无限增长
        while !self.det.is_empty() {
            self.det.pop();
        }
        self.det.detected()
    }
    fn flush(&self) {
        self.det.flush();
    }
}

// ---------------------------------------------------------------------------
// Voice：ASR + 声纹 + 采集 + VAD 的统一持有者
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct ListenOut {
    pub text: String,
    pub text_norm: String,
    pub embedding: Vec<f32>,
    pub rms: f32,
    pub end_reason: String,
    pub duration: f32,
    pub sample_rate: i32,
}

/// 一段手动录音会话：`listen_begin` 启动后台采集任务，`listen_end` 置位停止
/// 标志并取回结果，`listen_cancel` 置位取消标志（跳过推理直接丢弃）。
struct RecordSession {
    stop: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    done: Option<oneshot::Receiver<Result<ListenOut>>>,
}

pub struct Voice {
    asr: Option<Arc<OfflineRecognizer>>,
    spk: Option<Arc<SpeakerEmbeddingExtractor>>,
    vad: Option<Arc<Vad>>,
    cap: Option<AudioCapture>,
    tx: broadcast::Sender<Vec<f32>>,
    alive: Arc<AtomicBool>,
    playback_active: AtomicBool,
    /// 同一时刻只允许一段手动录音会话。
    session: tokio::sync::Mutex<Option<RecordSession>>,
}

impl Voice {
    /// 加载模型并尝试建立常驻采集。模型缺失只降级对应能力，不 panic。
    pub fn new(root: &Path) -> Self {
        let (tx, _rx) = broadcast::channel::<Vec<f32>>(2048);
        let alive = Arc::new(AtomicBool::new(false));

        // FunASR Paraformer-zh（离线中文 ASR，单一 int8 onnx + tokens）。
        let asr_dir = root.join("models/asr-zh");
        let asr = (|| -> Result<OfflineRecognizer> {
            let mut config = OfflineRecognizerConfig::default();
            config.model_config.paraformer = OfflineParaformerModelConfig {
                model: Some(asr_dir.join("model.int8.onnx").to_string_lossy().into_owned()),
            };
            config.model_config.tokens = Some(asr_dir.join("tokens.txt").to_string_lossy().into_owned());
            config.model_config.num_threads = 4;
            config.model_config.provider = Some("cpu".into());
            config.decoding_method = Some("greedy_search".into());
            OfflineRecognizer::create(&config).ok_or_else(|| anyhow!("FunASR Paraformer 模型加载失败"))
        })()
        .map_err(|e| eprintln!("[voice] ASR 不可用: {e}"))
        .ok()
        .map(Arc::new);

        let spk = (|| -> Result<SpeakerEmbeddingExtractor> {
            let config = SpeakerEmbeddingExtractorConfig {
                model: Some(root.join("models/spk/sv.onnx").to_string_lossy().into_owned()),
                num_threads: 2,
                debug: false,
                provider: Some("cpu".into()),
            };
            SpeakerEmbeddingExtractor::create(&config).ok_or_else(|| anyhow!("声纹模型加载失败"))
        })()
        .map_err(|e| eprintln!("[voice] 声纹不可用: {e}"))
        .ok()
        .map(Arc::new);

        let vad = Vad::new(&root.join("models/silero-vad/silero_vad.onnx"))
            .map_err(|e| eprintln!("[voice] VAD 不可用: {e}"))
            .ok()
            .map(Arc::new);

        let cap = AudioCapture::new(alive.clone(), tx.clone())
            .map_err(|e| eprintln!("[voice] 采集不可用: {e}"))
            .ok();

        Self {
            asr,
            spk,
            vad,
            cap,
            tx,
            alive,
            playback_active: AtomicBool::new(false),
            session: tokio::sync::Mutex::new(None),
        }
    }

    /// 状态汇报：`(mic_alive, cap_ok, vad_ready, asr_ready, spk_ready)`。
    pub fn status(&self) -> (bool, bool, bool, bool, bool) {
        (
            self.alive.load(Ordering::SeqCst),
            self.cap.is_some(),
            self.vad.is_some(),
            self.asr.is_some(),
            self.spk.is_some(),
        )
    }

    /// 权限授予后重建采集（授权前 cpal 回调恒为 0）。
    pub fn reinit(&mut self) -> (bool, bool) {
        self.cap = None;
        match AudioCapture::new(self.alive.clone(), self.tx.clone()) {
            Ok(c) => {
                self.cap = Some(c);
                (self.alive.load(Ordering::SeqCst), true)
            }
            Err(e) => {
                eprintln!("[voice] 重建采集失败: {e}");
                (self.alive.load(Ordering::SeqCst), false)
            }
        }
    }

    /// 回声门：所有出声路径开始/结束时通知后端。
    pub fn set_playback(&self, active: bool) {
        self.playback_active.store(active, Ordering::SeqCst);
    }

    pub fn embedding_dim(&self) -> Option<usize> {
        self.spk.as_ref().map(|s| s.dim() as usize)
    }

    /// 回声门：播报结束后再等 400 ms 余音窗口。
    async fn gate_playback(&self, ignore_playback: bool) {
        if !ignore_playback {
            return;
        }
        let mut waited = 0.0f32;
        while self.playback_active.load(Ordering::SeqCst) && waited < 10.0 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            waited += 0.05;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }

    /// 录音前清缓冲、复位 VAD。
    fn prepare_capture(&self) {
        if let Some(c) = &self.cap {
            c.discard();
        }
        if let Some(v) = &self.vad {
            v.reset();
        }
    }

    /// 录一句（旧式自动结束）：VAD 静默结束 / 硬超时结束，带回声门。
    pub async fn listen_once(
        &self,
        max_secs: f32,
        silence_secs: f32,
        ignore_playback: bool,
    ) -> Result<ListenOut> {
        if self.cap.is_none() {
            bail!("麦克风不可用：请检查系统麦克风授权");
        }
        let max_secs = max_secs.clamp(2.0, 60.0);
        let silence_secs = silence_secs.max(1.0);
        self.gate_playback(ignore_playback).await;
        self.prepare_capture();
        run_capture(
            self.tx.clone(),
            self.asr.clone(),
            self.spk.clone(),
            self.vad.clone(),
            None,
            None,
            max_secs,
            silence_secs,
        )
        .await
    }

    /// 手动录音·开始：立即返回，采集在后台任务里进行，直到 `listen_end` /
    /// `listen_cancel` 或硬超时。不做静默自动结束。
    pub async fn listen_begin(&self, max_secs: f32, ignore_playback: bool) -> Result<()> {
        if self.cap.is_none() {
            bail!("麦克风不可用：请检查系统麦克风授权");
        }
        let mut guard = self.session.lock().await;
        if guard.is_some() {
            bail!("录音已在进行中");
        }
        let max_secs = max_secs.clamp(2.0, 60.0);
        self.gate_playback(ignore_playback).await;
        self.prepare_capture();

        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let (out_tx, out_rx) = oneshot::channel();
        {
            let tx = self.tx.clone();
            let asr = self.asr.clone();
            let spk = self.spk.clone();
            let vad = self.vad.clone();
            let stop_task = stop.clone();
            let cancel_task = cancel.clone();
            tokio::spawn(async move {
                let result = run_capture(
                    tx,
                    asr,
                    spk,
                    vad,
                    Some(stop_task),
                    Some(cancel_task),
                    max_secs,
                    max_secs,
                )
                .await;
                // 接收端已被取消（listen_cancel）时 send 失败，直接丢弃结果。
                let _ = out_tx.send(result);
            });
        }
        *guard = Some(RecordSession {
            stop,
            cancel,
            done: Some(out_rx),
        });
        Ok(())
    }

    /// 手动录音·结束：停止采集，跑 ASR / 声纹推理并返回整句结果。
    pub async fn listen_end(&self) -> Result<ListenOut> {
        let session = self.session.lock().await.take();
        let mut session = session.ok_or_else(|| anyhow!("没有进行中的录音"))?;
        session.stop.store(true, Ordering::SeqCst);
        let rx = session.done.take().unwrap();
        rx.await.map_err(|_| anyhow!("录音任务中断"))?
    }

    /// 手动录音·取消：停止采集并丢弃整句（不做推理），用于返回 / 退出。
    pub async fn listen_cancel(&self) -> Result<()> {
        let session = self.session.lock().await.take();
        if let Some(session) = session {
            session.cancel.store(true, Ordering::SeqCst);
            session.stop.store(true, Ordering::SeqCst);
            // 不 await 结果：任务检测到 cancel 后自行空转结束。
        }
        Ok(())
    }
}

/// 采集 + 推理主循环。
///
/// * `stop = None`：旧式自动结束（静默 `silence_secs` / 无人声 8 s）。
/// * `stop = Some`：手动模式，只在停止标志置位或硬超时结束，忽略静默。
/// * `cancel = Some` 且被置位时，循环结束后直接返回空结果（跳过 ASR / 声纹）。
#[allow(clippy::too_many_arguments)]
async fn run_capture(
    tx: broadcast::Sender<Vec<f32>>,
    asr: Option<Arc<OfflineRecognizer>>,
    spk: Option<Arc<SpeakerEmbeddingExtractor>>,
    vad: Option<Arc<Vad>>,
    stop: Option<Arc<AtomicBool>>,
    cancel: Option<Arc<AtomicBool>>,
    max_secs: f32,
    silence_secs: f32,
) -> Result<ListenOut> {
    let manual = stop.is_some();
    let mut rx = tx.subscribe();
    while rx.try_recv().is_ok() {} // 丢掉订阅前的积压

    let t0 = Instant::now();
    let mut buf: Vec<f32> = Vec::with_capacity(SAMPLE_RATE as usize * 8);
    let mut last_voice = 0.0f32;
    let mut ever_voice = false;
    let mut end_reason = "timeout";
    let peak_abs = Arc::new(Mutex::new(0.0f32));

    loop {
        let now = t0.elapsed().as_secs_f32();
        if now >= max_secs {
            if let Some(v) = &vad {
                v.flush();
            }
            end_reason = "timeout";
            break;
        }
        if let Some(flag) = &stop {
            if flag.load(Ordering::SeqCst) {
                if let Some(v) = &vad {
                    v.flush();
                }
                end_reason = "manual";
                break;
            }
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(chunk)) => {
                if let Some(m) = chunk.iter().fold(None, |acc: Option<f32>, s| {
                    let a = s.abs();
                    Some(match acc {
                        Some(v) => v.max(a),
                        None => a,
                    })
                }) {
                    let mut p = peak_abs.lock().unwrap();
                    if m > *p {
                        *p = m;
                    }
                }
                let det = match &vad {
                    Some(v) => v.push(&chunk),
                    None => chunk.iter().any(|s| s.abs() > 0.008),
                };
                if det {
                    ever_voice = true;
                    last_voice = t0.elapsed().as_secs_f32();
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                eprintln!("[voice] 音频订阅落后，丢弃 {n} 块");
                continue;
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                end_reason = "capture_closed";
                break;
            }
            Err(_) => {
                if manual {
                    continue; // 手动模式：静默不结束，只靠停止标志 / 硬超时
                }
                // 100 ms 内没有新块：走静默/无人声判定
                let now = t0.elapsed().as_secs_f32();
                if ever_voice && now - last_voice >= silence_secs {
                    if let Some(v) = &vad {
                        v.flush();
                    }
                    end_reason = "silence";
                    break;
                }
                if !ever_voice && now >= NO_SPEECH_LIMIT_SECS {
                    end_reason = "no_speech";
                    break;
                }
            }
        }
    }
    let duration = t0.elapsed().as_secs_f32();
    let _ = peak_abs;

    // 用户取消：不做任何推理，直接丢弃整句。
    if cancel.map(|c| c.load(Ordering::SeqCst)).unwrap_or(false) {
        return Ok(ListenOut {
            text: String::new(),
            text_norm: String::new(),
            embedding: Vec::new(),
            rms: 0.0,
            end_reason: "cancelled".to_string(),
            duration,
            sample_rate: SAMPLE_RATE,
        });
    }

    if !ever_voice || end_reason == "no_speech" {
        return Ok(ListenOut {
            text: String::new(),
            text_norm: String::new(),
            embedding: Vec::new(),
            rms: 0.0,
            end_reason: end_reason.to_string(),
            duration,
            sample_rate: SAMPLE_RATE,
        });
    }

    // 按 20 ms 窗口的 RMS 掐掉首尾静音（给 ASR 与声纹都更干净的输入）
    let (s, e) = trim_silence(&buf);
    let speech = &buf[s..e];
    let voiced_secs = speech.len() as f32 / SAMPLE_RATE as f32;
    if voiced_secs < MIN_SPEECH_SECS {
        return Ok(ListenOut {
            text: String::new(),
            text_norm: String::new(),
            embedding: Vec::new(),
            rms: rms_of(speech),
            end_reason: "too_short".to_string(),
            duration,
            sample_rate: SAMPLE_RATE,
        });
    }

    let audio: Vec<f32> = speech.to_vec();
    let rms = rms_of(&audio);
    let (text, embedding) = tokio::task::spawn_blocking(move || {
        let text = match &asr {
            Some(rec) => {
                let stream = rec.create_stream();
                stream.accept_waveform(SAMPLE_RATE, &audio);
                rec.decode(&stream);
                stream.get_result().map(|r| r.text).unwrap_or_default()
            }
            None => String::new(),
        };
        let embedding = match &spk {
            Some(ex) => extract_embedding(ex, &audio).unwrap_or_default(),
            None => Vec::new(),
        };
        (text, embedding)
    })
    .await
    .map_err(|e| anyhow!("推理任务失败: {e}"))?;

    Ok(ListenOut {
        text_norm: crate::crypto::normalize_passphrase(&text),
        text,
        embedding,
        rms,
        end_reason: end_reason.to_string(),
        duration,
        sample_rate: SAMPLE_RATE,
    })
}

/// 声纹 embedding：Silero/ERes2Net 要求 ≥ 约 1 s 音频，太短会 `is_ready()==false`。
fn extract_embedding(ex: &SpeakerEmbeddingExtractor, audio: &[f32]) -> Option<Vec<f32>> {
    let stream = ex.create_stream()?;
    stream.accept_waveform(SAMPLE_RATE, audio);
    if !ex.is_ready(&stream) {
        return None;
    }
    ex.compute(&stream)
}

fn rms_of(s: &[f32]) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let sum: f64 = s.iter().map(|x| (*x as f64) * (*x as f64)).sum();
    (sum / s.len() as f64).sqrt() as f32
}

/// 掐掉首尾静音，返回 `(start, end)`。
fn trim_silence(s: &[f32]) -> (usize, usize) {
    const WIN: usize = 320; // 20 ms
    if s.len() <= WIN {
        return (0, s.len());
    }
    let n = s.len() / WIN;
    let mut rms = Vec::with_capacity(n);
    for i in 0..n {
        rms.push(rms_of(&s[i * WIN..(i + 1) * WIN]));
    }
    let peak = rms.iter().cloned().fold(0.0f32, f32::max);
    let thr = (peak * 0.12).max(0.004);
    let start = rms.iter().position(|r| *r > thr).unwrap_or(0);
    let end = rms.iter().rposition(|r| *r > thr).unwrap_or(n - 1);
    let pad = (SAMPLE_RATE as usize / 10).max(WIN); // 前后各留 100 ms
    let s0 = start.saturating_mul(WIN).saturating_sub(pad);
    let e0 = ((end + 1) * WIN + pad).min(s.len());
    (s0, e0)
}

/// 模型根目录（`--root` / `STAR_TREK_ROOT`）。
pub fn models_root(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Ok(p) = std::env::var("STAR_TREK_ROOT") {
        return PathBuf::from(p);
    }
    PathBuf::from("resources")
}
