//! Standalone voiceprint probe — TEST ONLY, does not touch main code.
//!
//! Reuses the exact model (`resources/models/spk/sv.onnx`) and the exact
//! similarity math (`vault::max_similarity`'s inner cosine, f64 accumulate)
//! that the app uses, so the numbers here reflect the real matcher.
//!
//! Input: 16 kHz / mono / raw little-endian f32 PCM files (produced from EDGE
//! TTS mp3 via `ffmpeg -ar 16000 -ac 1 -f f32le`).
//!
//! Usage:
//!   cargo run --release --example spk_probe -- <model.onnx> <a.f32> [b.f32 ...]
//!
//! Speaker grouping for the summary is inferred from the first character of
//! each file name (e.g. `A1.f32`, `A2.f32` = speaker A; `B1.f32` = speaker B).

use sherpa_onnx::{SpeakerEmbeddingExtractor, SpeakerEmbeddingExtractorConfig};
use std::path::Path;

const SAMPLE_RATE: i32 = 16000;
/// App default similarity threshold (main.rs DEFAULT_THRESHOLD_MILLI = 650).
const THRESHOLD: f32 = 0.65;

fn read_f32le(path: &str) -> Vec<f32> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let n = bytes.len() / 4;
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let o = i * 4;
        v.push(f32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]));
    }
    v
}

fn embedding(ex: &SpeakerEmbeddingExtractor, audio: &[f32]) -> Option<Vec<f32>> {
    let stream = ex.create_stream()?;
    stream.accept_waveform(SAMPLE_RATE, audio);
    if !ex.is_ready(&stream) {
        return None;
    }
    ex.compute(&stream)
}

/// Cosine similarity, identical math to vault::max_similarity.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0f64;
    let mut na = 0f64;
    let mut nb = 0f64;
    for i in 0..a.len() {
        dot += (a[i] as f64) * (b[i] as f64);
        na += (a[i] as f64) * (a[i] as f64);
        nb += (b[i] as f64) * (b[i] as f64);
    }
    if na <= 0.0 || nb <= 0.0 {
        return 0.0;
    }
    (dot / (na.sqrt() * nb.sqrt())) as f32
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        format!("{s:>width$}", width = n)
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: spk_probe <model.onnx> <a.f32> [b.f32 ...]");
        std::process::exit(2);
    }
    let model = &args[1];
    let files = &args[2..];

    let config = SpeakerEmbeddingExtractorConfig {
        model: Some(model.clone()),
        num_threads: 2,
        debug: false,
        provider: Some("cpu".into()),
    };
    let ex = SpeakerEmbeddingExtractor::create(&config)
        .unwrap_or_else(|| panic!("failed to load speaker model: {model}"));
    let dim = ex.dim() as usize;
    println!("model        : {model}");
    println!("embedding dim: {dim}");
    println!("sample rate  : {SAMPLE_RATE}");
    println!("threshold    : {THRESHOLD:.4}\n");

    let mut names: Vec<String> = Vec::new();
    let mut embs: Vec<Option<Vec<f32>>> = Vec::new();
    for f in files {
        let label = Path::new(f)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| f.clone());
        let audio = read_f32le(f);
        let dur = audio.len() as f32 / SAMPLE_RATE as f32;
        let e = embedding(&ex, &audio);
        match &e {
            Some(v) => println!("[{label}] {dur:>5.2}s -> embedding OK (len {})", v.len()),
            None => println!("[{label}] {dur:>5.2}s -> NOT READY (too short) - excluded"),
        }
        names.push(label);
        embs.push(e);
    }

    println!("\n=== cosine similarity matrix ===");
    print!("{:>12} ", "");
    for n in &names {
        print!("{}", trunc(n, 10));
    }
    println!();
    for i in 0..names.len() {
        print!("{} ", trunc(&names[i], 11));
        for j in 0..names.len() {
            match (&embs[i], &embs[j]) {
                (Some(a), Some(b)) => print!("{:>10.4}", cosine(a, b)),
                _ => print!("{:>10}", "-"),
            }
        }
        println!();
    }

    // Group pairs: same speaker (same first char) vs different speaker.
    let mut same: Vec<f32> = Vec::new();
    let mut cross: Vec<f32> = Vec::new();
    for i in 0..names.len() {
        for j in (i + 1)..names.len() {
            if let (Some(a), Some(b)) = (&embs[i], &embs[j]) {
                let c = cosine(a, b);
                let si = names[i].chars().next().unwrap_or('?');
                let sj = names[j].chars().next().unwrap_or('?');
                if si == sj {
                    same.push(c);
                } else {
                    cross.push(c);
                }
            }
        }
    }
    let avg = |v: &[f32]| if v.is_empty() { f32::NAN } else { v.iter().sum::<f32>() / v.len() as f32 };
    let min = |v: &[f32]| v.iter().cloned().fold(f32::INFINITY, f32::min);
    let max = |v: &[f32]| v.iter().cloned().fold(f32::NEG_INFINITY, f32::max);

    println!("\n=== summary ===");
    println!("same-speaker  pairs: n={}  avg={:.4}  min={:.4}", same.len(), avg(&same), min(&same));
    println!("cross-speaker pairs: n={}  avg={:.4}  max={:.4}", cross.len(), avg(&cross), max(&cross));

    let ok = !same.is_empty() && !cross.is_empty() && min(&same) > THRESHOLD && max(&cross) < THRESHOLD;
    println!(
        "\nverdict @ threshold {THRESHOLD:.4}: {}",
        if ok {
            "SEPARABLE - same-speaker always above, cross-speaker always below"
        } else {
            "OVERLAP - some pairs on the wrong side of the threshold"
        }
    );
}
