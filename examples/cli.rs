/// CLI VoIP client example.
///
/// Uses the voip_client library with cpal audio I/O.
/// Captures microphone and plays speaker audio, resampling between
/// device native rate and 16kHz.

use std::cmp::Ordering as CmpOrdering;

use anyhow::{anyhow, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;

use voip_client::resample::{LinearResampler, ResampleBuffer, FRAME_SAMPLES, INTERNAL_RATE};
use voip_client::{SipClient, Transport, VoipCommand, VoipConfig, VoipEvent};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("voip_client=info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: cli <server:port> <username> <password> [realm] [--tls] [--stun <server:port>]");
        eprintln!("Example: cli 192.168.1.100:5060 alice secret123 voip.local");
        eprintln!("Example: cli sip.example.com:5061 alice secret123 sip.example.com --tls");
        eprintln!("Example: cli sip.example.com:5061 alice secret123 --tls --stun stun.l.google.com:19302");
        std::process::exit(1);
    }

    // Check for --tls flag anywhere in args
    let use_tls = args.iter().any(|a| a == "--tls");
    let transport = if use_tls { Transport::Tls } else { Transport::Udp };

    // Check for --stun option
    let stun_server = args.iter().position(|a| a == "--stun")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| Some("stun.l.google.com:19302".to_string()));

    // Filter out flags and their arguments for positional args
    let mut positional = Vec::new();
    let mut skip_next = false;
    for arg in args.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--stun" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--") {
            continue;
        }
        positional.push(arg);
    }

    // Resolve hostname:port to SocketAddr (supports both IP and hostname)
    let server_str = positional[0].as_str();
    let server_addr = tokio::net::lookup_host(server_str)
        .await
        .map_err(|e| anyhow!("cannot resolve '{}': {e}", server_str))?
        .next()
        .ok_or_else(|| anyhow!("no addresses found for '{}'", server_str))?;

    // Extract hostname for TLS SNI (strip :port)
    let hostname = server_str.rsplit_once(':').map(|(h, _)| h).unwrap_or(server_str);

    let username = positional[1].to_string();
    let password = positional[2].to_string();
    let realm = if positional.len() > 3 {
        positional[3].to_string()
    } else {
        hostname.to_string()
    };

    println!("VoIP Client starting...");
    println!("Server: {} -> {server_addr} ({transport:?})", server_str);
    println!("User: {username}@{realm}");
    if let Some(ref stun) = stun_server {
        println!("STUN: {stun}");
    }
    println!();
    println!("Commands: call <uri>, answer, hangup, hold, unhold, transfer <uri>, dtmf <digit>, quit");
    println!();

    let (cmd_tx, cmd_rx) = mpsc::channel::<VoipCommand>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<VoipEvent>(16);

    // Spawn stdin reader
    tokio::spawn(async move {
        read_stdin(cmd_tx).await;
    });

    // Spawn SIP client in a background task (fully Send-safe)
    let config = VoipConfig {
        server_addr,
        username,
        password,
        realm,
        transport,
        hostname: hostname.to_string(),
        stun_server,
        io_sample_rate: voip_client::INTERNAL_RATE,
        io_frame_ms: 20,
    };
    tokio::spawn(async move {
        let mut client = match SipClient::new(config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to create SIP client: {e}");
                return;
            }
        };
        if let Err(e) = client.run(cmd_rx, event_tx).await {
            eprintln!("SIP client error: {e}");
        }
    });

    // Run event handler on the main task (cpal streams are not Send).
    // _active_streams keeps cpal streams alive; dropped on CallEnded.
    let mut _active_streams: Option<CpalStreams> = None;

    while let Some(event) = event_rx.recv().await {
        match event {
            VoipEvent::Registered => {
                println!("Registered successfully.");
            }
            VoipEvent::RegistrationFailed(reason) => {
                println!("Registration failed: {reason}");
            }
            VoipEvent::IncomingCall { from } => {
                println!("Incoming call from {from}");
                println!("Type 'answer' to accept or 'hangup' to decline.");
            }
            VoipEvent::Ringing => {
                println!("Ringing...");
            }
            VoipEvent::CallConnected { audio_tx, audio_rx } => {
                println!("Call connected.");
                match start_cpal_audio(audio_tx, audio_rx) {
                    Ok(streams) => {
                        _active_streams = Some(streams);
                    }
                    Err(e) => {
                        eprintln!("Failed to start audio: {e}");
                    }
                }
            }
            VoipEvent::CallEnded => {
                println!("Call ended.");
                _active_streams = None;
            }
            VoipEvent::CallFailed { reason } => {
                println!("Call failed: {reason}");
                _active_streams = None;
            }
            VoipEvent::DtmfReceived(ch) => {
                println!("DTMF received: {ch}");
            }
            VoipEvent::CallHeld => {
                println!("Call on hold.");
            }
            VoipEvent::CallResumed => {
                println!("Call resumed.");
            }
            VoipEvent::TransferResult { success, reason } => {
                if success {
                    println!("Transfer succeeded: {reason}");
                } else {
                    println!("Transfer failed: {reason}");
                }
            }
        }
    }

    Ok(())
}

async fn read_stdin(cmd_tx: mpsc::Sender<VoipCommand>) {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);

    use tokio::io::AsyncBufReadExt;
    let mut lines = reader.lines();

    loop {
        print!("> ");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }

                let cmd = if line.starts_with("call ") {
                    let target = line[5..].trim().to_string();
                    if target.is_empty() {
                        println!("Usage: call <sip:user@host>");
                        continue;
                    }
                    VoipCommand::Call(target)
                } else if line == "answer" || line == "a" {
                    VoipCommand::Answer
                } else if line == "hangup" || line == "h" || line == "bye" {
                    VoipCommand::Hangup
                } else if line.starts_with("dtmf ") {
                    let digit = line[5..].trim();
                    if digit.len() == 1 {
                        let ch = digit.chars().next().unwrap();
                        if "0123456789*#ABCD".contains(ch) {
                            VoipCommand::SendDtmf(ch)
                        } else {
                            println!("Invalid DTMF digit: {ch}. Valid: 0-9, *, #, A-D");
                            continue;
                        }
                    } else {
                        println!("Usage: dtmf <digit>");
                        continue;
                    }
                } else if line == "hold" {
                    VoipCommand::Hold
                } else if line == "unhold" || line == "resume" {
                    VoipCommand::Unhold
                } else if line.starts_with("transfer ") || line.starts_with("xfer ") {
                    let target = line.splitn(2, ' ').nth(1).unwrap_or("").trim().to_string();
                    if target.is_empty() {
                        println!("Usage: transfer <uri>");
                        continue;
                    }
                    VoipCommand::Transfer(target)
                } else if line == "quit" || line == "q" || line == "exit" {
                    let _ = cmd_tx.send(VoipCommand::Quit).await;
                    break;
                } else {
                    println!("Unknown command: {line}");
                    println!("Commands: call <uri>, answer, hangup, hold, unhold, transfer <uri>, dtmf <digit>, quit");
                    continue;
                };

                if cmd_tx.send(cmd).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!("stdin error: {e}");
                break;
            }
        }
    }
}

// ─── CPAL Audio ──────────────────────────────────────────────────────────────

/// Holds CPAL streams alive. Drop to stop audio.
struct CpalStreams {
    _streams: Vec<cpal::Stream>,
}

/// Start CPAL audio capture and playback, bridging to the library's channels.
fn start_cpal_audio(
    mic_tx: mpsc::Sender<Vec<f32>>,
    spk_rx: mpsc::Receiver<Vec<f32>>,
) -> Result<CpalStreams> {
    let host = cpal::default_host();

    let input_device = host
        .default_input_device()
        .ok_or_else(|| anyhow!("no input audio device"))?;
    let output_device = host
        .default_output_device()
        .ok_or_else(|| anyhow!("no output audio device"))?;

    tracing::info!(
        "Audio input: {}, output: {}",
        input_device.name().unwrap_or_default(),
        output_device.name().unwrap_or_default()
    );

    let input_stream = build_input_stream(&input_device, mic_tx)?;
    let output_stream = build_output_stream(&output_device, spk_rx)?;

    input_stream.play()?;
    output_stream.play()?;

    Ok(CpalStreams {
        _streams: vec![input_stream, output_stream],
    })
}

// ─── Input stream ───────────────────────────────────────────────────────────

fn build_input_stream(
    device: &cpal::Device,
    mic_tx: mpsc::Sender<Vec<f32>>,
) -> Result<cpal::Stream> {
    let fmt = choose_best_format(device.supported_input_configs()?, true)
        .ok_or_else(|| anyhow!("no supported input format"))?;

    let config = cpal::StreamConfig {
        channels: fmt.channels,
        sample_rate: cpal::SampleRate(fmt.sample_rate),
        buffer_size: cpal::BufferSize::Default,
    };

    tracing::info!(
        "Input: {}Hz {}ch {:?}",
        fmt.sample_rate,
        fmt.channels,
        fmt.sample_format
    );

    let err_fn = |err| tracing::error!("input stream error: {err}");

    let channels = fmt.channels as usize;
    let mut resampler = LinearResampler::new(fmt.sample_rate, INTERNAL_RATE);
    let mut mono_buf = Vec::new();
    let mut resampled = Vec::new();
    let mut accumulator = ResampleBuffer::new(INTERNAL_RATE as usize); // 1 second buffer

    let stream = match fmt.sample_format {
        cpal::SampleFormat::F32 => device.build_input_stream(
            &config,
            move |data: &[f32], _| {
                downmix_f32(data, channels, &mut mono_buf);
                resampler.process(&mono_buf, &mut resampled);
                push_frames(&resampled, &mut accumulator, &mic_tx);
            },
            err_fn,
            None,
        )?,
        cpal::SampleFormat::I16 => device.build_input_stream(
            &config,
            move |data: &[i16], _| {
                downmix_i16(data, channels, &mut mono_buf);
                resampler.process(&mono_buf, &mut resampled);
                push_frames(&resampled, &mut accumulator, &mic_tx);
            },
            err_fn,
            None,
        )?,
        _ => return Err(anyhow!("unsupported input format: {:?}", fmt.sample_format)),
    };

    Ok(stream)
}

fn push_frames(
    samples: &[f32],
    accumulator: &mut ResampleBuffer,
    tx: &mpsc::Sender<Vec<f32>>,
) {
    accumulator.push(samples);
    let mut frame = vec![0.0f32; FRAME_SAMPLES];
    while accumulator.pop_exact(&mut frame) {
        let _ = tx.try_send(frame.clone());
    }
}

// ─── Output stream ──────────────────────────────────────────────────────────

fn build_output_stream(
    device: &cpal::Device,
    mut spk_rx: mpsc::Receiver<Vec<f32>>,
) -> Result<cpal::Stream> {
    let fmt = choose_best_format(device.supported_output_configs()?, false)
        .ok_or_else(|| anyhow!("no supported output format"))?;

    let config = cpal::StreamConfig {
        channels: fmt.channels,
        sample_rate: cpal::SampleRate(fmt.sample_rate),
        buffer_size: cpal::BufferSize::Default,
    };

    tracing::info!(
        "Output: {}Hz {}ch {:?}",
        fmt.sample_rate,
        fmt.channels,
        fmt.sample_format
    );

    let err_fn = |err| tracing::error!("output stream error: {err}");

    let channels = fmt.channels as usize;
    let mut resampler = LinearResampler::new(INTERNAL_RATE, fmt.sample_rate);
    let mut resampled = Vec::new();
    let mut device_buf = ResampleBuffer::new(fmt.sample_rate as usize); // 1 second buffer
    let mut frame_buf = Vec::new();

    let stream = match fmt.sample_format {
        cpal::SampleFormat::F32 => device.build_output_stream(
            &config,
            move |out: &mut [f32], _| {
                let frames_needed = out.len() / channels;
                fill_output_buf(
                    &mut spk_rx,
                    &mut resampler,
                    &mut resampled,
                    &mut device_buf,
                    &mut frame_buf,
                    frames_needed,
                );
                write_interleaved_f32(&frame_buf, channels, out);
            },
            err_fn,
            None,
        )?,
        cpal::SampleFormat::I16 => device.build_output_stream(
            &config,
            move |out: &mut [i16], _| {
                let frames_needed = out.len() / channels;
                fill_output_buf(
                    &mut spk_rx,
                    &mut resampler,
                    &mut resampled,
                    &mut device_buf,
                    &mut frame_buf,
                    frames_needed,
                );
                write_interleaved_i16(&frame_buf, channels, out);
            },
            err_fn,
            None,
        )?,
        _ => return Err(anyhow!("unsupported output format: {:?}", fmt.sample_format)),
    };

    Ok(stream)
}

fn fill_output_buf(
    spk_rx: &mut mpsc::Receiver<Vec<f32>>,
    resampler: &mut LinearResampler,
    resampled: &mut Vec<f32>,
    device_buf: &mut ResampleBuffer,
    frame_buf: &mut Vec<f32>,
    frames_needed: usize,
) {
    while device_buf.len() < frames_needed {
        match spk_rx.try_recv() {
            Ok(frame) => {
                resampler.process(&frame, resampled);
                device_buf.push(resampled);
            }
            Err(_) => {
                // No data available, push silence
                let silence = vec![0.0f32; FRAME_SAMPLES];
                resampler.process(&silence, resampled);
                device_buf.push(resampled);
            }
        }
    }

    frame_buf.clear();
    frame_buf.resize(frames_needed, 0.0);
    let _ = device_buf.pop_exact(frame_buf);
}

fn write_interleaved_f32(mono: &[f32], channels: usize, out: &mut [f32]) {
    for (i, &s) in mono.iter().enumerate() {
        let base = i * channels;
        for ch in 0..channels {
            if base + ch < out.len() {
                out[base + ch] = s;
            }
        }
    }
    let filled = mono.len() * channels;
    for s in out.iter_mut().skip(filled) {
        *s = 0.0;
    }
}

fn write_interleaved_i16(mono: &[f32], channels: usize, out: &mut [i16]) {
    for (i, &s) in mono.iter().enumerate() {
        let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        let base = i * channels;
        for ch in 0..channels {
            if base + ch < out.len() {
                out[base + ch] = v;
            }
        }
    }
    let filled = mono.len() * channels;
    for s in out.iter_mut().skip(filled) {
        *s = 0;
    }
}

// ─── Downmix ────────────────────────────────────────────────────────────────

fn downmix_f32(data: &[f32], channels: usize, out: &mut Vec<f32>) {
    out.clear();
    if channels <= 1 {
        out.extend_from_slice(data);
        return;
    }
    for frame in data.chunks(channels) {
        out.push(frame[0]);
    }
}

fn downmix_i16(data: &[i16], channels: usize, out: &mut Vec<f32>) {
    out.clear();
    if channels <= 1 {
        out.extend(data.iter().map(|&v| v as f32 / i16::MAX as f32));
        return;
    }
    for frame in data.chunks(channels) {
        out.push(frame[0] as f32 / i16::MAX as f32);
    }
}

// ─── Format selection ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct StreamFormat {
    channels: u16,
    sample_rate: u32,
    sample_format: cpal::SampleFormat,
}

fn choose_best_format(
    supported: impl Iterator<Item = cpal::SupportedStreamConfigRange>,
    prefer_mono: bool,
) -> Option<StreamFormat> {
    let mut best: Option<StreamFormat> = None;

    for cfg in supported {
        let channels = cfg.channels();
        let fmt = cfg.sample_format();
        let min = cfg.min_sample_rate().0;
        let max = cfg.max_sample_rate().0;

        let rate = if INTERNAL_RATE >= min && INTERNAL_RATE <= max {
            INTERNAL_RATE
        } else if max < INTERNAL_RATE {
            max
        } else {
            min
        };

        let candidate = StreamFormat {
            channels,
            sample_rate: rate,
            sample_format: fmt,
        };

        best = Some(match best {
            None => candidate,
            Some(cur) => {
                if format_score(candidate, prefer_mono) > format_score(cur, prefer_mono) {
                    candidate
                } else {
                    cur
                }
            }
        });
    }

    best
}

fn format_score(fmt: StreamFormat, prefer_mono: bool) -> i64 {
    let mut score = 0i64;

    if prefer_mono {
        score += if fmt.channels == 1 { 200 } else { 50 };
    } else {
        score += if fmt.channels <= 2 { 100 } else { 50 };
    }

    score += match fmt.sample_format {
        cpal::SampleFormat::F32 => 100,
        cpal::SampleFormat::I16 => 60,
        _ => 0,
    };

    score += match fmt.sample_rate.cmp(&INTERNAL_RATE) {
        CmpOrdering::Equal => 150,
        CmpOrdering::Greater => 30,
        CmpOrdering::Less => 10,
    };

    score
}
