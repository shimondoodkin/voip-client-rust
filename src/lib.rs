//! # voip_client
//!
//! A SIP/RTP VoIP library with no audio hardware dependency.
//!
//! This library handles the SIP signaling protocol, RTP media transport,
//! codec encoding/decoding (Opus, G.722, G.711), SRTP encryption, DTMF,
//! NAT traversal (STUN + UPnP), and jitter buffering. Audio I/O is left
//! to the consumer via `mpsc` channels, making the library usable on any
//! platform (desktop, Android, embedded) and in any pipeline.
//!
//! ## Architecture
//!
//! The library communicates through two channel pairs:
//!
//! - **Commands** (`VoipCommand`): the consumer sends commands to the library
//!   (dial, answer, hangup, send DTMF, quit).
//! - **Events** (`VoipEvent`): the library emits events back to the consumer
//!   (registered, incoming call, call connected with audio channels, call ended, etc.).
//!
//! When a call connects, `VoipEvent::CallConnected` delivers a pair of audio
//! channels. The consumer writes mono `f32` microphone frames to `audio_tx`
//! and reads mono `f32` speaker frames from `audio_rx`. The sample rate of
//! these channels is set by `VoipConfig::io_sample_rate` (default 16 kHz;
//! set to 48000 for a 48 kHz pipeline). The library resamples internally.
//! When the call ends, the channels are dropped and `VoipEvent::CallEnded`
//! is emitted.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use tokio::sync::mpsc;
//! use voip_client::{SipClient, VoipCommand, VoipConfig, VoipEvent, Transport};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = VoipConfig {
//!         server_addr: "192.168.1.100:5060".parse::<SocketAddr>()?,
//!         username: "alice".into(),
//!         password: "secret".into(),
//!         realm: "voip.local".into(),
//!         transport: Transport::Udp,
//!         hostname: "192.168.1.100".into(),
//!         stun_server: Some("stun.l.google.com:19302".into()),
//!         io_sample_rate: 16000, // or 48000 for a 48 kHz pipeline
//!         io_frame_ms: 20,      // or 10 for 10 ms frames
//!     };
//!
//!     let (cmd_tx, cmd_rx) = mpsc::channel::<VoipCommand>(16);
//!     let (event_tx, mut event_rx) = mpsc::channel::<VoipEvent>(16);
//!
//!     // Spawn the SIP client
//!     let mut client = SipClient::new(config).await?;
//!     tokio::spawn(async move {
//!         client.run(cmd_rx, event_tx).await.ok();
//!     });
//!
//!     // Handle events
//!     while let Some(event) = event_rx.recv().await {
//!         match event {
//!             VoipEvent::Registered => {
//!                 // Ready to make/receive calls
//!                 cmd_tx.send(VoipCommand::Call("1001".into())).await?;
//!             }
//!             VoipEvent::CallConnected { audio_tx, audio_rx } => {
//!                 // Bridge audio_tx/audio_rx to your audio source/sink.
//!                 // Frame size = io_sample_rate * io_frame_ms / 1000 samples.
//!                 // (e.g. 320 at 16 kHz / 20 ms, 160 at 16 kHz / 10 ms)
//!             }
//!             VoipEvent::CallEnded => break,
//!             _ => {}
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Supported codecs
//!
//! | Codec | Payload type | Clock rate | Audio rate | Quality |
//! |-------|-------------|------------|------------|---------|
//! | Opus  | 111         | 48 kHz     | 16 kHz     | Best    |
//! | G.722 | 9           | 8 kHz*     | 16 kHz     | Good    |
//! | PCMU  | 0           | 8 kHz      | 8 kHz      | Basic   |
//! | PCMA  | 8           | 8 kHz      | 8 kHz      | Basic   |
//!
//! *G.722 uses 8 kHz in RTP per RFC 3551 despite being a 16 kHz codec.
//!
//! The library always works at 16 kHz internally. For G.711 codecs, the RTP
//! layer handles 16 kHz <-> 8 kHz resampling transparently.
//!
//! ## Audio format
//!
//! All audio exchanged through the channels is:
//! - **Sample rate**: set by `VoipConfig::io_sample_rate` (default 16 kHz)
//! - **Channels**: mono (1 channel)
//! - **Format**: `f32` samples in the range `[-1.0, 1.0]`
//! - **Frame size**: `io_sample_rate * io_frame_ms / 1000` samples (e.g. 160 at 16 kHz/10 ms, 960 at 48 kHz/20 ms)
//!
//! ## Features
//!
//! - SIP over UDP and TLS (with automatic reconnection)
//! - Digest authentication (RFC 2617)
//! - Session timers with re-INVITE keepalive (RFC 4028)
//! - Reliable provisional responses / PRACK (RFC 3262)
//! - Call transfer: blind (REFER, RFC 3515) and attended (REFER with Replaces)
//! - Hold / unhold via re-INVITE with SDP direction attributes (RFC 3264)
//! - DNS SRV lookup for SIP server discovery (RFC 3263)
//! - RTP with adaptive jitter buffer
//! - DTMF send and receive (RFC 4733 telephone-event)
//! - SRTP AES-128-CM + HMAC-SHA1-80 (RFC 3711)
//! - NAT traversal: UPnP-IGD port mapping + STUN discovery
//! - Codec negotiation via SDP offer/answer
//!
//! ## Example
//!
//! See `examples/cli.rs` for a full CLI client using cpal for audio I/O.
//! Run it with:
//!
//! ```sh
//! cargo run --example cli -- sip.example.com:5061 alice secret realm --tls
//! ```

pub mod codec;
pub mod dns;
pub mod jitter;
pub mod nat;
pub mod resample;
pub mod rtp;
pub mod sdp;
pub mod sip;
pub mod srtp;
pub mod stun;

pub use codec::Codec;
pub use resample::{FRAME_SAMPLES, INTERNAL_RATE};
pub use sip::{SipClient, Transport, VoipCommand, VoipConfig, VoipEvent};
