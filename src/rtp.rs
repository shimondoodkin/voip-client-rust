/// RTP transport over UDP.
///
/// Handles packetization of audio frames into RTP packets and vice versa.
/// Bridges audio channels (16kHz) to network, with 16kHz↔8kHz resampling
/// for G.711 codecs. Includes jitter buffer, DTMF, and optional SRTP.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::resample::{LinearResampler, FRAME_SAMPLES};
use crate::codec::{self, Codec, CodecState};
use crate::jitter::JitterBuffer;
use crate::sip::VoipEvent;
use crate::srtp::SrtpContext;

/// RTP header size.
const RTP_HEADER_SIZE: usize = 12;
/// RTP version.
const RTP_VERSION: u8 = 2;
/// DTMF event payload type (RFC 4733).
const DTMF_PAYLOAD_TYPE: u8 = 101;

/// Start an RTP media session.
///
/// If `srtp_send` and `srtp_recv` are provided, all outgoing packets are
/// encrypted and all incoming packets are decrypted using SRTP (RFC 3711).
///
/// Returns the local RTP port and a shutdown sender. Drop the sender to stop.
pub async fn start_session(
    remote_addr: SocketAddr,
    codec: Codec,
    mut mic_rx: mpsc::Receiver<Vec<f32>>,
    spk_tx: mpsc::Sender<Vec<f32>>,
    mut dtmf_rx: mpsc::Receiver<char>,
    event_tx: Option<mpsc::Sender<VoipEvent>>,
    srtp_send: Option<SrtpContext>,
    srtp_recv: Option<SrtpContext>,
) -> Result<(u16, tokio::sync::oneshot::Sender<()>)> {
    // Bind to an even port in 10000-60000 range (RTP convention)
    let socket = bind_rtp_socket().await?;
    let local_port = socket.local_addr()?.port();
    tracing::info!("RTP bound to port {local_port}, remote={remote_addr}, codec={:?}", codec);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let socket = std::sync::Arc::new(socket);
        let send_socket = socket.clone();

        // SRTP contexts (separate for send/recv to track ROC independently)
        let mut srtp_tx = srtp_send;
        let mut srtp_rx = srtp_recv;
        if srtp_tx.is_some() {
            tracing::info!("SRTP enabled for RTP session");
        }

        // Random SSRC and initial sequence number
        let ssrc: u32 = rand::random();
        let mut seq: u16 = rand::random();
        let mut timestamp: u32 = rand::random();

        let mut enc_state = CodecState::new();
        let mut dec_state = CodecState::new();
        let mut encode_buf = Vec::new();
        let mut decode_buf = Vec::new();
        let mut recv_buf = [0u8; 2048];

        // Resamplers for G.711 codecs (16kHz ↔ 8kHz)
        let mut down_resampler = LinearResampler::new(16000, 8000);
        let mut up_resampler = LinearResampler::new(8000, 16000);
        let mut resample_buf = Vec::new();

        let payload_type = codec.rtp_payload_type();

        // Jitter buffer
        let mut jitter = JitterBuffer::new(codec.rtp_clock_rate());
        // 20ms playout tick
        let mut playout_tick = tokio::time::interval(Duration::from_millis(20));
        playout_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Silence frame for PLC
        let silence_frame = vec![0.0f32; FRAME_SAMPLES];

        // DTMF state
        let mut dtmf_active: Option<DtmfState> = None;

        loop {
            tokio::select! {
                // Send path: mic → encode → RTP → UDP
                Some(frame_16k) = mic_rx.recv() => {
                    let pcm = if codec.audio_sample_rate() == 8000 {
                        // Downsample 16kHz → 8kHz for G.711
                        down_resampler.process(&frame_16k, &mut resample_buf);
                        &resample_buf
                    } else {
                        &frame_16k
                    };

                    codec::encode_frame(codec, &mut enc_state, pcm, &mut encode_buf);

                    let packet = build_rtp_packet(
                        payload_type,
                        seq,
                        timestamp,
                        ssrc,
                        &encode_buf,
                    );

                    let wire_packet = if let Some(ref mut ctx) = srtp_tx {
                        ctx.encrypt_rtp(&packet)
                    } else {
                        packet
                    };

                    if let Err(e) = send_socket.send_to(&wire_packet, remote_addr).await {
                        tracing::warn!("RTP send error: {e}");
                    }

                    seq = seq.wrapping_add(1);
                    timestamp = timestamp.wrapping_add(codec.timestamp_increment());
                }

                // Receive path: UDP → RTP → jitter buffer
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, _from)) => {
                            if len < RTP_HEADER_SIZE {
                                continue;
                            }

                            let raw = &recv_buf[..len];

                            // Decrypt SRTP if enabled
                            let decrypted;
                            let data = if let Some(ref mut ctx) = srtp_rx {
                                match ctx.decrypt_rtp(raw) {
                                    Ok(d) => { decrypted = d; &decrypted[..] }
                                    Err(e) => {
                                        tracing::warn!("SRTP decrypt failed: {e}");
                                        continue;
                                    }
                                }
                            } else {
                                raw
                            };

                            if let Some((rtp_seq, rtp_ts, payload)) = parse_rtp_full(data) {
                                let pt = data[1] & 0x7F;
                                if pt == DTMF_PAYLOAD_TYPE {
                                    // Detect incoming DTMF
                                    if payload.len() >= 4 {
                                        let end_bit = payload[1] & 0x80 != 0;
                                        if end_bit {
                                            let code = payload[0];
                                            if let Some(ch) = dtmf_code_to_digit(code) {
                                                if let Some(ref tx) = event_tx {
                                                    let _ = tx.try_send(VoipEvent::DtmfReceived(ch));
                                                }
                                                tracing::info!("DTMF received: {ch} (code={code})");
                                            }
                                        }
                                    }
                                    continue;
                                }
                                jitter.push(rtp_seq, rtp_ts, payload.to_vec());
                            }
                        }
                        Err(e) => {
                            tracing::warn!("RTP recv error: {e}");
                        }
                    }
                }

                // Playout tick: pop from jitter buffer → decode → speaker
                _ = playout_tick.tick() => {
                    match jitter.pop() {
                        Some(pkt) => {
                            codec::decode_frame(codec, &mut dec_state, &pkt.payload, &mut decode_buf);

                            let output = if codec.audio_sample_rate() == 8000 {
                                up_resampler.process(&decode_buf, &mut resample_buf);
                                resample_buf.clone()
                            } else {
                                decode_buf.clone()
                            };

                            for chunk in output.chunks(FRAME_SAMPLES) {
                                if chunk.len() == FRAME_SAMPLES {
                                    let _ = spk_tx.try_send(chunk.to_vec());
                                }
                            }
                        }
                        None => {
                            // No packet available — send silence (simple PLC)
                            let _ = spk_tx.try_send(silence_frame.clone());
                        }
                    }
                }

                // DTMF command
                Some(digit) = dtmf_rx.recv() => {
                    let event_code = dtmf_digit_to_code(digit);
                    if let Some(code) = event_code {
                        tracing::info!("Sending DTMF: {digit}");
                        dtmf_active = Some(DtmfState {
                            code,
                            start_ts: timestamp,
                            duration: 0,
                            packets_sent: 0,
                        });
                    }
                }

                // Shutdown signal
                _ = &mut shutdown_rx => {
                    if jitter.stats_received > 0 {
                        tracing::info!(
                            "RTP session stopped. Stats: recv={}, lost={}, dropped={}, jitter={:.1}ms",
                            jitter.stats_received, jitter.stats_lost, jitter.stats_dropped,
                            jitter.jitter_ms()
                        );
                    }
                    break;
                }
            }

            // Send DTMF event packets if active
            if let Some(ref mut dtmf) = dtmf_active {
                let done = send_dtmf_packets(
                    dtmf,
                    &send_socket,
                    remote_addr,
                    &mut seq,
                    ssrc,
                    &mut srtp_tx,
                ).await;
                if done {
                    dtmf_active = None;
                }
            }
        }
    });

    Ok((local_port, shutdown_tx))
}

/// Bind a UDP socket to an even port in the RTP range.
pub async fn bind_rtp_socket() -> Result<UdpSocket> {
    // Try even ports in 10000-60000 range
    for port in (10000..60000).step_by(2) {
        if let Ok(sock) = UdpSocket::bind(("0.0.0.0", port)).await {
            return Ok(sock);
        }
    }
    // Fallback: let OS choose
    Ok(UdpSocket::bind("0.0.0.0:0").await?)
}

/// Build an RTP packet with header + payload.
fn build_rtp_packet(
    payload_type: u8,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(RTP_HEADER_SIZE + payload.len());

    // Byte 0: V=2, P=0, X=0, CC=0
    packet.push(RTP_VERSION << 6);
    // Byte 1: M=0, PT
    packet.push(payload_type & 0x7F);
    // Bytes 2-3: sequence number
    packet.extend_from_slice(&seq.to_be_bytes());
    // Bytes 4-7: timestamp
    packet.extend_from_slice(&timestamp.to_be_bytes());
    // Bytes 8-11: SSRC
    packet.extend_from_slice(&ssrc.to_be_bytes());
    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Build an RTP packet with marker bit set.
fn build_rtp_packet_marker(
    payload_type: u8,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
    marker: bool,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(RTP_HEADER_SIZE + payload.len());

    packet.push(RTP_VERSION << 6);
    let pt_byte = if marker { payload_type | 0x80 } else { payload_type & 0x7F };
    packet.push(pt_byte);
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);

    packet
}

/// Parse an RTP packet and extract sequence number, timestamp, and payload.
fn parse_rtp_full(data: &[u8]) -> Option<(u16, u32, &[u8])> {
    if data.len() < RTP_HEADER_SIZE {
        return None;
    }

    let version = (data[0] >> 6) & 0x03;
    if version != RTP_VERSION {
        return None;
    }

    let cc = (data[0] & 0x0F) as usize;
    let has_extension = (data[0] >> 4) & 0x01 != 0;

    let seq = u16::from_be_bytes([data[2], data[3]]);
    let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let mut offset = RTP_HEADER_SIZE + cc * 4;

    // Skip header extension if present
    if has_extension {
        if data.len() < offset + 4 {
            return None;
        }
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + ext_len * 4;
    }

    if offset > data.len() {
        return None;
    }

    // Check for padding
    let has_padding = (data[0] >> 5) & 0x01 != 0;
    let end = if has_padding && data.len() > offset {
        let pad_len = data[data.len() - 1] as usize;
        data.len().saturating_sub(pad_len)
    } else {
        data.len()
    };

    if offset >= end {
        return None;
    }

    Some((seq, timestamp, &data[offset..end]))
}

#[cfg(test)]
fn parse_rtp_payload(data: &[u8]) -> Option<&[u8]> {
    parse_rtp_full(data).map(|(_, _, payload)| payload)
}

// ═══════════════════════════════════════════════════════════════════════════
// DTMF (RFC 4733)
// ═══════════════════════════════════════════════════════════════════════════

struct DtmfState {
    code: u8,
    start_ts: u32,
    duration: u16,
    packets_sent: u8,
}

fn dtmf_digit_to_code(digit: char) -> Option<u8> {
    match digit {
        '0'..='9' => Some(digit as u8 - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        'A'..='D' => Some(12 + digit as u8 - b'A'),
        'a'..='d' => Some(12 + digit as u8 - b'a'),
        _ => None,
    }
}

fn dtmf_code_to_digit(code: u8) -> Option<char> {
    match code {
        0..=9 => Some((b'0' + code) as char),
        10 => Some('*'),
        11 => Some('#'),
        12..=15 => Some((b'A' + code - 12) as char),
        _ => None,
    }
}

/// Send DTMF event packets. Returns true when done.
async fn send_dtmf_packets(
    state: &mut DtmfState,
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    seq: &mut u16,
    ssrc: u32,
    srtp_tx: &mut Option<SrtpContext>,
) -> bool {
    // RFC 4733: send start, middle, and end packets
    // Duration in timestamp units (8000 Hz clock → 160 per 20ms)
    // Total event: ~160ms = 8 packets worth of duration
    let duration_increment: u16 = 160; // 20ms per step
    let total_duration: u16 = 160 * 8; // 160ms total

    state.duration += duration_increment;
    state.packets_sent += 1;

    let is_end = state.duration >= total_duration;

    // Build DTMF event payload (4 bytes per RFC 4733)
    let mut payload = [0u8; 4];
    payload[0] = state.code;
    // Byte 1: E(1) R(1) volume(6)
    payload[1] = if is_end { 0x80 } else { 0x00 } | 10; // volume=10
    payload[2..4].copy_from_slice(&state.duration.to_be_bytes());

    let marker = state.packets_sent == 1; // marker on first packet
    let packet = build_rtp_packet_marker(
        DTMF_PAYLOAD_TYPE,
        *seq,
        state.start_ts,
        ssrc,
        &payload,
        marker,
    );

    let wire = if let Some(ref mut ctx) = srtp_tx {
        ctx.encrypt_rtp(&packet)
    } else {
        packet
    };
    let _ = socket.send_to(&wire, remote_addr).await;
    *seq = seq.wrapping_add(1);

    if is_end {
        // Send end packet 3 times for reliability
        for _ in 0..2 {
            let end_packet = build_rtp_packet_marker(
                DTMF_PAYLOAD_TYPE,
                *seq,
                state.start_ts,
                ssrc,
                &payload,
                false,
            );
            let wire = if let Some(ref mut ctx) = srtp_tx {
                ctx.encrypt_rtp(&end_packet)
            } else {
                end_packet
            };
            let _ = socket.send_to(&wire, remote_addr).await;
            *seq = seq.wrapping_add(1);
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_rtp() {
        let payload = b"hello rtp";
        let packet = build_rtp_packet(0, 1234, 5678, 0xDEADBEEF, payload);

        assert_eq!(packet.len(), RTP_HEADER_SIZE + payload.len());
        assert_eq!((packet[0] >> 6) & 0x03, 2); // version
        assert_eq!(packet[1] & 0x7F, 0); // payload type

        let parsed = parse_rtp_payload(&packet).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn test_rtp_sequence_fields() {
        let packet = build_rtp_packet(9, 0x1234, 0xABCD0000, 0x12345678, &[0; 160]);

        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        assert_eq!(seq, 0x1234);

        let ts = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        assert_eq!(ts, 0xABCD0000);

        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        assert_eq!(ssrc, 0x12345678);
    }

    #[test]
    fn test_parse_rtp_full() {
        let packet = build_rtp_packet(9, 42, 12345, 0xAABBCCDD, &[1, 2, 3]);
        let (seq, ts, payload) = parse_rtp_full(&packet).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(ts, 12345);
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn test_dtmf_digit_codes() {
        assert_eq!(dtmf_digit_to_code('0'), Some(0));
        assert_eq!(dtmf_digit_to_code('9'), Some(9));
        assert_eq!(dtmf_digit_to_code('*'), Some(10));
        assert_eq!(dtmf_digit_to_code('#'), Some(11));
        assert_eq!(dtmf_digit_to_code('A'), Some(12));
        assert_eq!(dtmf_digit_to_code('D'), Some(15));
        assert_eq!(dtmf_digit_to_code('a'), Some(12));
        assert_eq!(dtmf_digit_to_code('X'), None);
    }

    #[test]
    fn test_dtmf_code_roundtrip() {
        for ch in "0123456789*#ABCD".chars() {
            let code = dtmf_digit_to_code(ch).unwrap();
            let back = dtmf_code_to_digit(code).unwrap();
            assert_eq!(ch, back, "roundtrip failed for '{ch}' -> {code}");
        }
        assert_eq!(dtmf_code_to_digit(16), None);
    }

    #[test]
    fn test_rtp_marker_bit() {
        let packet = build_rtp_packet_marker(101, 1, 0, 0, &[0; 4], true);
        assert_eq!(packet[1] & 0x80, 0x80); // marker set
        assert_eq!(packet[1] & 0x7F, 101); // PT

        let packet = build_rtp_packet_marker(101, 1, 0, 0, &[0; 4], false);
        assert_eq!(packet[1] & 0x80, 0); // marker not set
    }
}
