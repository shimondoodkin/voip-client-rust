/// SDP build/parse for VoIP.
///
/// Supports offer/answer model with G.722, G.711, Opus codecs,
/// telephone-event for DTMF, and optional SRTP crypto attributes.

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};

use crate::codec::Codec;

/// Parsed SDP offer with all advertised codecs.
pub struct SdpOffer {
    pub codecs: Vec<(u8, Codec)>,
    pub ip: IpAddr,
    pub port: u16,
    pub ptime: u16,
    /// Remote SRTP crypto line (if present)
    pub crypto: Option<String>,
    /// Whether telephone-event is offered
    pub telephone_event_pt: Option<u8>,
}

/// Build an SDP offer advertising all supported codecs.
/// Opus first (best quality), then G.722, then G.711.
/// If `crypto_attr` is provided, uses `RTP/SAVP` and includes an `a=crypto` line.
pub fn build_offer(local_ip: IpAddr, rtp_port: u16, crypto_attr: Option<&str>) -> String {
    let codecs = Codec::offer_list();
    let pt_list: String = codecs.iter()
        .map(|c| c.rtp_payload_type().to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let profile = if crypto_attr.is_some() { "RTP/SAVP" } else { "RTP/AVP" };

    let mut sdp = format!(
        "v=0\r\n\
         o=voip_client 0 0 IN IP4 {local_ip}\r\n\
         s=call\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} {profile} {pt_list} 101\r\n"
    );

    for c in codecs {
        let pt = c.rtp_payload_type();
        let name = c.name();
        let clock = c.rtp_clock_rate();
        match c {
            Codec::Opus => {
                sdp.push_str(&format!("a=rtpmap:{pt} opus/48000/2\r\n"));
                sdp.push_str(&format!("a=fmtp:{pt} useinbandfec=1\r\n"));
            }
            _ => {
                sdp.push_str(&format!("a=rtpmap:{pt} {name}/{clock}\r\n"));
            }
        }
    }

    // Telephone-event for DTMF (RFC 4733)
    sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
    sdp.push_str("a=fmtp:101 0-16\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");

    if let Some(attr) = crypto_attr {
        sdp.push_str(&format!("a=crypto:{attr}\r\n"));
    }

    sdp
}

/// Build an SDP offer with a specific direction attribute.
///
/// Used for hold (`sendonly`), unhold (`sendrecv`), and `inactive`.
/// If `crypto_attr` is provided, uses `RTP/SAVP` and includes an `a=crypto` line.
pub fn build_offer_with_direction(local_ip: IpAddr, rtp_port: u16, direction: &str, crypto_attr: Option<&str>) -> String {
    let codecs = Codec::offer_list();
    let pt_list: String = codecs.iter()
        .map(|c| c.rtp_payload_type().to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let profile = if crypto_attr.is_some() { "RTP/SAVP" } else { "RTP/AVP" };

    let mut sdp = format!(
        "v=0\r\n\
         o=voip_client 0 0 IN IP4 {local_ip}\r\n\
         s=call\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} {profile} {pt_list} 101\r\n"
    );

    for c in codecs {
        let pt = c.rtp_payload_type();
        let name = c.name();
        let clock = c.rtp_clock_rate();
        match c {
            Codec::Opus => {
                sdp.push_str(&format!("a=rtpmap:{pt} opus/48000/2\r\n"));
                sdp.push_str(&format!("a=fmtp:{pt} useinbandfec=1\r\n"));
            }
            _ => {
                sdp.push_str(&format!("a=rtpmap:{pt} {name}/{clock}\r\n"));
            }
        }
    }

    sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
    sdp.push_str("a=fmtp:101 0-16\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str(&format!("a={direction}\r\n"));

    if let Some(attr) = crypto_attr {
        sdp.push_str(&format!("a=crypto:{attr}\r\n"));
    }

    sdp
}

/// Build an SDP answer mirroring only the first mutually-supported codec from the remote offer.
/// If `crypto_attr` is provided, uses `RTP/SAVP` and includes an `a=crypto` line.
pub fn build_answer(local_ip: IpAddr, rtp_port: u16, remote: &SdpOffer, crypto_attr: Option<&str>) -> String {
    // Find first mutually-supported codec
    let (pt, codec) = remote.codecs.first()
        .copied()
        .unwrap_or((0, Codec::Ulaw));

    let mut pt_list = pt.to_string();

    // Include telephone-event if remote offered it
    let tel_event_pt = remote.telephone_event_pt;
    if let Some(tpt) = tel_event_pt {
        pt_list.push_str(&format!(" {tpt}"));
    }

    let profile = if crypto_attr.is_some() { "RTP/SAVP" } else { "RTP/AVP" };

    let mut sdp = format!(
        "v=0\r\n\
         o=voip_client 0 0 IN IP4 {local_ip}\r\n\
         s=call\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} {profile} {pt_list}\r\n"
    );

    match codec {
        Codec::Opus => {
            sdp.push_str(&format!("a=rtpmap:{pt} opus/48000/2\r\n"));
            sdp.push_str(&format!("a=fmtp:{pt} useinbandfec=1\r\n"));
        }
        _ => {
            sdp.push_str(&format!("a=rtpmap:{pt} {}/{}\r\n", codec.name(), codec.rtp_clock_rate()));
        }
    }

    if let Some(tpt) = tel_event_pt {
        sdp.push_str(&format!("a=rtpmap:{tpt} telephone-event/8000\r\n"));
        sdp.push_str(&format!("a=fmtp:{tpt} 0-16\r\n"));
    }

    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");

    if let Some(attr) = crypto_attr {
        sdp.push_str(&format!("a=crypto:{attr}\r\n"));
    }

    sdp
}

/// Parse an SDP offer to extract all advertised codecs, IP, port.
pub fn parse_offer(sdp: &str) -> Result<SdpOffer> {
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut ptime: u16 = 20;
    let mut crypto: Option<String> = None;
    let mut telephone_event_pt: Option<u8> = None;

    // Collect payload types from m= line
    let mut m_payload_types: Vec<u8> = Vec::new();
    // Map dynamic PT -> codec via rtpmap
    let mut dynamic_codecs: Vec<(u8, Codec)> = Vec::new();

    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("c=IN IP4 ") {
            let addr_str = line.strip_prefix("c=IN IP4 ").unwrap().trim();
            ip = Some(addr_str.parse().map_err(|e| anyhow!("bad SDP c= IP: {e}"))?);
        } else if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = Some(parts[1].parse().map_err(|e| anyhow!("bad SDP m=audio port: {e}"))?);
            }
            for &pt_str in parts.iter().skip(3) {
                if let Ok(pt) = pt_str.parse::<u8>() {
                    m_payload_types.push(pt);
                }
            }
        } else if line.starts_with("a=rtpmap:") {
            // Parse a=rtpmap:PT name/clock[/channels]
            let rest = &line[9..];
            if let Some((pt_str, name_part)) = rest.split_once(' ') {
                if let Ok(pt) = pt_str.parse::<u8>() {
                    let name_lower = name_part.to_lowercase();
                    if name_lower.starts_with("telephone-event") {
                        telephone_event_pt = Some(pt);
                    } else if name_lower.starts_with("opus/") {
                        dynamic_codecs.push((pt, Codec::Opus));
                    } else if name_lower.starts_with("g722/") {
                        dynamic_codecs.push((pt, Codec::G722));
                    } else if name_lower.starts_with("pcmu/") {
                        dynamic_codecs.push((pt, Codec::Ulaw));
                    } else if name_lower.starts_with("pcma/") {
                        dynamic_codecs.push((pt, Codec::Alaw));
                    }
                }
            }
        } else if line.starts_with("a=ptime:") {
            if let Ok(v) = line[8..].trim().parse::<u16>() {
                ptime = v;
            }
        } else if line.starts_with("a=crypto:") {
            crypto = Some(line[9..].to_string());
        }
    }

    // Build ordered codec list: for each PT in m= line order, resolve to codec
    let mut codecs = Vec::new();
    for pt in &m_payload_types {
        // Check dynamic mappings first
        if let Some(&(_, codec)) = dynamic_codecs.iter().find(|(p, _)| p == pt) {
            codecs.push((*pt, codec));
        } else if let Some(codec) = Codec::from_payload_type(*pt) {
            // Static payload type
            codecs.push((*pt, codec));
        }
        // Skip unknown PTs (telephone-event, etc.)
    }

    match (ip, port) {
        (Some(ip), Some(port)) => Ok(SdpOffer { codecs, ip, port, ptime, crypto, telephone_event_pt }),
        (None, _) => Err(anyhow!("SDP missing c= line")),
        (_, None) => Err(anyhow!("SDP missing m=audio line")),
    }
}

/// Parse an SDP answer to extract the remote RTP address, negotiated codec,
/// and optional SRTP crypto attribute.
///
/// Picks the first payload type from the m= line that we support.
pub fn parse_answer(sdp: &str) -> Result<(SocketAddr, Codec, Option<String>)> {
    let offer = parse_offer(sdp)?;
    let codec = offer.codecs.first().map(|&(_, c)| c).unwrap_or(Codec::Ulaw);
    Ok((SocketAddr::new(offer.ip, offer.port), codec, offer.crypto))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_and_parse_roundtrip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let port = 12345u16;
        let sdp = build_offer(ip, port, None);
        let (addr, codec, _crypto) = parse_answer(&sdp).unwrap();
        assert_eq!(addr, SocketAddr::new(ip, port));
        // Opus is first in offer list now
        assert_eq!(codec, Codec::Opus);
    }

    #[test]
    fn test_parse_asterisk_g722_answer() {
        let sdp = "v=0\r\n\
                    o=Asterisk 12345 12346 IN IP4 10.0.0.1\r\n\
                    s=Asterisk\r\n\
                    c=IN IP4 10.0.0.1\r\n\
                    t=0 0\r\n\
                    m=audio 20000 RTP/AVP 9\r\n\
                    a=rtpmap:9 G722/8000\r\n\
                    a=ptime:20\r\n\
                    a=sendrecv\r\n";
        let (addr, codec, _crypto) = parse_answer(sdp).unwrap();
        assert_eq!(addr.port(), 20000);
        assert_eq!(codec, Codec::G722);
    }

    #[test]
    fn test_parse_ulaw_fallback() {
        let sdp = "v=0\r\n\
                    c=IN IP4 10.0.0.1\r\n\
                    m=audio 20000 RTP/AVP 0\r\n";
        let (_, codec, _crypto) = parse_answer(sdp).unwrap();
        assert_eq!(codec, Codec::Ulaw);
    }

    #[test]
    fn test_parse_offer_codecs() {
        let sdp = "v=0\r\n\
                    c=IN IP4 10.0.0.1\r\n\
                    m=audio 20000 RTP/AVP 111 9 0 8 101\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:9 G722/8000\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:8 PCMA/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=fmtp:101 0-16\r\n";
        let offer = parse_offer(sdp).unwrap();
        assert_eq!(offer.codecs.len(), 4);
        assert_eq!(offer.codecs[0], (111, Codec::Opus));
        assert_eq!(offer.codecs[1], (9, Codec::G722));
        assert_eq!(offer.telephone_event_pt, Some(101));
    }

    #[test]
    fn test_build_answer_mirrors_codec() {
        let sdp = "v=0\r\n\
                    c=IN IP4 10.0.0.1\r\n\
                    m=audio 20000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=fmtp:101 0-16\r\n";
        let offer = parse_offer(sdp).unwrap();
        let answer = build_answer(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            30000,
            &offer,
            None,
        );
        assert!(answer.contains("m=audio 30000 RTP/AVP 0 101"));
        assert!(answer.contains("a=rtpmap:0 PCMU/8000"));
        assert!(answer.contains("a=rtpmap:101 telephone-event/8000"));
    }
}
