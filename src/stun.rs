/// Minimal STUN binding request client (RFC 5389).
///
/// Discovers the public (NAT-mapped) IP:port for an existing UDP socket
/// by sending a Binding Request to a STUN server and parsing the
/// XOR-MAPPED-ADDRESS from the response.

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112A442;
/// STUN Binding Request type.
const BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Response type.
const BINDING_RESPONSE: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS attribute type.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// MAPPED-ADDRESS attribute type (fallback).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// STUN header length.
const STUN_HEADER_LEN: usize = 20;

/// Discover public address by sending STUN Binding Request through the given socket.
///
/// The socket should already be bound — we use its existing NAT mapping.
/// Retries up to 3 times with 1s timeout each.
pub async fn discover_public_addr(
    socket: &UdpSocket,
    stun_server: &str,
) -> Result<SocketAddr> {
    let stun_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await
        .map_err(|e| anyhow!("STUN server resolve failed: {e}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for STUN server"))?;

    let transaction_id = generate_transaction_id();
    let request = build_binding_request(&transaction_id);

    for attempt in 1..=3 {
        socket.send_to(&request, stun_addr).await?;
        tracing::debug!("STUN request sent to {stun_addr} (attempt {attempt})");

        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                let data = &buf[..len];
                match parse_binding_response(data, &transaction_id) {
                    Ok(addr) => {
                        tracing::info!("STUN discovered public address: {addr}");
                        return Ok(addr);
                    }
                    Err(e) => {
                        tracing::debug!("STUN parse failed: {e}");
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("STUN recv error: {e}");
            }
            Err(_) => {
                tracing::debug!("STUN timeout (attempt {attempt})");
            }
        }
    }

    Err(anyhow!("STUN discovery failed after 3 attempts"))
}

/// Build a STUN Binding Request.
fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(STUN_HEADER_LEN);

    // Message Type: Binding Request (0x0001)
    pkt.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message Length: 0 (no attributes)
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Magic Cookie
    pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    pkt.extend_from_slice(transaction_id);

    pkt
}

/// Parse a STUN Binding Response and extract the mapped address.
fn parse_binding_response(data: &[u8], expected_tid: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < STUN_HEADER_LEN {
        return Err(anyhow!("response too short"));
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(anyhow!("not a Binding Response: 0x{msg_type:04x}"));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(anyhow!("bad magic cookie"));
    }

    // Verify transaction ID
    if &data[8..20] != expected_tid {
        return Err(anyhow!("transaction ID mismatch"));
    }

    // Parse attributes
    let attrs_end = STUN_HEADER_LEN + msg_len.min(data.len() - STUN_HEADER_LEN);
    let mut offset = STUN_HEADER_LEN;

    while offset + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > attrs_end {
            break;
        }

        let attr_data = &data[offset..offset + attr_len];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return parse_xor_mapped_address(attr_data);
        } else if attr_type == ATTR_MAPPED_ADDRESS {
            return parse_mapped_address(attr_data);
        }

        // Attributes are padded to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }

    Err(anyhow!("no mapped address in response"))
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(anyhow!("XOR-MAPPED-ADDRESS too short"));
    }

    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let x_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ MAGIC_COOKIE;
            let ip = std::net::Ipv4Addr::from(x_ip);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), x_port))
        }
        0x02 => {
            // IPv6 — not commonly needed for VoIP, but handle gracefully
            Err(anyhow!("IPv6 STUN not supported"))
        }
        _ => Err(anyhow!("unknown address family: {family}")),
    }
}

/// Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1).
fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(anyhow!("MAPPED-ADDRESS too short"));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        _ => Err(anyhow!("unsupported address family: {family}")),
    }
}

/// Generate a random 12-byte transaction ID.
fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    for b in id.iter_mut() {
        *b = rand::random();
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let tid = [1u8; 12];
        let pkt = build_binding_request(&tid);
        assert_eq!(pkt.len(), 20);
        assert_eq!(&pkt[0..2], &[0, 1]); // Binding Request
        assert_eq!(&pkt[2..4], &[0, 0]); // Length 0
        assert_eq!(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), MAGIC_COOKIE);
        assert_eq!(&pkt[8..20], &tid);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        // Craft a XOR-MAPPED-ADDRESS for 198.51.100.1:12345
        let ip: u32 = 0xC6336401; // 198.51.100.1
        let port: u16 = 12345;

        let x_ip = ip ^ MAGIC_COOKIE;
        let x_port = port ^ (MAGIC_COOKIE >> 16) as u16;

        let mut data = vec![0u8; 8];
        data[1] = 0x01; // IPv4
        data[2..4].copy_from_slice(&x_port.to_be_bytes());
        data[4..8].copy_from_slice(&x_ip.to_be_bytes());

        let addr = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn test_parse_binding_response() {
        // Build a complete STUN Binding Response with XOR-MAPPED-ADDRESS
        let tid = [0x42u8; 12];
        let ip: u32 = 0xC0A80164; // 192.168.1.100
        let port: u16 = 54321;
        let x_ip = ip ^ MAGIC_COOKIE;
        let x_port = port ^ (MAGIC_COOKIE >> 16) as u16;

        let mut attr = vec![0u8; 8];
        attr[1] = 0x01; // IPv4
        attr[2..4].copy_from_slice(&x_port.to_be_bytes());
        attr[4..8].copy_from_slice(&x_ip.to_be_bytes());

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        let attr_total_len = 4 + attr.len(); // type(2) + len(2) + data
        pkt.extend_from_slice(&(attr_total_len as u16).to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&tid);

        // Attribute: XOR-MAPPED-ADDRESS
        pkt.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        pkt.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&attr);

        let addr = parse_binding_response(&pkt, &tid).unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(addr.port(), 54321);
    }
}
