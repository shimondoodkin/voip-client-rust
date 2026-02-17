/// NAT traversal: UPnP-IGD port mapping + STUN discovery.
///
/// Tries UPnP first (creates actual port forwarding on the router),
/// falls back to STUN (discovers public address only).

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;

/// Result of NAT traversal — the public address to advertise in SDP.
#[derive(Debug, Clone)]
pub struct NatMapping {
    /// Public IP:port to use in SDP c=/m= lines.
    pub public_addr: SocketAddr,
    /// Method used to discover/create the mapping.
    pub method: NatMethod,
}

#[derive(Debug, Clone, Copy)]
pub enum NatMethod {
    /// UPnP-IGD port mapping created on router.
    Upnp,
    /// STUN discovered address (no port mapping created).
    Stun,
    /// No NAT traversal — using local address.
    Local,
}

/// Attempt NAT traversal for an RTP socket.
///
/// 1. Try UPnP-IGD to create a port mapping (best: actual forwarding rule)
/// 2. Fall back to STUN (discovers public addr, works with cone NAT)
/// 3. Fall back to local address
pub async fn discover(
    rtp_socket: &UdpSocket,
    local_ip: IpAddr,
    stun_server: Option<&str>,
) -> NatMapping {
    let local_port = rtp_socket.local_addr()
        .map(|a| a.port())
        .unwrap_or(0);
    let local_addr = SocketAddr::new(local_ip, local_port);

    // Try UPnP-IGD first
    match try_upnp(local_addr).await {
        Ok(public_addr) => {
            tracing::info!("UPnP mapped {local_addr} -> {public_addr}");
            return NatMapping { public_addr, method: NatMethod::Upnp };
        }
        Err(e) => {
            tracing::debug!("UPnP failed: {e}");
        }
    }

    // Try STUN
    if let Some(server) = stun_server {
        match crate::stun::discover_public_addr(rtp_socket, server).await {
            Ok(public_addr) => {
                return NatMapping { public_addr, method: NatMethod::Stun };
            }
            Err(e) => {
                tracing::debug!("STUN failed: {e}");
            }
        }
    }

    // Fallback: local address
    tracing::debug!("NAT traversal failed, using local address {local_addr}");
    NatMapping { public_addr: local_addr, method: NatMethod::Local }
}

/// Try to create a UPnP-IGD port mapping.
async fn try_upnp(local_addr: SocketAddr) -> Result<SocketAddr> {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::SearchOptions;

    let opts = SearchOptions {
        timeout: Some(std::time::Duration::from_secs(3)),
        ..Default::default()
    };

    let gateway = search_gateway(opts).await
        .map_err(|e| anyhow!("UPnP gateway search failed: {e}"))?;

    let external_ip = gateway.get_external_ip().await
        .map_err(|e| anyhow!("UPnP get external IP failed: {e}"))?;

    // Try to map the same port externally; if taken, let the gateway pick
    let external_port = match gateway.add_port(
        igd_next::PortMappingProtocol::UDP,
        local_addr.port(),
        local_addr,
        300, // 5 minute lease
        "voip_client RTP",
    ).await {
        Ok(()) => local_addr.port(),
        Err(_) => {
            // Port taken — ask gateway to pick one
            gateway.add_any_port(
                igd_next::PortMappingProtocol::UDP,
                local_addr,
                300,
                "voip_client RTP",
            ).await
            .map_err(|e| anyhow!("UPnP add_any_port failed: {e}"))?
        }
    };

    Ok(SocketAddr::new(external_ip, external_port))
}

/// Remove a UPnP port mapping (best-effort cleanup).
pub async fn remove_upnp_mapping(external_port: u16) {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::SearchOptions;

    let opts = SearchOptions {
        timeout: Some(std::time::Duration::from_secs(2)),
        ..Default::default()
    };

    if let Ok(gateway) = search_gateway(opts).await {
        let _ = gateway.remove_port(
            igd_next::PortMappingProtocol::UDP,
            external_port,
        ).await;
        tracing::debug!("UPnP mapping removed for port {external_port}");
    }
}
