/// DNS SRV lookup for SIP server discovery (RFC 3263).
///
/// Resolves `_sip._udp.<domain>`, `_sip._tcp.<domain>`, and
/// `_sips._tcp.<domain>` SRV records to find the SIP server address.
/// Falls back to A/AAAA record lookup if no SRV records are found.
///
/// This module is optional — callers can skip DNS resolution and provide
/// a pre-resolved `SocketAddr` directly in [`VoipConfig`].

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};

use crate::sip::Transport;

/// A resolved SIP server target from DNS SRV.
#[derive(Debug, Clone)]
pub struct SrvTarget {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub transport: Transport,
}

/// Result of SIP DNS resolution.
#[derive(Debug, Clone)]
pub struct SipDnsResult {
    /// Resolved socket address of the best SIP server.
    pub addr: SocketAddr,
    /// Transport determined from the SRV record type.
    pub transport: Transport,
    /// All SRV targets found, sorted by priority and weight.
    pub targets: Vec<SrvTarget>,
}

/// Resolve a SIP domain to a server address using DNS SRV records (RFC 3263).
///
/// Queries in order:
/// 1. `_sips._tcp.<domain>` (TLS, preferred)
/// 2. `_sip._tcp.<domain>` (TCP)
/// 3. `_sip._udp.<domain>` (UDP)
///
/// If `preferred_transport` is specified, only that transport's SRV records
/// are queried. If no SRV records are found, falls back to A/AAAA lookup
/// on the domain with the standard port (5060 for UDP/TCP, 5061 for TLS).
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> anyhow::Result<()> {
/// use voip_client::dns;
/// let result = dns::resolve_sip_server("voip.example.com", None).await?;
/// println!("Server: {} via {:?}", result.addr, result.transport);
/// # Ok(())
/// # }
/// ```
pub async fn resolve_sip_server(
    domain: &str,
    preferred_transport: Option<Transport>,
) -> Result<SipDnsResult> {
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .map_err(|e| anyhow!("failed to create DNS resolver: {e}"))?
        .build();

    // Define SRV queries to try, in priority order
    let queries: Vec<(String, Transport, u16)> = match preferred_transport {
        Some(Transport::Tls) => vec![
            (format!("_sips._tcp.{domain}."), Transport::Tls, 5061),
        ],
        Some(Transport::Udp) => vec![
            (format!("_sip._udp.{domain}."), Transport::Udp, 5060),
        ],
        None => vec![
            (format!("_sips._tcp.{domain}."), Transport::Tls, 5061),
            (format!("_sip._udp.{domain}."), Transport::Udp, 5060),
        ],
    };

    for (srv_name, transport, _default_port) in &queries {
        match resolver.srv_lookup(srv_name.as_str()).await {
            Ok(lookup) => {
                let mut targets: Vec<SrvTarget> = lookup
                    .iter()
                    .map(|record| SrvTarget {
                        host: record.target().to_string().trim_end_matches('.').to_string(),
                        port: record.port(),
                        priority: record.priority(),
                        weight: record.weight(),
                        transport: *transport,
                    })
                    .collect();

                if targets.is_empty() {
                    continue;
                }

                // Sort by priority (ascending), then by weight (descending)
                // RFC 2782: lower priority = preferred; higher weight = preferred within same priority
                targets.sort_by(|a, b| {
                    a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight))
                });

                // Resolve the best target's hostname to an IP
                let best = &targets[0];
                let ip = resolve_host(&resolver, &best.host).await?;

                return Ok(SipDnsResult {
                    addr: SocketAddr::new(ip, best.port),
                    transport: *transport,
                    targets,
                });
            }
            Err(e) => {
                tracing::debug!("SRV lookup {srv_name} failed: {e}");
                continue;
            }
        }
    }

    // Fallback: A/AAAA lookup on the bare domain
    tracing::debug!("No SRV records found, falling back to A/AAAA for {domain}");
    let transport = preferred_transport.unwrap_or(Transport::Udp);
    let default_port = match transport {
        Transport::Tls => 5061,
        Transport::Udp => 5060,
    };

    let ip = resolve_host(&resolver, domain).await?;
    Ok(SipDnsResult {
        addr: SocketAddr::new(ip, default_port),
        transport,
        targets: vec![SrvTarget {
            host: domain.to_string(),
            port: default_port,
            priority: 0,
            weight: 0,
            transport,
        }],
    })
}

/// Resolve a hostname to an IP address (A/AAAA).
async fn resolve_host(
    resolver: &hickory_resolver::TokioResolver,
    host: &str,
) -> Result<IpAddr> {
    // Try parsing as IP first (skip DNS if already an address)
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| anyhow!("DNS lookup failed for {host}: {e}"))?;

    response
        .iter()
        .next()
        .ok_or_else(|| anyhow!("no DNS records found for {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv_target_sorting() {
        let mut targets = vec![
            SrvTarget { host: "c.example.com".into(), port: 5060, priority: 20, weight: 10, transport: Transport::Udp },
            SrvTarget { host: "a.example.com".into(), port: 5060, priority: 10, weight: 50, transport: Transport::Udp },
            SrvTarget { host: "b.example.com".into(), port: 5060, priority: 10, weight: 100, transport: Transport::Udp },
        ];

        targets.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight))
        });

        assert_eq!(targets[0].host, "b.example.com"); // priority 10, weight 100 (highest)
        assert_eq!(targets[1].host, "a.example.com"); // priority 10, weight 50
        assert_eq!(targets[2].host, "c.example.com"); // priority 20
    }

    #[tokio::test]
    async fn test_resolve_ip_passthrough() {
        // When given an IP address string, resolve_host should return it directly
        let resolver = hickory_resolver::TokioResolver::builder_tokio().unwrap().build();
        let ip = resolve_host(&resolver, "127.0.0.1").await.unwrap();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }
}
