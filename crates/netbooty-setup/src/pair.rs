//! Pairing with a NetBooty server, and announcing this PC to it.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use anyhow::{Context, Result, bail};
use netbooty_cfg::pairing::{Pairing, b64_decode, b64_encode, fingerprint};
use netbooty_cfg::proto;

use crate::install;
use crate::settings::NetworkSettings;

/// A server that answered discovery.
pub struct Offer {
    /// The address the answer came from (more reliable than the one the
    /// server advertises, which can be a container-internal address).
    pub from: Ipv4Addr,
    pub pairing: Pairing,
}

impl Offer {
    pub fn fingerprints(&self) -> String {
        self.pairing.keys.iter().map(fingerprint).collect::<Vec<_>>().join(" / ")
    }

    /// The pairing code, pointing at the address that answered.
    pub fn code_for_source(&self) -> String {
        Pairing { server: Some(self.from.octets()), ..self.pairing.clone() }.encode()
    }
}

/// Broadcast a discovery request and collect offers for `wait`.
pub fn discover(port: u16, wait: std::time::Duration) -> Result<Vec<Offer>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.send_to(proto::DISCOVER, SocketAddrV4::new(Ipv4Addr::BROADCAST, port)).context("broadcasting")?;
    let deadline = std::time::Instant::now() + wait;
    let mut offers: Vec<Offer> = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        sock.set_read_timeout(Some(left.max(std::time::Duration::from_millis(1))))?;
        let Ok((n, from)) = sock.recv_from(&mut buf) else { break };
        let std::net::SocketAddr::V4(from) = from else { continue };
        let Some(code) = proto::parse_offer(&buf[..n]) else { continue };
        let Ok(pairing) = Pairing::decode(code) else { continue };
        if !offers.iter().any(|o| o.pairing.keys == pairing.keys) {
            offers.push(Offer { from: *from.ip(), pairing });
        }
    }
    Ok(offers)
}

/// Apply a pairing code to the network settings.
pub fn apply(code: &str, n: &mut NetworkSettings) -> Result<Pairing> {
    let p = Pairing::decode(code).map_err(|e| anyhow::anyhow!("not a valid pairing code ({e:?})"))?;
    n.enabled = true;
    n.port = p.port;
    n.server = p.server.map(Ipv4Addr::from);
    n.keys = p.keys.iter().map(|k| b64_encode(k)).collect();
    Ok(p)
}

pub fn unpair(n: &mut NetworkSettings) {
    n.keys.clear();
    n.server = None;
}

/// Decoded public keys from settings.
pub fn keys(n: &NetworkSettings) -> Result<Vec<[u8; 32]>> {
    n.keys
        .iter()
        .map(|k| {
            b64_decode(k)
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("bad key {k:?} in settings"))
        })
        .collect()
}

pub fn fingerprints(n: &NetworkSettings) -> String {
    keys(n)
        .map(|k| k.iter().map(fingerprint).collect::<Vec<_>>().join(" / "))
        .unwrap_or_else(|e| e.to_string())
}

fn hostname() -> String {
    let h = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let h: String = h.trim().chars().filter(|c| c.is_ascii_graphic()).take(proto::MAX_HOSTNAME).collect();
    if h.is_empty() { "pc".into() } else { h }
}

/// Tell the server about this PC (client ID, hostname, target names) so it
/// shows up for approval right away. Broadcast plus the paired server's
/// address; unauthenticated and harmless (it only creates a request).
pub fn announce(n: &NetworkSettings) -> Result<String> {
    let cfg = install::installed_config().context("NetBooty is not installed yet")?;
    let host = hostname();
    let msg = proto::announce(&proto::Announce {
        client_id: cfg.client_id,
        hostname: host.clone(),
        targets: cfg.targets.iter().map(|t| t.name.clone()).collect(),
    })
    .context("building announce message")?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    let mut sent = false;
    let mut dests = vec![SocketAddrV4::new(Ipv4Addr::BROADCAST, n.port)];
    dests.extend(n.server.map(|ip| SocketAddrV4::new(ip, n.port)));
    for d in dests {
        sent |= sock.send_to(&msg, d).is_ok();
    }
    if !sent {
        bail!("could not send the announcement");
    }
    Ok(host)
}
