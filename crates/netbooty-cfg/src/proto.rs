//! NetBooty's LAN protocol (UDP).
//!
//! - **Request** (37 bytes), sent by NetBooty at boot, broadcast and
//!   optionally unicast: `"NBTY1" ‖ client_id[16] ‖ nonce[16]`.
//! - **Reply** (80 bytes) from the server: `target[16] ‖ signature[64]`, where
//!   the Ed25519 signature covers `"NBTY1-resp" ‖ client_id ‖ nonce ‖ target`.
//!   `target` is a NUL-padded name; all zeros means "no preference".
//! - **Announce**, sent by `netbooty-setup pair --announce` so a PC shows up
//!   for approval with its name and targets before it ever boots NetBooty:
//!   `"NBTYA" ‖ client_id[16] ‖ len ‖ hostname ‖ count ‖ name[16]*count`.
//!   It is unauthenticated and only ever creates a pairing request.
//! - **Discover** (`"NBTYD1"`), broadcast by `netbooty-setup pair --discover`;
//!   servers answer with an **offer**: `"NBTYP1" ‖ pairing code`. The code
//!   holds only public data, and the user confirms its fingerprint against
//!   the server's web page before trusting it.

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

use crate::config::{NAME_LEN, name_bytes, name_from_bytes};

pub const MAGIC: &[u8; 5] = b"NBTY1";
pub const ANNOUNCE_MAGIC: &[u8; 5] = b"NBTYA";
pub const RESPONSE_CONTEXT: &[u8; 10] = b"NBTY1-resp";
pub const DEFAULT_PORT: u16 = crate::config::DEFAULT_PORT;
pub const REQUEST_LEN: usize = 37;
pub const REPLY_LEN: usize = 80;
pub const MAX_HOSTNAME: usize = 63;
pub const DISCOVER: &[u8; 6] = b"NBTYD1";
pub const OFFER_MAGIC: &[u8; 6] = b"NBTYP1";
const MAX_OFFER: usize = 512;

/// A server's answer to [`DISCOVER`].
pub fn offer(pairing_code: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(6 + pairing_code.len());
    b.extend_from_slice(OFFER_MAGIC);
    b.extend_from_slice(pairing_code.as_bytes());
    b
}

/// The pairing code in an offer, if it is one.
pub fn parse_offer(b: &[u8]) -> Option<&str> {
    if b.len() > MAX_OFFER {
        return None;
    }
    core::str::from_utf8(b.strip_prefix(OFFER_MAGIC.as_slice())?).ok()
}

pub fn request(client_id: &[u8; 16], nonce: &[u8; 16]) -> [u8; REQUEST_LEN] {
    let mut r = [0u8; REQUEST_LEN];
    r[..5].copy_from_slice(MAGIC);
    r[5..21].copy_from_slice(client_id);
    r[21..].copy_from_slice(nonce);
    r
}

/// Split a request into (client_id, nonce); `None` if it is not one.
pub fn parse_request(b: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    if b.len() != REQUEST_LEN || &b[..5] != MAGIC {
        return None;
    }
    Some((b[5..21].try_into().ok()?, b[21..].try_into().ok()?))
}

/// What the server answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    NoPreference,
    Target(String),
}

fn signed_message(client_id: &[u8; 16], nonce: &[u8; 16], target: &[u8; NAME_LEN]) -> [u8; 58] {
    let mut m = [0u8; 58];
    m[..10].copy_from_slice(RESPONSE_CONTEXT);
    m[10..26].copy_from_slice(client_id);
    m[26..42].copy_from_slice(nonce);
    m[42..].copy_from_slice(target);
    m
}

/// Public key for a 32-byte secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    *KeyPair::from_seed(Seed::new(*seed)).pk
}

/// Build a signed reply. `target: None` means "no preference". `None` if the
/// target name is invalid.
pub fn sign_reply(
    seed: &[u8; 32],
    client_id: &[u8; 16],
    nonce: &[u8; 16],
    target: Option<&str>,
) -> Option<[u8; REPLY_LEN]> {
    let t = match target {
        Some(name) => name_bytes(name)?,
        None => [0; NAME_LEN],
    };
    let kp = KeyPair::from_seed(Seed::new(*seed));
    let sig = kp.sk.sign(signed_message(client_id, nonce, &t), None);
    let mut r = [0u8; REPLY_LEN];
    r[..NAME_LEN].copy_from_slice(&t);
    r[NAME_LEN..].copy_from_slice(sig.as_ref());
    Some(r)
}

/// Verify a reply against every nonce this boot sent and every trusted key.
/// Returns `None` for anything that is not a valid, signed reply.
pub fn verify(reply: &[u8], client_id: &[u8; 16], nonces: &[[u8; 16]], keys: &[[u8; 32]]) -> Option<Reply> {
    if reply.len() != REPLY_LEN {
        return None;
    }
    let target: [u8; NAME_LEN] = reply[..NAME_LEN].try_into().ok()?;
    let name = name_from_bytes(&target)?;
    let sig = Signature::from_slice(&reply[NAME_LEN..]).ok()?;
    let valid = keys.iter().any(|k| {
        let pk = PublicKey::new(*k);
        nonces.iter().any(|n| pk.verify(signed_message(client_id, n, &target), &sig).is_ok())
    });
    if !valid {
        return None;
    }
    Some(if name.is_empty() { Reply::NoPreference } else { Reply::Target(String::from(name)) })
}

/// A PC introducing itself for approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    pub client_id: [u8; 16],
    pub hostname: String,
    pub targets: Vec<String>,
}

pub fn announce(a: &Announce) -> Option<Vec<u8>> {
    let host = a.hostname.as_bytes();
    if host.len() > MAX_HOSTNAME || a.targets.len() > crate::config::MAX_TARGETS {
        return None;
    }
    let mut b = Vec::with_capacity(23 + host.len() + a.targets.len() * NAME_LEN);
    b.extend_from_slice(ANNOUNCE_MAGIC);
    b.extend_from_slice(&a.client_id);
    b.push(host.len() as u8);
    b.extend_from_slice(host);
    b.push(a.targets.len() as u8);
    for t in &a.targets {
        b.extend_from_slice(&name_bytes(t)?);
    }
    Some(b)
}

pub fn parse_announce(b: &[u8]) -> Option<Announce> {
    if b.len() < 23 || &b[..5] != ANNOUNCE_MAGIC {
        return None;
    }
    let client_id = b[5..21].try_into().ok()?;
    let hlen = b[21] as usize;
    if hlen > MAX_HOSTNAME {
        return None;
    }
    let hostname = core::str::from_utf8(b.get(22..22 + hlen)?).ok()?;
    let count = *b.get(22 + hlen)? as usize;
    let rest = b.get(23 + hlen..)?;
    if count > crate::config::MAX_TARGETS || rest.len() != count * NAME_LEN {
        return None;
    }
    let targets = rest
        .as_chunks::<NAME_LEN>()
        .0
        .iter()
        .map(|c| name_from_bytes(c).filter(|n| !n.is_empty()).map(String::from))
        .collect::<Option<Vec<_>>>()?;
    Some(Announce { client_id, hostname: String::from(hostname), targets })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const SEED: [u8; 32] = [7; 32];
    const CID: [u8; 16] = [1; 16];
    const NONCE: [u8; 16] = [2; 16];

    #[test]
    fn request_layout() {
        let r = request(&CID, &NONCE);
        assert_eq!(&r[..5], b"NBTY1");
        assert_eq!(parse_request(&r), Some((CID, NONCE)));
        assert_eq!(parse_request(&r[..36]), None);
        let mut bad = r;
        bad[0] = b'X';
        assert_eq!(parse_request(&bad), None);
    }

    #[test]
    fn signed_reply_round_trip() {
        let pk = public_key(&SEED);
        let r = sign_reply(&SEED, &CID, &NONCE, Some("windows")).unwrap();
        assert_eq!(verify(&r, &CID, &[NONCE], &[pk]), Some(Reply::Target("windows".into())));
        let none = sign_reply(&SEED, &CID, &NONCE, None).unwrap();
        assert_eq!(verify(&none, &CID, &[NONCE], &[pk]), Some(Reply::NoPreference));
        // Any nonce sent this boot is accepted; any trusted key is accepted.
        assert!(verify(&r, &CID, &[[9; 16], NONCE], &[[0; 32], pk]).is_some());
    }

    #[test]
    fn rejects_forgeries_and_replays() {
        let pk = public_key(&SEED);
        let r = sign_reply(&SEED, &CID, &NONCE, Some("windows")).unwrap();
        // Replay: a reply to an older nonce.
        assert_eq!(verify(&r, &CID, &[[3; 16]], &[pk]), None);
        // Meant for another PC.
        assert_eq!(verify(&r, &[5; 16], &[NONCE], &[pk]), None);
        // Signed by someone else.
        assert_eq!(verify(&r, &CID, &[NONCE], &[public_key(&[8; 32])]), None);
        // Target swapped after signing.
        let mut swapped = r;
        swapped[..16].copy_from_slice(&name_bytes("linux").unwrap());
        assert_eq!(verify(&swapped, &CID, &[NONCE], &[pk]), None);
        // Wrong size / junk.
        assert_eq!(verify(&r[..79], &CID, &[NONCE], &[pk]), None);
        assert_eq!(verify(&[0xFF; 80], &CID, &[NONCE], &[pk]), None);
        assert_eq!(verify(&r, &CID, &[NONCE], &[]), None);
        assert!(sign_reply(&SEED, &CID, &NONCE, Some("bad name")).is_none());
    }

    #[test]
    fn discovery_offer() {
        let o = offer("netbooty-pair:1:47000:abc");
        assert_eq!(parse_offer(&o), Some("netbooty-pair:1:47000:abc"));
        assert_eq!(parse_offer(b"NBTYX1abc"), None);
        assert_eq!(parse_offer(&[b'N'; 600]), None);
    }

    #[test]
    fn announce_round_trip() {
        let a = Announce {
            client_id: CID,
            hostname: "zaqbox".into(),
            targets: vec!["windows".into(), "linux".into()],
        };
        let b = announce(&a).unwrap();
        assert_eq!(parse_announce(&b), Some(a));
        assert_eq!(parse_announce(&b[..b.len() - 1]), None);
        assert_eq!(parse_announce(&request(&CID, &NONCE)), None);
    }
}
