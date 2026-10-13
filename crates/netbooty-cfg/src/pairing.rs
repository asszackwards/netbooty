//! Pairing code: everything a PC needs to trust a server, in one line that
//! can be copied from the web app. Contains no secrets.
//!
//! `netbooty-pair:1:<port>:<key>[,<next-key>][:<server-ipv4>]`, keys in
//! unpadded base64url.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

const PREFIX: &str = "netbooty-pair:1:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pairing {
    pub port: u16,
    /// Current key first, then the next one during a rotation.
    pub keys: Vec<[u8; 32]>,
    pub server: Option<[u8; 4]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    NotAPairingCode,
    BadPort,
    BadKey,
    BadAddress,
}

impl Pairing {
    pub fn encode(&self) -> String {
        let keys: Vec<String> = self.keys.iter().map(|k| b64_encode(k)).collect();
        let mut s = format!("{PREFIX}{}:{}", self.port, keys.join(","));
        if let Some(ip) = self.server {
            s.push_str(&format!(":{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
        }
        s
    }

    pub fn decode(code: &str) -> Result<Self, PairingError> {
        let rest = code.trim().strip_prefix(PREFIX).ok_or(PairingError::NotAPairingCode)?;
        let mut parts = rest.split(':');
        let port =
            parts.next().and_then(|p| p.parse().ok()).filter(|&p| p != 0).ok_or(PairingError::BadPort)?;
        let keys = parts
            .next()
            .ok_or(PairingError::BadKey)?
            .split(',')
            .map(|k| b64_decode(k).and_then(|v| v.try_into().ok()).ok_or(PairingError::BadKey))
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        if keys.is_empty() || keys.len() > crate::config::MAX_KEYS {
            return Err(PairingError::BadKey);
        }
        let server = match parts.next() {
            None => None,
            Some(ip) => Some(parse_ipv4(ip).ok_or(PairingError::BadAddress)?),
        };
        if parts.next().is_some() {
            return Err(PairingError::NotAPairingCode);
        }
        Ok(Self { port, keys, server })
    }
}

/// Short human-comparable fingerprint of a public key.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let h = Sha256::digest(key);
    format!(
        "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for b in &mut out {
        *b = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let vals: Vec<u32> =
        s.bytes().map(|c| ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)).collect::<Option<_>>()?;
    if vals.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &v)| acc | v << (18 - 6 * i));
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn code_round_trip() {
        let p = Pairing { port: 47000, keys: vec![[1; 32], [2; 32]], server: Some([10, 10, 0, 5]) };
        let code = p.encode();
        assert!(code.starts_with("netbooty-pair:1:47000:"));
        assert!(code.ends_with(":10.10.0.5"));
        assert_eq!(Pairing::decode(&code), Ok(p));
        let bare = Pairing { port: 1, keys: vec![[3; 32]], server: None };
        assert_eq!(Pairing::decode(&format!("  {}\n", bare.encode())), Ok(bare));
    }

    #[test]
    fn rejects_bad_codes() {
        assert_eq!(Pairing::decode("hello"), Err(PairingError::NotAPairingCode));
        assert_eq!(Pairing::decode("netbooty-pair:1:0:AAAA"), Err(PairingError::BadPort));
        assert_eq!(Pairing::decode("netbooty-pair:1:47000:AAAA"), Err(PairingError::BadKey));
        let good = Pairing { port: 47000, keys: vec![[1; 32]], server: None }.encode();
        assert_eq!(Pairing::decode(&format!("{good}:300.1.1.1")), Err(PairingError::BadAddress));
    }

    #[test]
    fn base64url() {
        assert_eq!(b64_encode(b"hello"), "aGVsbG8");
        assert_eq!(b64_decode("aGVsbG8").unwrap(), b"hello");
        for n in 0..40u8 {
            let data: Vec<u8> = (0..n).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        }
        assert!(b64_decode("a").is_none());
        assert!(b64_decode("a+b=").is_none());
    }

    #[test]
    fn fingerprint_is_stable() {
        let f = fingerprint(&[0; 32]);
        assert_eq!(f.len(), 19);
        assert_eq!(f, fingerprint(&[0; 32]));
        assert_ne!(f, fingerprint(&[1; 32]));
    }
}
