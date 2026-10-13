//! NetBooty's LAN protocol (UDP).
//!
//! Request (37 bytes): `"NBTY1" ‖ client_id[16] ‖ nonce[16]`, broadcast and
//! optionally unicast to the server.
//! Reply (80 bytes): `target[16] ‖ signature[64]`, where the Ed25519
//! signature covers `"NBTY1-resp" ‖ client_id ‖ nonce ‖ target`. Replies are
//! verified (and acted on) from milestone 4; until then NetBooty only reports
//! them.

pub const MAGIC: &[u8; 5] = b"NBTY1";
pub const RESPONSE_CONTEXT: &[u8; 10] = b"NBTY1-resp";
pub const DEFAULT_PORT: u16 = crate::config::DEFAULT_PORT;
pub const REQUEST_LEN: usize = 37;
pub const REPLY_LEN: usize = 80;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let r = request(&[1; 16], &[2; 16]);
        assert_eq!(&r[..5], b"NBTY1");
        assert_eq!(parse_request(&r), Some(([1; 16], [2; 16])));
        assert_eq!(parse_request(&r[..36]), None);
        let mut bad = r;
        bad[0] = b'X';
        assert_eq!(parse_request(&bad), None);
    }
}
