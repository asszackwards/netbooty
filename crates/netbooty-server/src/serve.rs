//! The UDP responder.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use anyhow::{Context, Result};
use netbooty_cfg::proto;

use crate::store::{MAX_REQUESTS, REQUEST_TTL_SECS, Request, Store, answer_for, hex, now};

/// Datagrams accepted per source address per second; the rest are dropped.
const RATE_PER_SEC: u32 = 20;

struct RateLimit {
    seen: HashMap<IpAddr, (u64, u32)>,
}

impl RateLimit {
    fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        if self.seen.len() > 4096 {
            self.seen.retain(|_, (sec, _)| *sec == now);
        }
        let e = self.seen.entry(ip).or_insert((now, 0));
        if e.0 != now {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= RATE_PER_SEC
    }
}

/// `pairing_code` is handed to `netbooty-setup pair --discover` on request.
pub fn serve(store: &Store, bind: Ipv4Addr, port: u16, pairing_code: &str) -> Result<()> {
    let sock = UdpSocket::bind((bind, port)).with_context(|| format!("binding udp/{port}"))?;
    println!("listening on {bind}:{port}/udp");
    let mut rate = RateLimit { seen: HashMap::new() };
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("receive failed: {e}");
                continue;
            }
        };
        if !rate.allow(from.ip(), now()) {
            continue;
        }
        let data = &buf[..n];
        let result = if let Some((cid, nonce)) = proto::parse_request(data) {
            handle_request(store, &sock, from, &cid, &nonce)
        } else if data == proto::DISCOVER {
            println!("discovery request from {}", from.ip());
            sock.send_to(&proto::offer(pairing_code), from).map(|_| ()).context("sending offer")
        } else if let Some(a) = proto::parse_announce(data) {
            record_request(store, from, &a.client_id, Some(a.hostname), a.targets)
        } else {
            Ok(())
        };
        if let Err(e) = result {
            eprintln!("error handling {from}: {e:#}");
        }
    }
}

pub fn handle_request(
    store: &Store,
    sock: &UdpSocket,
    from: SocketAddr,
    cid: &[u8; 16],
    nonce: &[u8; 16],
) -> Result<()> {
    let id = hex(cid);
    let state = store.state()?;
    let Some(client) = state.clients.get(&id) else {
        return record_request(store, from, cid, None, Vec::new());
    };
    let now = now();
    let mut status = store.status()?;
    let entry = status.clients.entry(id).or_default();
    let (answer, served) = answer_for(client, Some(entry), now);
    let seed = store.signing_seed()?;
    let reply = match proto::sign_reply(&seed, cid, nonce, answer.as_deref()) {
        Some(r) => r,
        None => {
            eprintln!("{}: invalid target {:?} in state; answering no preference", client.name, answer);
            proto::sign_reply(&seed, cid, nonce, None).context("signing")?
        }
    };
    sock.send_to(&reply, from).with_context(|| format!("replying to {from}"))?;
    println!("answered {} ({}): {}", client.name, from.ip(), answer.as_deref().unwrap_or("no preference"));

    entry.last_seen = now;
    entry.from = from.ip().to_string();
    entry.last_answer = answer.unwrap_or_default();
    if let Some(s) = served {
        entry.once_served = Some(s);
    }
    store.save_status(&status)
}

/// Remember an unknown PC so it can be approved (unless dismissed).
pub fn record_request(
    store: &Store,
    from: SocketAddr,
    cid: &[u8; 16],
    hostname: Option<String>,
    targets: Vec<String>,
) -> Result<()> {
    let id = hex(cid);
    let state = store.state()?;
    if state.clients.contains_key(&id) || state.dismissed.contains(&id) {
        return Ok(());
    }
    let now = now();
    let mut reqs = store.requests()?;
    // Drop expired ones and those approved or dismissed meanwhile.
    reqs.requests.retain(|k, r| {
        now.saturating_sub(r.last_seen) < REQUEST_TTL_SECS
            && !state.clients.contains_key(k)
            && !state.dismissed.contains(k)
    });
    let is_new = !reqs.requests.contains_key(&id);
    if is_new && reqs.requests.len() >= MAX_REQUESTS {
        let oldest = reqs.requests.iter().min_by_key(|(_, r)| r.last_seen).map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            reqs.requests.remove(&k);
        }
    }
    let r =
        reqs.requests.entry(id.clone()).or_insert_with(|| Request { first_seen: now, ..Request::default() });
    r.last_seen = now;
    r.from = from.ip().to_string();
    if hostname.is_some() {
        r.hostname = hostname;
    }
    if !targets.is_empty() {
        r.targets = targets;
    }
    if is_new {
        println!("pairing request from {} (client {id})", from.ip());
    }
    store.save_requests(&reqs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Client, Once, State};
    use netbooty_cfg::pairing::Pairing;

    fn setup() -> (Store, UdpSocket, UdpSocket) {
        let dir = std::env::temp_dir().join(format!(
            "nbs-serve-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        store.write_seed("current", &[4; 32]).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        (store, server, client)
    }

    #[test]
    fn approved_pc_gets_signed_answer_and_once_is_consumed() {
        let (store, server, client) = setup();
        let cid = [7u8; 16];
        let mut st = State::default();
        st.clients.insert(
            hex(&cid),
            Client {
                name: "pc".into(),
                targets: vec!["windows".into(), "linux".into()],
                choice: Some("linux".into()),
                once: Some(Once { id: "x".into(), target: "windows".into() }),
                mac: None,
            },
        );
        store.save_state(&st).unwrap();
        let keys = store.public_keys().unwrap();

        let from = client.local_addr().unwrap();
        handle_request(&store, &server, from, &cid, &[1; 16]).unwrap();
        let mut buf = [0u8; 128];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(
            proto::verify(&buf[..n], &cid, &[[1; 16]], &keys),
            Some(proto::Reply::Target("windows".into()))
        );
        let status = store.status().unwrap();
        let s = &status.clients[&hex(&cid)];
        assert_eq!(s.last_answer, "windows");
        assert_eq!(s.once_served.as_ref().unwrap().id, "x");
        // A pairing code from this store verifies too.
        let code = store.publish(47000, None, false).unwrap().pairing_code;
        assert_eq!(Pairing::decode(&code).unwrap().keys, keys);
        let _ = std::fs::remove_dir_all(&store.data);
    }

    #[test]
    fn unknown_pc_becomes_pairing_request_without_answer() {
        let (store, server, client) = setup();
        let cid = [9u8; 16];
        let from = client.local_addr().unwrap();
        handle_request(&store, &server, from, &cid, &[1; 16]).unwrap();
        client.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        assert!(client.recv(&mut [0u8; 128]).is_err(), "unknown PCs get no answer");
        let reqs = store.requests().unwrap();
        assert!(reqs.requests.contains_key(&hex(&cid)));
        // Announce adds hostname and targets.
        record_request(&store, from, &cid, Some("zaqbox".into()), vec!["windows".into()]).unwrap();
        let r = &store.requests().unwrap().requests[&hex(&cid)];
        assert_eq!(r.hostname.as_deref(), Some("zaqbox"));
        assert_eq!(r.targets, ["windows"]);
        // Dismissed PCs are not recorded again.
        let mut st = State::default();
        st.dismissed.push(hex(&[8u8; 16]));
        store.save_state(&st).unwrap();
        record_request(&store, from, &[8u8; 16], None, Vec::new()).unwrap();
        assert!(!store.requests().unwrap().requests.contains_key(&hex(&[8u8; 16])));
        let _ = std::fs::remove_dir_all(&store.data);
    }

    #[test]
    fn rate_limit() {
        let mut r = RateLimit { seen: HashMap::new() };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!((0..RATE_PER_SEC).all(|_| r.allow(ip, 5)));
        assert!(!r.allow(ip, 5));
        assert!(r.allow(ip, 6));
    }
}
