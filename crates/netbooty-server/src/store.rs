//! On-disk layout and the JSON contract shared with the web app.
//!
//! ```text
//! <data>/key/current.seed   private Ed25519 seed (hex), responder only
//! <data>/key/next.seed      next seed during a key rotation
//! <data>/state/public.json  public keys, fingerprints, pairing code      written by: responder
//! <data>/state/state.json   approved PCs, choices, one-shots, dismissed  written by: web app / CLI
//! <data>/state/requests.json  pending pairing requests                  written by: responder
//! <data>/state/status.json  last seen / last answer / one-shot use       written by: responder
//! ```
//!
//! Every file has `"version": 1` and is replaced atomically (temp file +
//! rename), and each file has a single writer, so the web app never needs
//! the key and the two never overwrite each other's updates.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use netbooty_cfg::pairing::{Pairing, b64_encode, fingerprint};
use netbooty_cfg::proto;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
/// How long a consumed one-shot is still served, so every retry of the same
/// boot gets the same answer.
pub const ONCE_GRACE_SECS: u64 = 60;
pub const MAX_REQUESTS: usize = 32;
pub const REQUEST_TTL_SECS: u64 = 24 * 3600;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Once {
    /// Changes whenever a new one-shot is set, so its use can be tracked.
    pub id: String,
    pub target: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub name: String,
    #[serde(default)]
    pub targets: Vec<String>,
    /// Persistent choice; `None` = no preference (the PC boots its default).
    #[serde(default)]
    pub choice: Option<String>,
    #[serde(default)]
    pub once: Option<Once>,
}

/// Written by the web app / CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Approved PCs by client ID (hex).
    #[serde(default)]
    pub clients: BTreeMap<String, Client>,
    /// Pairing requests the user dismissed (client IDs).
    #[serde(default)]
    pub dismissed: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self { version: VERSION, clients: BTreeMap::new(), dismissed: Vec::new() }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub first_seen: u64,
    pub last_seen: u64,
    pub from: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
}

/// Written by the responder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requests {
    pub version: u32,
    #[serde(default)]
    pub requests: BTreeMap<String, Request>,
}

impl Default for Requests {
    fn default() -> Self {
        Self { version: VERSION, requests: BTreeMap::new() }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Served {
    pub id: String,
    pub at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStatus {
    pub last_seen: u64,
    pub from: String,
    /// Target name, or "" for no preference.
    pub last_answer: String,
    #[serde(default)]
    pub once_served: Option<Served>,
}

/// Written by the responder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub version: u32,
    #[serde(default)]
    pub clients: BTreeMap<String, ClientStatus>,
}

impl Default for Status {
    fn default() -> Self {
        Self { version: VERSION, clients: BTreeMap::new() }
    }
}

/// Written by the responder: everything public a PC needs to pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Public {
    pub version: u32,
    pub port: u16,
    pub server_ip: Option<String>,
    pub keys: Vec<String>,
    pub fingerprints: Vec<String>,
    pub pairing_code: String,
}

pub struct Store {
    pub data: PathBuf,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent dir")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut text = serde_json::to_vec_pretty(value)?;
    text.push(b'\n');
    write_atomic(path, &text)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Store {
    pub fn new(data: impl Into<PathBuf>) -> Self {
        Self { data: data.into() }
    }

    fn key_path(&self, name: &str) -> PathBuf {
        self.data.join("key").join(format!("{name}.seed"))
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.data.join("state").join(name)
    }

    pub fn seed(&self, name: &str) -> Result<Option<[u8; 32]>> {
        match fs::read_to_string(self.key_path(name)) {
            Ok(t) => {
                unhex(&t).map(Some).with_context(|| format!("bad key file {}", self.key_path(name).display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.key_path(name).display())),
        }
    }

    /// The signing seed (current key).
    pub fn signing_seed(&self) -> Result<[u8; 32]> {
        self.seed("current")?.context("no key yet; run `netbooty-server keygen`")
    }

    pub fn write_seed(&self, name: &str, seed: &[u8; 32]) -> Result<()> {
        let dir = self.data.join("key");
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let path = self.key_path(name);
        write_atomic(&path, format!("{}\n", hex(seed)).as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn remove_seed(&self, name: &str) -> Result<()> {
        match fs::remove_file(self.key_path(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Public keys: current first, then next.
    pub fn public_keys(&self) -> Result<Vec<[u8; 32]>> {
        let mut keys = Vec::new();
        for name in ["current", "next"] {
            if let Some(seed) = self.seed(name)? {
                keys.push(proto::public_key(&seed));
            }
        }
        Ok(keys)
    }

    pub fn publish(&self, port: u16, server_ip: Option<[u8; 4]>) -> Result<Public> {
        let keys = self.public_keys()?;
        if keys.is_empty() {
            bail!("no key yet; run `netbooty-server keygen`");
        }
        let code = Pairing { port, keys: keys.clone(), server: server_ip }.encode();
        let public = Public {
            version: VERSION,
            port,
            server_ip: server_ip.map(|ip| std::net::Ipv4Addr::from(ip).to_string()),
            keys: keys.iter().map(|k| b64_encode(k)).collect(),
            fingerprints: keys.iter().map(fingerprint).collect(),
            pairing_code: code,
        };
        write_json(&self.state_path("public.json"), &public)?;
        Ok(public)
    }

    pub fn state(&self) -> Result<State> {
        read_json(&self.state_path("state.json"))
    }

    pub fn save_state(&self, s: &State) -> Result<()> {
        write_json(&self.state_path("state.json"), s)
    }

    pub fn requests(&self) -> Result<Requests> {
        read_json(&self.state_path("requests.json"))
    }

    pub fn save_requests(&self, r: &Requests) -> Result<()> {
        write_json(&self.state_path("requests.json"), r)
    }

    pub fn status(&self) -> Result<Status> {
        read_json(&self.state_path("status.json"))
    }

    pub fn save_status(&self, s: &Status) -> Result<()> {
        write_json(&self.state_path("status.json"), s)
    }
}

/// What to answer `client`: the one-shot if it is unused (or was used less
/// than [`ONCE_GRACE_SECS`] ago), else the persistent choice. Returns the
/// answer and whether this use consumes the one-shot.
pub fn answer_for(
    client: &Client,
    status: Option<&ClientStatus>,
    now: u64,
) -> (Option<String>, Option<Served>) {
    if let Some(once) = &client.once {
        match status.and_then(|s| s.once_served.as_ref()).filter(|s| s.id == once.id) {
            None => return (Some(once.target.clone()), Some(Served { id: once.id.clone(), at: now })),
            Some(served) if now.saturating_sub(served.at) < ONCE_GRACE_SECS => {
                return (Some(once.target.clone()), None);
            }
            Some(_) => {}
        }
    }
    (client.choice.clone(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(choice: Option<&str>, once: Option<(&str, &str)>) -> Client {
        Client {
            name: "pc".into(),
            targets: vec!["windows".into(), "linux".into()],
            choice: choice.map(String::from),
            once: once.map(|(id, t)| Once { id: id.into(), target: t.into() }),
        }
    }

    #[test]
    fn once_is_used_once_with_grace() {
        let c = client(Some("linux"), Some(("a", "windows")));
        // First use consumes it.
        let (ans, served) = answer_for(&c, None, 1000);
        assert_eq!(ans.as_deref(), Some("windows"));
        let served = served.unwrap();
        let st = ClientStatus { once_served: Some(served), ..Default::default() };
        // Retries of the same boot still get it...
        assert_eq!(answer_for(&c, Some(&st), 1030), (Some("windows".into()), None));
        // ...a later boot gets the persistent choice.
        assert_eq!(answer_for(&c, Some(&st), 1100).0.as_deref(), Some("linux"));
        // A new one-shot (new id) is served again.
        let c2 = client(Some("linux"), Some(("b", "windows")));
        assert_eq!(answer_for(&c2, Some(&st), 1100).0.as_deref(), Some("windows"));
        // No choice = no preference.
        assert_eq!(answer_for(&client(None, None), None, 0).0, None);
    }

    #[test]
    fn files_round_trip_and_keys() {
        let dir = std::env::temp_dir().join(format!("nbs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        assert!(store.signing_seed().is_err());
        store.write_seed("current", &[3; 32]).unwrap();
        let public = store.publish(47000, Some([10, 0, 0, 5])).unwrap();
        assert_eq!(public.keys.len(), 1);
        assert!(public.pairing_code.ends_with(":10.0.0.5"));
        let decoded = Pairing::decode(&public.pairing_code).unwrap();
        assert_eq!(decoded.keys, vec![proto::public_key(&[3; 32])]);

        let mut s = State::default();
        s.clients.insert("00".repeat(16), client(Some("windows"), None));
        store.save_state(&s).unwrap();
        assert_eq!(store.state().unwrap(), s);
        let text = fs::read_to_string(dir.join("state/state.json")).unwrap();
        assert!(text.contains("\"version\": 1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("key/current.seed")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
