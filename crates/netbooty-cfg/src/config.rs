//! The `.nbtycfg` section: a fixed-size, versioned, little-endian byte layout.
//!
//! The selector embeds a placeholder copy of this section; `netbooty-setup patch`
//! overwrites it in place (no size change) before the binary is signed.
//! Encoding is explicit (offsets below) rather than `#[repr(C)]` so the host
//! and UEFI builds can never disagree about padding.

use alloc::string::String;
use alloc::vec::Vec;

pub const SECTION_NAME: &str = ".nbtycfg";
pub const SIZE: usize = 2048;
pub const MAGIC: [u8; 8] = *b"NBTYCFG1";
pub const VERSION: u16 = 1;

pub const MAX_TARGETS: usize = 8;
pub const MAX_KEYS: usize = 2;
pub const NAME_LEN: usize = 16;
pub const DESC_LEN: usize = 60;
pub const PATH_LEN: usize = 128;

const FLAG_PROVISIONED: u16 = 1 << 0;

// Header offsets.
const O_MAGIC: usize = 0;
const O_VERSION: usize = 8;
const O_FLAGS: usize = 10;
const O_KEY_COUNT: usize = 12;
const O_DEFAULT: usize = 13;
const O_MENU_MODE: usize = 14;
const O_RESET_TYPE: usize = 15;
const O_FALLBACK: usize = 16;
const O_REASSERT: usize = 17;
const O_TARGET_COUNT: usize = 18;
const O_RETRIES: usize = 19;
const O_MENU_TIMEOUT: usize = 20;
const O_NET_TIMEOUT: usize = 22;
const O_PORT: usize = 24;
const O_SERVER_IP: usize = 28;
const O_CLIENT_ID: usize = 32;
const O_KEYS: usize = 48;
const O_TARGETS: usize = 128;

// Per-target offsets (relative to the target's start).
const TARGET_SIZE: usize = 224;
const T_NAME: usize = 0;
const T_HOTKEY: usize = 16;
const T_MATCH: usize = 17;
const T_HINT: usize = 18;
const T_PART_SIG_TYPE: usize = 20;
const T_PART_SIG: usize = 24;
const T_DESC: usize = 40;
const T_PATH: usize = 100;

const _: () = assert!(O_KEYS + MAX_KEYS * 32 <= O_TARGETS);
const _: () = assert!(T_PATH + PATH_LEN - 4 <= TARGET_SIZE);
const _: () = assert!(O_TARGETS + MAX_TARGETS * TARGET_SIZE <= SIZE);

pub const DEFAULT_EXIT: u8 = 0xFF;
pub const NO_HINT: u16 = 0xFFFF;
pub const DEFAULT_PORT: u16 = 47000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuMode {
    /// Show the menu only when a key is held at startup.
    OnKey,
    /// Always show the menu with a countdown.
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetKind {
    Warm,
    Cold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Return to firmware so it continues with the next BootOrder entry.
    Exit,
    /// LoadImage/StartImage the target directly (does not keep PCRs pristine).
    Chainload,
}

/// Which fields of a [`Target`] must match a `Boot####` entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchFlags {
    pub path: bool,
    pub description: bool,
    pub partition: bool,
}

impl MatchFlags {
    fn to_byte(self) -> u8 {
        self.path as u8 | (self.description as u8) << 1 | (self.partition as u8) << 2
    }
    fn from_byte(b: u8) -> Self {
        Self { path: b & 1 != 0, description: b & 2 != 0, partition: b & 4 != 0 }
    }
    pub fn any(self) -> bool {
        self.path || self.description || self.partition
    }
}

/// Partition identity taken from a hard-drive device path node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionSig {
    /// 1 = MBR (first 4 bytes of `sig` used), 2 = GPT.
    pub sig_type: u8,
    pub sig: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub hotkey: Option<char>,
    pub matching: MatchFlags,
    pub boot_num_hint: Option<u16>,
    pub partition: Option<PartitionSig>,
    pub description: String,
    pub loader_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub provisioned: bool,
    pub keys: Vec<[u8; 32]>,
    /// Index into `targets`, or `None` for "exit to firmware".
    pub default: Option<usize>,
    pub menu_mode: MenuMode,
    pub menu_timeout_s: u16,
    pub reset: ResetKind,
    pub fallback: Fallback,
    pub reassert_bootorder: bool,
    pub retries: u8,
    pub net_timeout_ms: u16,
    pub port: u16,
    /// `None` = broadcast only.
    pub server_ip: Option<[u8; 4]>,
    pub client_id: [u8; 16],
    pub targets: Vec<Target>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provisioned: false,
            keys: Vec::new(),
            default: None,
            menu_mode: MenuMode::OnKey,
            menu_timeout_s: 5,
            reset: ResetKind::Warm,
            fallback: Fallback::Exit,
            reassert_bootorder: true,
            retries: 2,
            net_timeout_ms: 2000,
            port: DEFAULT_PORT,
            server_ip: None,
            client_id: [0; 16],
            targets: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    BadMagic,
    UnsupportedVersion(u16),
    TooManyTargets,
    TooManyKeys,
    BadDefault,
    /// A string field is too long, not valid UTF-8, or a name is empty/non-ASCII.
    BadString,
    DuplicateName,
}

/// The unprovisioned section compiled into the selector. Usable in a `static`.
pub const fn placeholder() -> [u8; SIZE] {
    let mut b = [0u8; SIZE];
    let mut i = 0;
    while i < 8 {
        b[O_MAGIC + i] = MAGIC[i];
        i += 1;
    }
    b[O_VERSION] = VERSION as u8;
    b[O_DEFAULT] = DEFAULT_EXIT;
    b
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn wr16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn rd_str(b: &[u8]) -> Result<String, ConfigError> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).map(String::from).map_err(|_| ConfigError::BadString)
}

fn wr_str(dst: &mut [u8], s: &str) -> Result<(), ConfigError> {
    // Keep at least one NUL so readers never depend on the field length.
    if s.len() >= dst.len() || s.as_bytes().contains(&0) {
        return Err(ConfigError::BadString);
    }
    dst[..s.len()].copy_from_slice(s.as_bytes());
    Ok(())
}

/// Target names are short ASCII identifiers; they appear in the protocol and in
/// the `NetBootyNext` variable.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < NAME_LEN
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
}

/// Encode a target name as the fixed-width wire/variable form.
pub fn name_bytes(name: &str) -> Option<[u8; NAME_LEN]> {
    if !valid_name(name) {
        return None;
    }
    let mut out = [0u8; NAME_LEN];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Some(out)
}

/// Decode the fixed-width form. All-zero decodes to `Some("")`.
pub fn name_from_bytes(b: &[u8]) -> Option<&str> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    if b[end..].iter().any(|&c| c != 0) {
        return None;
    }
    let s = core::str::from_utf8(&b[..end]).ok()?;
    (s.is_empty() || valid_name(s)).then_some(s)
}

impl Config {
    pub fn target_index(&self, name: &str) -> Option<usize> {
        self.targets.iter().position(|t| t.name.eq_ignore_ascii_case(name))
    }

    pub fn decode(b: &[u8; SIZE]) -> Result<Self, ConfigError> {
        if b[O_MAGIC..O_MAGIC + 8] != MAGIC {
            return Err(ConfigError::BadMagic);
        }
        let version = rd16(b, O_VERSION);
        if version != VERSION {
            return Err(ConfigError::UnsupportedVersion(version));
        }
        let flags = rd16(b, O_FLAGS);
        let key_count = b[O_KEY_COUNT] as usize;
        let target_count = b[O_TARGET_COUNT] as usize;
        if key_count > MAX_KEYS {
            return Err(ConfigError::TooManyKeys);
        }
        if target_count > MAX_TARGETS {
            return Err(ConfigError::TooManyTargets);
        }

        let keys = (0..key_count)
            .map(|i| {
                let o = O_KEYS + i * 32;
                b[o..o + 32].try_into().unwrap()
            })
            .collect();

        let mut targets = Vec::with_capacity(target_count);
        for i in 0..target_count {
            let t = &b[O_TARGETS + i * TARGET_SIZE..][..TARGET_SIZE];
            let name = rd_str(&t[T_NAME..T_NAME + NAME_LEN])?;
            if !valid_name(&name) {
                return Err(ConfigError::BadString);
            }
            let hint = rd16(t, T_HINT);
            let sig_type = t[T_PART_SIG_TYPE];
            targets.push(Target {
                name,
                hotkey: (t[T_HOTKEY] != 0).then(|| t[T_HOTKEY] as char),
                matching: MatchFlags::from_byte(t[T_MATCH]),
                boot_num_hint: (hint != NO_HINT).then_some(hint),
                partition: (sig_type != 0).then(|| PartitionSig {
                    sig_type,
                    sig: t[T_PART_SIG..T_PART_SIG + 16].try_into().unwrap(),
                }),
                description: rd_str(&t[T_DESC..T_DESC + DESC_LEN])?,
                loader_path: rd_str(&t[T_PATH..T_PATH + PATH_LEN - 4])?,
            });
        }

        let default = match b[O_DEFAULT] {
            DEFAULT_EXIT => None,
            i if (i as usize) < target_count => Some(i as usize),
            _ => return Err(ConfigError::BadDefault),
        };
        let ip: [u8; 4] = b[O_SERVER_IP..O_SERVER_IP + 4].try_into().unwrap();

        Ok(Self {
            provisioned: flags & FLAG_PROVISIONED != 0,
            keys,
            default,
            menu_mode: if b[O_MENU_MODE] == 1 { MenuMode::Always } else { MenuMode::OnKey },
            menu_timeout_s: rd16(b, O_MENU_TIMEOUT),
            reset: if b[O_RESET_TYPE] == 1 { ResetKind::Cold } else { ResetKind::Warm },
            fallback: if b[O_FALLBACK] == 1 { Fallback::Chainload } else { Fallback::Exit },
            reassert_bootorder: b[O_REASSERT] != 0,
            retries: b[O_RETRIES],
            net_timeout_ms: rd16(b, O_NET_TIMEOUT),
            port: rd16(b, O_PORT),
            server_ip: (ip != [0; 4]).then_some(ip),
            client_id: b[O_CLIENT_ID..O_CLIENT_ID + 16].try_into().unwrap(),
            targets,
        })
    }

    pub fn encode(&self) -> Result<[u8; SIZE], ConfigError> {
        if self.targets.len() > MAX_TARGETS {
            return Err(ConfigError::TooManyTargets);
        }
        if self.keys.len() > MAX_KEYS {
            return Err(ConfigError::TooManyKeys);
        }
        if matches!(self.default, Some(i) if i >= self.targets.len()) {
            return Err(ConfigError::BadDefault);
        }
        for (i, t) in self.targets.iter().enumerate() {
            if self.targets[..i].iter().any(|u| u.name.eq_ignore_ascii_case(&t.name)) {
                return Err(ConfigError::DuplicateName);
            }
        }

        let mut b = placeholder();
        wr16(&mut b, O_FLAGS, if self.provisioned { FLAG_PROVISIONED } else { 0 });
        b[O_KEY_COUNT] = self.keys.len() as u8;
        b[O_DEFAULT] = self.default.map_or(DEFAULT_EXIT, |i| i as u8);
        b[O_MENU_MODE] = (self.menu_mode == MenuMode::Always) as u8;
        b[O_RESET_TYPE] = (self.reset == ResetKind::Cold) as u8;
        b[O_FALLBACK] = (self.fallback == Fallback::Chainload) as u8;
        b[O_REASSERT] = self.reassert_bootorder as u8;
        b[O_TARGET_COUNT] = self.targets.len() as u8;
        b[O_RETRIES] = self.retries;
        wr16(&mut b, O_MENU_TIMEOUT, self.menu_timeout_s);
        wr16(&mut b, O_NET_TIMEOUT, self.net_timeout_ms);
        wr16(&mut b, O_PORT, self.port);
        b[O_SERVER_IP..O_SERVER_IP + 4].copy_from_slice(&self.server_ip.unwrap_or([0; 4]));
        b[O_CLIENT_ID..O_CLIENT_ID + 16].copy_from_slice(&self.client_id);
        for (i, k) in self.keys.iter().enumerate() {
            b[O_KEYS + i * 32..][..32].copy_from_slice(k);
        }

        for (i, t) in self.targets.iter().enumerate() {
            if !valid_name(&t.name) {
                return Err(ConfigError::BadString);
            }
            let tb = &mut b[O_TARGETS + i * TARGET_SIZE..][..TARGET_SIZE];
            wr_str(&mut tb[T_NAME..T_NAME + NAME_LEN], &t.name)?;
            tb[T_HOTKEY] = match t.hotkey {
                Some(c) if c.is_ascii_graphic() => c.to_ascii_lowercase() as u8,
                Some(_) => return Err(ConfigError::BadString),
                None => 0,
            };
            tb[T_MATCH] = t.matching.to_byte();
            wr16(tb, T_HINT, t.boot_num_hint.unwrap_or(NO_HINT));
            if let Some(p) = t.partition {
                tb[T_PART_SIG_TYPE] = p.sig_type;
                tb[T_PART_SIG..T_PART_SIG + 16].copy_from_slice(&p.sig);
            }
            wr_str(&mut tb[T_DESC..T_DESC + DESC_LEN], &t.description)?;
            wr_str(&mut tb[T_PATH..T_PATH + PATH_LEN - 4], &t.loader_path)?;
        }
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample() -> Config {
        Config {
            provisioned: true,
            keys: vec![[7; 32], [9; 32]],
            default: Some(1),
            menu_mode: MenuMode::Always,
            menu_timeout_s: 3,
            reset: ResetKind::Cold,
            fallback: Fallback::Chainload,
            reassert_bootorder: false,
            retries: 1,
            net_timeout_ms: 1500,
            port: 4242,
            server_ip: Some([192, 168, 1, 2]),
            client_id: [0xAB; 16],
            targets: vec![
                Target {
                    name: "windows".to_string(),
                    hotkey: Some('w'),
                    matching: MatchFlags { path: true, description: false, partition: true },
                    boot_num_hint: Some(0),
                    partition: Some(PartitionSig { sig_type: 2, sig: [3; 16] }),
                    description: String::new(),
                    loader_path: "\\EFI\\Microsoft\\Boot\\bootmgfw.efi".to_string(),
                },
                Target {
                    name: "linux".to_string(),
                    hotkey: None,
                    matching: MatchFlags { path: false, description: true, partition: false },
                    boot_num_hint: None,
                    partition: None,
                    description: "ubuntu".to_string(),
                    loader_path: String::new(),
                },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let c = sample();
        assert_eq!(Config::decode(&c.encode().unwrap()).unwrap(), c);
    }

    #[test]
    fn placeholder_decodes_as_unprovisioned() {
        let c = Config::decode(&placeholder()).unwrap();
        assert!(!c.provisioned);
        assert!(c.targets.is_empty());
        assert_eq!(c.default, None);
    }

    #[test]
    fn rejects_bad_input() {
        let mut b = placeholder();
        b[0] = b'X';
        assert_eq!(Config::decode(&b), Err(ConfigError::BadMagic));

        let mut c = sample();
        c.default = Some(5);
        assert_eq!(c.encode(), Err(ConfigError::BadDefault));

        let mut c = sample();
        c.targets[1].name = "WINDOWS".to_string();
        assert_eq!(c.encode(), Err(ConfigError::DuplicateName));

        let mut c = sample();
        c.targets[0].name = "has space".to_string();
        assert_eq!(c.encode(), Err(ConfigError::BadString));

        let mut b = sample().encode().unwrap();
        b[O_TARGET_COUNT] = 9;
        assert_eq!(Config::decode(&b), Err(ConfigError::TooManyTargets));
    }

    #[test]
    fn names() {
        assert_eq!(&name_bytes("linux").unwrap()[..6], b"linux\0");
        assert_eq!(name_from_bytes(&name_bytes("linux").unwrap()), Some("linux"));
        assert_eq!(name_from_bytes(&[0; 16]), Some(""));
        assert_eq!(name_from_bytes(b"lin\0ux\0\0\0\0\0\0\0\0\0\0"), None);
        assert!(name_bytes("0123456789abcdef").is_none());
    }
}
