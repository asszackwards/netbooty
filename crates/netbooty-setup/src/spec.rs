//! Target specs (`name=...,path=...`), building the `.nbtycfg` config from
//! saved settings, and discovering targets from the firmware's boot entries.

use anyhow::{Context, Result, bail};
use netbooty_cfg::config::{
    Config, Fallback, MatchFlags, MenuMode, NAME_LEN, PartitionSig, ResetKind, Target, valid_name,
};
use netbooty_cfg::loadopt::{LoadOption, matches};

use crate::efivars::Store;
use crate::install::is_netbooty_entry;
use crate::settings::{FallbackArg, MenuArg, ResetArg, Settings};

pub fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s: String = s.chars().filter(|c| *c != '-').collect();
    if s.len() != N * 2 {
        bail!("expected {} hex digits, got {:?}", N * 2, s);
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).context("bad hex")?;
    }
    Ok(out)
}

/// GUID text -> on-disk mixed-endian bytes.
pub fn parse_guid(s: &str) -> Result<[u8; 16]> {
    let b: [u8; 16] = parse_hex(s)?;
    let mut g = b;
    g[..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    g[4..6].copy_from_slice(&[b[5], b[4]]);
    g[6..8].copy_from_slice(&[b[7], b[6]]);
    Ok(g)
}

pub fn fmt_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

pub fn fmt_part(p: &PartitionSig) -> String {
    match p.sig_type {
        2 => fmt_guid(&p.sig),
        _ => format!("mbr:{:02x}{:02x}{:02x}{:02x}", p.sig[3], p.sig[2], p.sig[1], p.sig[0]),
    }
}

/// Parse one `--target` spec. `part=auto` / `hint=auto` are filled from the
/// matching `Boot####` entry, read lazily into `entries`.
pub fn parse_target(
    spec: &str,
    entries: &mut Option<Vec<(u16, LoadOption)>>,
    efivars: &Store,
) -> Result<Target> {
    let mut t = Target {
        name: String::new(),
        hotkey: None,
        matching: MatchFlags::default(),
        boot_num_hint: None,
        partition: None,
        description: String::new(),
        loader_path: String::new(),
    };
    let (mut auto_part, mut auto_hint) = (false, false);
    for kv in spec.split(',') {
        let (k, v) = kv.split_once('=').with_context(|| format!("bad target field {kv:?}"))?;
        match k {
            "name" => t.name = v.to_string(),
            "path" => {
                t.loader_path = v.replace('/', "\\");
                t.matching.path = true;
            }
            "desc" => {
                t.description = v.to_string();
                t.matching.description = true;
            }
            "part" if v == "auto" => auto_part = true,
            "part" => {
                t.partition = Some(PartitionSig { sig_type: 2, sig: parse_guid(v)? });
                t.matching.partition = true;
            }
            "hint" if v == "auto" => auto_hint = true,
            "hint" => t.boot_num_hint = Some(u16::from_str_radix(v, 16).context("bad hint")?),
            "key" => {
                let mut c = v.chars();
                t.hotkey = Some(c.next().context("empty key")?.to_ascii_lowercase());
                if c.next().is_some() {
                    bail!("key must be one character");
                }
            }
            _ => bail!("unknown target field {k:?}"),
        }
    }
    if !valid_name(&t.name) {
        bail!("target name {:?} must be 1-15 chars of [A-Za-z0-9._-]", t.name);
    }
    if !t.matching.any() {
        bail!("target {}: give at least one of path=, desc=, part=", t.name);
    }

    if auto_part || auto_hint {
        let entries = match entries {
            Some(e) => e,
            None => entries.insert(efivars.boot_entries()?),
        };
        // NetBooty's own entry is never a candidate.
        let found: Vec<_> = entries.iter().filter(|(_, o)| !is_netbooty_entry(o) && matches(&t, o)).collect();
        let (num, opt) = match found.as_slice() {
            [one] => *one,
            [] => bail!("target {}: no Boot#### entry matches", t.name),
            many => bail!(
                "target {}: {} entries match ({}); narrow it with path=/desc=/part=",
                t.name,
                many.len(),
                many.iter().map(|(n, _)| format!("Boot{n:04X}")).collect::<Vec<_>>().join(", ")
            ),
        };
        if auto_hint {
            t.boot_num_hint = Some(*num);
        }
        if auto_part {
            t.partition =
                Some(opt.partition.with_context(|| format!("Boot{num:04X} has no partition node"))?);
            t.matching.partition = true;
        }
    }
    Ok(t)
}

/// A boot target discovered from the firmware's entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    pub name: String,
    pub boot_num: u16,
    pub spec: String,
}

fn is_fallback_path(path: &str) -> bool {
    path.replace('/', "\\").to_ascii_lowercase().trim_start_matches('\\').starts_with("efi\\boot\\")
}

/// Short target name for an entry: first word of its description, or the
/// vendor directory of its loader (`\EFI\fedora\...` -> `fedora`).
fn base_name(o: &LoadOption, num: u16) -> String {
    let generic = ["uefi", "efi", "boot", "os", "linux", "manager", "the"];
    let word = o
        .description
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .find(|w| !w.is_empty() && !generic.contains(&w.as_str()));
    let vendor_dir = || {
        let p = o.loader_path.replace('/', "\\");
        let mut parts = p.trim_start_matches('\\').split('\\');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(efi), Some(dir), Some(_))
                if efi.eq_ignore_ascii_case("efi") && !dir.eq_ignore_ascii_case("boot") =>
            {
                Some(dir.to_ascii_lowercase())
            }
            _ => None,
        }
    };
    let name: String = word
        .or_else(vendor_dir)
        .unwrap_or_else(|| format!("entry{num:04x}"))
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(NAME_LEN - 3)
        .collect();
    if name.is_empty() { format!("entry{num:04x}") } else { name }
}

/// Bootable OS entries on disk partitions, excluding NetBooty itself and
/// removable-media fallback paths (`\EFI\BOOT\...`) on partitions that also
/// have a proper OS entry.
pub fn discover(entries: &[(u16, LoadOption)]) -> Vec<Discovered> {
    let candidates: Vec<&(u16, LoadOption)> = entries
        .iter()
        .filter(|(_, o)| {
            o.active()
                && !is_netbooty_entry(o)
                && o.partition.is_some()
                && o.loader_path.to_ascii_lowercase().ends_with(".efi")
        })
        .collect();
    let mut out: Vec<Discovered> = Vec::new();
    let mut keys = Vec::new();
    for &&(num, ref o) in &candidates {
        if is_fallback_path(&o.loader_path)
            && candidates
                .iter()
                .any(|(n, x)| *n != num && x.partition == o.partition && !is_fallback_path(&x.loader_path))
        {
            continue;
        }
        let base = base_name(o, num);
        let mut name = base.clone();
        let mut i = 2;
        while out.iter().any(|d| d.name == name) {
            name = format!("{base}-{i}");
            i += 1;
        }
        let mut spec = format!(
            "name={name},path={},part={},hint={num:04X}",
            o.loader_path,
            fmt_part(&o.partition.unwrap())
        );
        if let Some(c) = name.chars().next().filter(|c| c.is_ascii_alphabetic() && !keys.contains(c)) {
            keys.push(c);
            spec.push_str(&format!(",key={c}"));
        }
        out.push(Discovered { name, boot_num: num, spec });
    }
    out
}

pub fn print_config(c: &Config) {
    println!("provisioned:   {}", c.provisioned);
    println!("client id:     {}", c.client_id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("default:       {}", c.default.map_or("exit", |i| c.targets[i].name.as_str()));
    println!("menu:          {:?}, {}s", c.menu_mode, c.menu_timeout_s);
    println!(
        "reset:         {:?}; fallback {:?}; reassert BootOrder {}",
        c.reset, c.fallback, c.reassert_bootorder
    );
    if c.network {
        let server = c.server_ip.map_or("broadcast only".into(), |ip| {
            format!("broadcast + {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        });
        println!("network:       port {}, {server}, {} ms, {} retries", c.port, c.net_timeout_ms, c.retries);
    } else {
        println!("network:       off");
    }
    for t in &c.targets {
        let mut rules = Vec::new();
        if t.matching.path {
            rules.push(format!("path={}", t.loader_path));
        }
        if t.matching.description {
            rules.push(format!("desc={}", t.description));
        }
        if let Some(p) = t.partition.filter(|_| t.matching.partition) {
            rules.push(format!("part={}", fmt_part(&p)));
        }
        if let Some(h) = t.boot_num_hint {
            rules.push(format!("hint={h:04X}"));
        }
        if let Some(k) = t.hotkey {
            rules.push(format!("key={k}"));
        }
        println!("target {:<15} {}", t.name, rules.join(" "));
    }
}

/// The `.nbtycfg` contents for `s`, keeping `existing`'s client ID.
pub fn build_config(s: &Settings, existing: Option<&Config>, efivars: &Store) -> Result<Config> {
    let mut entries = None;
    let targets =
        s.targets.iter().map(|t| parse_target(t, &mut entries, efivars)).collect::<Result<Vec<_>>>()?;
    let mut cfg = Config {
        provisioned: true,
        targets,
        menu_mode: match s.menu {
            MenuArg::OnKey => MenuMode::OnKey,
            MenuArg::Always => MenuMode::Always,
        },
        menu_timeout_s: s.menu_timeout,
        reset: match s.reset {
            ResetArg::Warm => ResetKind::Warm,
            ResetArg::Cold => ResetKind::Cold,
        },
        fallback: match s.fallback {
            FallbackArg::Exit => Fallback::Exit,
            FallbackArg::Chainload => Fallback::Chainload,
        },
        reassert_bootorder: !s.no_reassert,
        network: s.network.enabled,
        port: s.network.port,
        server_ip: s.network.server.map(|ip| ip.octets()),
        net_timeout_ms: s.network.timeout_ms,
        retries: s.network.retries,
        ..Config::default()
    };
    cfg.default = match s.default.as_str() {
        "exit" => None,
        name => Some(cfg.target_index(name).with_context(|| format!("default {name:?} is not a target"))?),
    };
    cfg.client_id = match &s.client_id {
        Some(id) => parse_hex(id)?,
        None => match existing {
            Some(c) if c.provisioned && c.client_id != [0; 16] => c.client_id,
            _ => {
                let mut id = [0u8; 16];
                getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
                id
            }
        },
    };
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netbooty_cfg::loadopt::build;

    fn entry(desc: &str, part: u8, path: &str) -> LoadOption {
        let mut fpl = build::hd_node(1, 2048, 1 << 20, 2, [part; 16]);
        fpl.extend(build::file_node(path));
        fpl.extend(build::end_node());
        LoadOption::parse(&build::load_option(1, desc, &fpl, b"")).unwrap()
    }

    #[test]
    fn discovers_os_entries() {
        let entries = vec![
            (0x0000, entry("Windows Boot Manager", 1, "\\EFI\\Microsoft\\Boot\\bootmgfw.efi")),
            (0x0001, entry("NetBooty", 2, "\\EFI\\netbooty\\shimx64.efi")),
            (0x0003, entry("ubuntu", 2, "\\EFI\\ubuntu\\shimx64.efi")),
            // Firmware-added fallback entry on a disk that has a real OS entry.
            (0x0004, entry("UEFI OS", 2, "\\EFI\\BOOT\\BOOTX64.EFI")),
            // Fallback-only disk is kept, named after nothing useful.
            (0x0005, entry("UEFI OS", 3, "\\EFI\\BOOT\\BOOTX64.EFI")),
            (0x0006, entry("Fedora Linux", 4, "\\EFI\\fedora\\shimx64.efi")),
            (0x0007, entry("Linux Boot Manager", 4, "\\EFI\\systemd\\systemd-bootx64.efi")),
        ];
        let d = discover(&entries);
        let names: Vec<&str> = d.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["windows", "ubuntu", "entry0005", "fedora", "systemd"]);
        assert!(d[0].spec.contains("path=\\EFI\\Microsoft\\Boot\\bootmgfw.efi"));
        assert!(d[0].spec.contains("hint=0000") && d[0].spec.contains("key=w"));
        assert!(d[1].spec.contains("key=u"));
        assert!(d[2].spec.contains("key=e"));
        assert!(d[4].spec.contains("key=s"));
        // Specs parse back into valid targets.
        let store = Store::new(Some("/nonexistent".into()));
        for x in &d {
            parse_target(&x.spec, &mut None, &store).unwrap();
        }
    }

    #[test]
    fn duplicate_names_get_suffixes() {
        let entries = vec![
            (1, entry("ubuntu", 1, "\\EFI\\ubuntu\\shimx64.efi")),
            (2, entry("ubuntu", 2, "\\EFI\\ubuntu\\shimx64.efi")),
        ];
        let names: Vec<String> = discover(&entries).into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["ubuntu", "ubuntu-2"]);
    }
}
