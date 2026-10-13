//! Host-side NetBooty tool: provisions the `.nbtycfg` section of a NetBooty
//! binary, installs it, and sets one-shot boot requests from a running OS.

mod efivars;
mod install;
mod pe;
mod system;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use netbooty_cfg::config::{
    Config, Fallback, MatchFlags, MenuMode, PartitionSig, ResetKind, Target, valid_name,
};
use netbooty_cfg::loadopt::{LoadOption, matches};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum MenuArg {
    OnKey,
    Always,
}

#[derive(Clone, Copy, ValueEnum)]
enum ResetArg {
    Warm,
    Cold,
}

#[derive(Clone, Copy, ValueEnum)]
enum FallbackArg {
    Exit,
    Chainload,
}

/// Configuration written into the `.nbtycfg` section.
#[derive(Args)]
struct ConfigArgs {
    /// Target spec: name=<n>[,path=<loader path>][,desc=<text>][,part=<guid>|auto][,hint=<hex>|auto][,key=<c>].
    /// `auto` fills the value from the matching Boot#### entry on this machine.
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    /// Target name to boot when nothing else decides, or `exit`.
    #[arg(long, default_value = "exit")]
    default: String,
    #[arg(long, value_enum, default_value = "on-key")]
    menu: MenuArg,
    #[arg(long, default_value_t = 5)]
    menu_timeout: u16,
    #[arg(long, value_enum, default_value = "warm")]
    reset: ResetArg,
    #[arg(long, value_enum, default_value = "exit")]
    fallback: FallbackArg,
    /// Do not move NetBooty back to the front of BootOrder on each boot.
    #[arg(long)]
    no_reassert: bool,
    /// 32 hex digits; default keeps the existing ID or generates a new one.
    #[arg(long)]
    client_id: Option<String>,
    /// Directory with efivarfs-style files (default /sys/firmware/efi/efivars).
    #[arg(long)]
    efivars: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a configuration into a NetBooty binary (before signing).
    Patch {
        #[command(flatten)]
        cfg: ConfigArgs,
        input: PathBuf,
        output: PathBuf,
    },
    /// Print the configuration embedded in a NetBooty binary.
    Show { file: PathBuf },
    /// Ask NetBooty to boot <target> once on the next boot (`clear` cancels).
    Next {
        target: String,
        #[arg(long)]
        efivars: Option<PathBuf>,
    },
    /// Create a dedicated Secure Boot signing key (MOK) for NetBooty.
    Keygen {
        #[arg(long, default_value = install::KEY_DIR)]
        dir: PathBuf,
    },
    /// Configure, sign and install NetBooty to the ESP and create its boot entry.
    /// Does not make it the default unless --first is given.
    Install {
        #[command(flatten)]
        cfg: ConfigArgs,
        /// Unprovisioned netbooty.efi to install.
        #[arg(long)]
        image: PathBuf,
        /// Mount point of the ESP to install to (default: auto-detect).
        #[arg(long)]
        esp: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "auto")]
        mode: install::Mode,
        /// ESP-relative distro shim to copy, e.g. \EFI\ubuntu\shimx64.efi (default: auto-detect).
        #[arg(long)]
        shim: Option<String>,
        /// Signing key and certificate (default: the keygen key for shim mode).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Put NetBooty first in BootOrder (refused while its key is not enrolled).
        #[arg(long)]
        first: bool,
        /// Show what would be done without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Update NetBooty's copy of shim and MokManager from the distro's shim.
    RefreshShim {
        #[arg(long)]
        esp: Option<PathBuf>,
        /// ESP-relative distro shim to copy (default: auto-detect).
        #[arg(long)]
        shim: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove NetBooty's boot entry and files from the ESP.
    Uninstall {
        #[arg(long)]
        esp: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Read-only report of firmware, boot entries, ESPs and NetBooty state.
    Doctor,
}

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
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
fn parse_guid(s: &str) -> Result<[u8; 16]> {
    let b: [u8; 16] = parse_hex(s)?;
    let mut g = b;
    g[..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    g[4..6].copy_from_slice(&[b[5], b[4]]);
    g[6..8].copy_from_slice(&[b[7], b[6]]);
    Ok(g)
}

fn fmt_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

pub(crate) fn fmt_part(p: &PartitionSig) -> String {
    match p.sig_type {
        2 => fmt_guid(&p.sig),
        _ => format!("mbr:{:02x}{:02x}{:02x}{:02x}", p.sig[3], p.sig[2], p.sig[1], p.sig[0]),
    }
}

fn parse_target(
    spec: &str,
    entries: &mut Option<Vec<(u16, LoadOption)>>,
    efivars: &efivars::Store,
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
        // NetBooty's own entry can share loader and partition with a target
        // (shim chaining), so it is never a candidate.
        let found: Vec<_> =
            entries.iter().filter(|(_, o)| !install::is_netbooty_entry(o) && matches(&t, o)).collect();
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

fn print_config(c: &Config) {
    println!("provisioned:   {}", c.provisioned);
    println!("client id:     {}", c.client_id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("default:       {}", c.default.map_or("exit", |i| c.targets[i].name.as_str()));
    println!("menu:          {:?}, {}s", c.menu_mode, c.menu_timeout_s);
    println!(
        "reset:         {:?}; fallback {:?}; reassert BootOrder {}",
        c.reset, c.fallback, c.reassert_bootorder
    );
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

fn build_config(a: &ConfigArgs, existing: Option<&Config>) -> Result<Config> {
    let store = efivars::Store::new(a.efivars.clone());
    let mut entries = None;
    let targets =
        a.targets.iter().map(|s| parse_target(s, &mut entries, &store)).collect::<Result<Vec<_>>>()?;
    let mut cfg = Config {
        provisioned: true,
        targets,
        menu_mode: match a.menu {
            MenuArg::OnKey => MenuMode::OnKey,
            MenuArg::Always => MenuMode::Always,
        },
        menu_timeout_s: a.menu_timeout,
        reset: match a.reset {
            ResetArg::Warm => ResetKind::Warm,
            ResetArg::Cold => ResetKind::Cold,
        },
        fallback: match a.fallback {
            FallbackArg::Exit => Fallback::Exit,
            FallbackArg::Chainload => Fallback::Chainload,
        },
        reassert_bootorder: !a.no_reassert,
        ..Config::default()
    };
    cfg.default = match a.default.as_str() {
        "exit" => None,
        name => Some(cfg.target_index(name).with_context(|| format!("default {name:?} is not a target"))?),
    };
    cfg.client_id = match &a.client_id {
        Some(s) => parse_hex(s)?,
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

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Patch { cfg, input, output } => {
            let mut image = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let current = pe::read_config(&image)?;
            let cfg = build_config(&cfg, Some(&current))?;
            let bytes = cfg.encode().map_err(|e| anyhow::anyhow!("invalid config: {e:?}"))?;
            pe::write_config(&mut image, &bytes)?;
            std::fs::write(&output, &image).with_context(|| format!("writing {}", output.display()))?;
            print_config(&cfg);
            println!("wrote {}", output.display());
        }
        Cmd::Show { file } => print_config(&pe::read_config(&std::fs::read(&file)?)?),
        Cmd::Next { target, efivars } => {
            let store = efivars::Store::new(efivars);
            if target == "clear" {
                store.delete_next()?;
                println!("cleared pending request");
            } else {
                store.set_next(&target)?;
                println!("NetBooty will boot {target} on the next boot");
            }
        }
        Cmd::Keygen { dir } => install::keygen(&dir)?,
        Cmd::Install { cfg, image, esp, mode, shim, key, cert, first, dry_run } => {
            let opts = install::InstallOpts { image, esp, mode, shim, key, cert, first, dry_run };
            install::install(opts, |existing, first| {
                let mut c = build_config(&cfg, existing)?;
                // Until NetBooty is the default, it must not promote itself
                // when started through a one-shot BootNext test.
                c.reassert_bootorder &= first;
                print_config(&c);
                Ok(c)
            })?;
        }
        Cmd::RefreshShim { esp, shim, dry_run } => install::refresh_shim(esp, shim, dry_run)?,
        Cmd::Uninstall { esp, dry_run } => install::uninstall(esp, dry_run)?,
        Cmd::Doctor => install::doctor()?,
    }
    Ok(())
}
