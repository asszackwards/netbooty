//! Interactive installer and configurator (`sudo netbooty-setup`).
//!
//! First run: detect the system, choose boot targets and menu behavior,
//! install, and guide through key enrollment, a one-time test and activation.
//! Later runs: show the current state and offer the next sensible step.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use netbooty_cfg::config::valid_name;
use netbooty_cfg::loadopt::{LoadOption, matches};

use crate::efivars::Store;
use crate::install::{self, ENTRY_LABEL, InstallOpts, KEY_DIR, Mode};
use crate::settings::{FallbackArg, MenuArg, NetworkSettings, ResetArg, SETTINGS_PATH, Settings};
use crate::spec::{self, Discovered, fmt_part};
use crate::system::{self, MokState, SecureBoot};

/// Preview mode: everything is asked and shown, nothing is changed.
static DRY: AtomicBool = AtomicBool::new(false);

fn dry() -> bool {
    DRY.load(Ordering::Relaxed)
}

fn opts() -> InstallOpts {
    InstallOpts { image: None, dry_run: dry(), interactive: true }
}

fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

/// Where the install stands, derived from the machine (not just settings).
struct State {
    sb: SecureBoot,
    mok: MokState,
    entry: Option<u16>,
    saved: Option<Settings>,
}

impl State {
    fn read(store: &Store) -> Result<Self> {
        let sb = system::secure_boot(store.dir());
        let (_, _, der) = install::key_paths(Path::new(KEY_DIR));
        let mok = if der.exists() { system::mok_state(&der) } else { MokState::NotEnrolled };
        let entry = store
            .boot_entries()?
            .into_iter()
            .find(|(_, o)| o.description == ENTRY_LABEL && install::is_netbooty_entry(o))
            .map(|(n, _)| n);
        Ok(Self { sb, mok, entry, saved: Settings::load()? })
    }

    /// Shim mode under Secure Boot needs the MOK before NetBooty can run.
    fn key_ready(&self) -> bool {
        let shim = self.saved.as_ref().is_none_or(|s| s.mode == Mode::Shim);
        !(shim && self.sb == SecureBoot::Enabled) || self.mok == MokState::Enrolled
    }
}

pub fn run(dry_run: bool) -> Result<()> {
    DRY.store(dry_run, Ordering::Relaxed);
    println!("NetBooty setup{}\n", if dry_run { " (preview: nothing will be changed)" } else { "" });
    let store = Store::new(None);
    if !store.dir().is_dir() {
        bail!("this system did not boot in UEFI mode; NetBooty needs UEFI");
    }
    if !dry_run && !system::is_root() {
        bail!("setup changes firmware boot settings; run it as root: sudo netbooty-setup");
    }

    loop {
        let st = State::read(&store)?;
        print_state(&st, &store);
        let Some(saved) = st.saved.clone() else {
            // An install from before settings were saved: start from its config.
            let legacy = legacy_settings(&store, st.entry);
            if legacy.is_some() {
                println!("Found an existing NetBooty install; its settings are the defaults below.\n");
            }
            if configure(&store, legacy.as_ref())? {
                after_install(&store)?;
            }
            return Ok(());
        };

        let mut actions: Vec<(&str, Action)> = Vec::new();
        if st.mok == MokState::Pending {
            actions.push(("Reboot now to enroll the signing key", Action::Reboot));
        }
        if !saved.first && st.entry.is_some() && st.key_ready() {
            actions.push(("Test NetBooty once (reboot into it now)", Action::Test));
            actions.push(("Make NetBooty the default boot entry", Action::Activate));
        }
        actions.push(("Change configuration", Action::Configure));
        actions.push(("Repair / reinstall with current settings", Action::Repair));
        actions.push(("Show detailed status", Action::Doctor));
        actions.push(("Uninstall NetBooty", Action::Uninstall));
        actions.push(("Quit", Action::Quit));

        let labels: Vec<&str> = actions.iter().map(|(l, _)| *l).collect();
        let pick = Select::with_theme(&theme())
            .with_prompt("What would you like to do?")
            .items(&labels)
            .default(0)
            .interact()?;
        match actions[pick].1 {
            Action::Reboot => return reboot(),
            Action::Test => return test_once(st.entry.unwrap()),
            Action::Activate => {
                let mut s = saved;
                s.first = true;
                install::install(&s, opts())?;
                println!("\nNetBooty is now the default. It will show its menu on every boot.");
                return Ok(());
            }
            Action::Configure => {
                if configure(&store, Some(&saved))? {
                    after_install(&store)?;
                }
                return Ok(());
            }
            Action::Repair => {
                install::install(&saved, opts())?;
            }
            Action::Doctor => install::doctor()?,
            Action::Uninstall => {
                if Confirm::with_theme(&theme())
                    .with_prompt("Remove NetBooty, its boot entry, files and services?")
                    .default(false)
                    .interact()?
                {
                    install::uninstall(None, dry())?;
                    return Ok(());
                }
            }
            Action::Quit => return Ok(()),
        }
        println!();
    }
}

#[derive(Clone, Copy)]
enum Action {
    Reboot,
    Test,
    Activate,
    Configure,
    Repair,
    Doctor,
    Uninstall,
    Quit,
}

fn print_state(st: &State, store: &Store) {
    println!("Secure Boot:  {:?}", st.sb);
    match &st.saved {
        None if st.entry.is_some() => {
            println!("NetBooty:     installed by an older version (no saved settings)")
        }
        None => println!("NetBooty:     not installed"),
        Some(s) => {
            let entry = st.entry.map_or("boot entry missing".into(), |n| format!("Boot{n:04X}"));
            let default = if s.first { "default boot entry" } else { "installed, not the default yet" };
            println!("NetBooty:     {default} ({entry})");
            let names: Vec<&str> = s
                .targets
                .iter()
                .filter_map(|t| t.split(',').find_map(|kv| kv.strip_prefix("name=")))
                .collect();
            println!("Targets:      {} (default {})", names.join(", "), s.default);
            let menu = match s.menu {
                MenuArg::Always => format!("always shown, {} s countdown", s.menu_timeout),
                MenuArg::OnKey => "only when a key is held at startup".into(),
            };
            println!("Menu:         {menu}");
        }
    }
    if st.sb == SecureBoot::Enabled {
        let mok = match st.mok {
            MokState::Enrolled => "enrolled",
            MokState::Pending => "waiting for enrollment at next boot",
            MokState::NotEnrolled => "not enrolled",
            MokState::Unknown => "unknown",
        };
        println!("Signing key:  {mok}");
    }
    if let Some(t) = store.pending_next() {
        println!("Pending:      next boot goes to {t}");
    }
    println!();
}

/// Settings equivalent to the config embedded in an installed NetBooty that
/// predates the settings file.
fn legacy_settings(store: &Store, entry: Option<u16>) -> Option<Settings> {
    let cfg = install::installed_config()?;
    let targets = cfg
        .targets
        .iter()
        .map(|t| {
            let mut kv = vec![format!("name={}", t.name)];
            if t.matching.path {
                kv.push(format!("path={}", t.loader_path));
            }
            if t.matching.description {
                kv.push(format!("desc={}", t.description));
            }
            if let Some(p) = t.partition.filter(|_| t.matching.partition) {
                kv.push(format!("part={}", fmt_part(&p)));
            }
            if let Some(h) = t.boot_num_hint {
                kv.push(format!("hint={h:04X}"));
            }
            if let Some(k) = t.hotkey {
                kv.push(format!("key={k}"));
            }
            kv.join(",")
        })
        .collect();
    Some(Settings {
        targets,
        default: cfg.default.map_or("exit".into(), |i| cfg.targets[i].name.clone()),
        menu: if cfg.menu_mode == netbooty_cfg::config::MenuMode::Always {
            MenuArg::Always
        } else {
            MenuArg::OnKey
        },
        menu_timeout: cfg.menu_timeout_s,
        reset: ResetArg::Warm,
        fallback: FallbackArg::Exit,
        no_reassert: false,
        client_id: None,
        mode: Mode::Auto,
        esp: None,
        shim: None,
        key: None,
        cert: None,
        first: entry.is_some() && store.boot_order().first() == entry.as_ref(),
        network: Default::default(),
    })
}

/// Name and hotkey a previous configuration gave to the entry `num`.
fn previous_target(
    previous: Option<&Settings>,
    store: &Store,
    entry: &LoadOption,
) -> Option<(String, Option<char>)> {
    let prev = previous?;
    prev.targets.iter().find_map(|spec| {
        let t = spec::parse_target(spec, &mut None, store).ok()?;
        matches(&t, entry).then(|| (t.name.clone(), t.hotkey))
    })
}

fn describe(d: &Discovered, entries: &[(u16, LoadOption)]) -> String {
    let o = entries.iter().find(|(n, _)| *n == d.boot_num).map(|(_, o)| o);
    let (desc, path, part) = o.map_or(("?".into(), String::new(), String::new()), |o| {
        (o.description.clone(), o.loader_path.clone(), o.partition.map(|p| fmt_part(&p)).unwrap_or_default())
    });
    let short_part: String = part.chars().take(8).collect();
    format!("{desc}  (Boot{:04X}: {path} on {short_part}…)", d.boot_num)
}

/// Ask for the configuration and install it. Returns false if cancelled.
fn configure(store: &Store, previous: Option<&Settings>) -> Result<bool> {
    let entries = store.boot_entries()?;
    let found = spec::discover(&entries);
    if found.is_empty() {
        bail!("no OS boot entries found in the firmware; `netbooty-setup doctor` shows what is there");
    }

    println!("Boot entries found in your firmware:");
    let labels: Vec<String> = found.iter().map(|d| describe(d, &entries)).collect();
    let entry_of = |d: &Discovered| &entries.iter().find(|(n, _)| *n == d.boot_num).unwrap().1;
    let prev: Vec<Option<(String, Option<char>)>> =
        found.iter().map(|d| previous_target(previous, store, entry_of(d))).collect();
    // Preselect what a previous configuration offered (everything otherwise).
    let preselect: Vec<bool> =
        prev.iter().map(|p| p.is_some() || previous.is_none() || prev.iter().all(Option::is_none)).collect();
    let picked = MultiSelect::with_theme(&theme())
        .with_prompt("Which should NetBooty offer? (space toggles, enter confirms)")
        .items(&labels)
        .defaults(&preselect)
        .interact()?;
    if picked.is_empty() {
        bail!("nothing selected");
    }

    let mut targets: Vec<(String, String)> = Vec::new(); // (name, spec)
    let mut used_keys: Vec<char> = Vec::new();
    for &i in &picked {
        let d = &found[i];
        let taken: Vec<String> = targets.iter().map(|(n, _)| n.clone()).collect();
        let name: String = Input::with_theme(&theme())
            .with_prompt(format!("Name for \"{}\"", labels[i].split("  (").next().unwrap_or("")))
            .default(prev[i].as_ref().map_or(d.name.clone(), |(n, _)| n.clone()))
            .validate_with(|s: &String| -> Result<(), String> {
                if !valid_name(s) {
                    Err("1-15 characters: letters, digits, - _ .".into())
                } else if taken.iter().any(|t| t.eq_ignore_ascii_case(s)) {
                    Err("already used".into())
                } else {
                    Ok(())
                }
            })
            .interact_text()?;
        let suggested = prev[i]
            .as_ref()
            .and_then(|(_, k)| *k)
            .or_else(|| name.chars().next().filter(|c| c.is_ascii_alphabetic()))
            .filter(|c| !used_keys.contains(c));
        let key: String = Input::with_theme(&theme())
            .with_prompt(format!("Menu key for {name} (empty for none)"))
            .default(suggested.map(String::from).unwrap_or_default())
            .allow_empty(true)
            .validate_with(|s: &String| -> Result<(), String> {
                let mut c = s.chars();
                match (c.next(), c.next()) {
                    (None, _) => Ok(()),
                    (Some(k), None)
                        if k.is_ascii_alphabetic() && !used_keys.contains(&k.to_ascii_lowercase()) =>
                    {
                        Ok(())
                    }
                    (Some(_), None) => Err("a letter not used by another target".into()),
                    _ => Err("one letter".into()),
                }
            })
            .interact_text()?;
        // Rebuild the spec with the chosen name and key; the boot entry
        // details come from discovery.
        let mut spec: Vec<String> = d
            .spec
            .split(',')
            .filter(|kv| !kv.starts_with("name=") && !kv.starts_with("key="))
            .map(String::from)
            .collect();
        spec.insert(0, format!("name={name}"));
        if let Some(k) = key.chars().next() {
            let k = k.to_ascii_lowercase();
            used_keys.push(k);
            spec.push(format!("key={k}"));
        }
        targets.push((name, spec.join(",")));
    }

    let current = store.boot_current();
    let mut choices: Vec<String> = targets.iter().map(|(n, _)| n.clone()).collect();
    choices.push("none: continue with the next firmware boot entry".into());
    let default_idx = previous
        .and_then(|p| targets.iter().position(|(n, _)| *n == p.default))
        .or_else(|| picked.iter().position(|&i| Some(found[i].boot_num) == current))
        .unwrap_or(0);
    let def = Select::with_theme(&theme())
        .with_prompt("Default when you don't choose")
        .items(&choices)
        .default(default_idx)
        .interact()?;
    let default = if def == targets.len() { "exit".to_string() } else { targets[def].0.clone() };

    let menu_idx = Select::with_theme(&theme())
        .with_prompt("When should the menu appear?")
        .items(["Every boot, with a countdown", "Only when I hold a key during startup"])
        .default(match previous.map(|p| p.menu) {
            Some(MenuArg::OnKey) => 1,
            _ => 0,
        })
        .interact()?;
    let menu = if menu_idx == 0 { MenuArg::Always } else { MenuArg::OnKey };
    let menu_timeout = if menu == MenuArg::Always {
        Input::<u16>::with_theme(&theme())
            .with_prompt("Countdown in seconds")
            .default(previous.map_or(10, |p| p.menu_timeout))
            .validate_with(|n: &u16| if (1..=600).contains(n) { Ok(()) } else { Err("1-600") })
            .interact_text()?
    } else {
        previous.map_or(10, |p| p.menu_timeout)
    };

    let network = ask_network(previous.map(|p| p.network.clone()).unwrap_or_default())?;
    let newly_paired = !network.keys.is_empty() && previous.is_none_or(|p| p.network.keys != network.keys);

    let s = Settings {
        targets: targets.into_iter().map(|(_, s)| s).collect(),
        default,
        menu,
        menu_timeout,
        reset: previous.map_or(ResetArg::Warm, |p| p.reset),
        fallback: previous.map_or(FallbackArg::Exit, |p| p.fallback),
        no_reassert: previous.is_some_and(|p| p.no_reassert),
        client_id: previous.and_then(|p| p.client_id.clone()),
        mode: previous.map_or(Mode::Auto, |p| p.mode),
        esp: previous.and_then(|p| p.esp.clone()),
        shim: previous.and_then(|p| p.shim.clone()),
        key: previous.and_then(|p| p.key.clone()),
        cert: previous.and_then(|p| p.cert.clone()),
        first: previous.is_some_and(|p| p.first),
        network,
    };

    println!("\nSettings to install (saved in {SETTINGS_PATH}):\n{}", s.to_toml()?);
    if !Confirm::with_theme(&theme()).with_prompt("Install now?").default(true).interact()? {
        println!("Cancelled; nothing was changed.");
        return Ok(false);
    }
    install::install(&s, opts())?;
    if newly_paired && !dry() {
        match crate::pair::announce(&s.network) {
            Ok(host) => println!("\nAnnounced as {host}: approve it on the server's web page (New PCs)."),
            Err(e) => println!("\nCould not announce ({e:#}); the PC will appear there after its next boot."),
        }
    }
    Ok(true)
}

/// Discover servers on the LAN and let the user confirm one by fingerprint.
/// Returns its pairing code (pointing at the address that answered).
pub fn pick_discovered(port: u16) -> Result<Option<String>> {
    println!("Looking for NetBooty servers on the LAN (UDP {port})...");
    let offers = crate::pair::discover(port, std::time::Duration::from_secs(2))?;
    if offers.is_empty() {
        println!("No server answered. Is it running, with host networking, and is UDP {port} allowed?");
        return Ok(None);
    }
    let labels: Vec<String> =
        offers.iter().map(|o| format!("{}  fingerprint {}", o.from, o.fingerprints())).collect();
    let pick = if offers.len() == 1 {
        println!("Found: {}", labels[0]);
        0
    } else {
        Select::with_theme(&theme()).with_prompt("Which server?").items(&labels).default(0).interact()?
    };
    let ok = Confirm::with_theme(&theme())
        .with_prompt("Does this fingerprint match the one on the server's web page?")
        .default(false)
        .interact()?;
    Ok(ok.then(|| offers[pick].code_for_source()))
}

/// The boot-server step: keep, change or add a pairing.
fn ask_network(mut n: NetworkSettings) -> Result<NetworkSettings> {
    let paired = !n.keys.is_empty();
    let mut choices = Vec::new();
    if paired {
        choices.push(format!("Keep the paired server (key {})", crate::pair::fingerprints(&n)));
    }
    choices.push(String::from("Find a NetBooty server on the LAN"));
    choices.push(String::from("Paste a pairing code"));
    choices.push(String::from(if paired {
        "Unpair (only report server replies)"
    } else {
        "No server for now"
    }));
    let pick = Select::with_theme(&theme())
        .with_prompt("Boot server (lets a server on your LAN choose the OS)")
        .items(&choices)
        .default(0)
        .interact()?;
    let offset = usize::from(!paired);
    match pick + offset {
        0 => {}
        1 => match pick_discovered(n.port)? {
            Some(code) => {
                crate::pair::apply(&code, &mut n)?;
            }
            None => println!("Keeping the current server setting."),
        },
        2 => loop {
            let code: String = Input::with_theme(&theme())
                .with_prompt("Paste the pairing code from the server's web page")
                .validate_with(|c: &String| -> Result<(), String> {
                    netbooty_cfg::pairing::Pairing::decode(c)
                        .map(|_| ())
                        .map_err(|_| "not a pairing code".into())
                })
                .interact_text()?;
            let mut candidate = n.clone();
            crate::pair::apply(&code, &mut candidate)?;
            println!("Server key fingerprint: {}", crate::pair::fingerprints(&candidate));
            if Confirm::with_theme(&theme())
                .with_prompt("Does it match the fingerprint shown on the server's web page?")
                .default(true)
                .interact()?
            {
                n = candidate;
                break;
            }
        },
        _ => crate::pair::unpair(&mut n),
    }
    n.enabled = true;
    Ok(n)
}

/// After installing: offer the reboot that the next step needs.
fn after_install(store: &Store) -> Result<()> {
    let st = State::read(store)?;
    println!();
    if st.mok == MokState::Pending {
        println!("The signing key is queued. On the next boot a blue MokManager screen appears:");
        println!("press a key within 10 seconds, then Enroll MOK -> Continue -> Yes, enter your");
        println!("password and Reboot. Afterwards run `sudo netbooty-setup` again to continue.");
        if Confirm::with_theme(&theme()).with_prompt("Reboot now?").default(false).interact()? {
            return reboot();
        }
    } else if st.saved.as_ref().is_some_and(|s| !s.first)
        && let Some(n) = st.entry
        && st.key_ready()
    {
        println!("Try NetBooty once before making it the default. If anything goes wrong your");
        println!("normal boot is untouched. Run `sudo netbooty-setup` afterwards to activate it.");
        if Confirm::with_theme(&theme())
            .with_prompt("Reboot into NetBooty once now?")
            .default(false)
            .interact()?
        {
            return test_once(n);
        }
    }
    Ok(())
}

fn test_once(entry: u16) -> Result<()> {
    if dry() {
        println!("[preview] would run: efibootmgr -n {entry:04X} && systemctl reboot");
        return Ok(());
    }
    let status = Command::new("efibootmgr").args(["-q", "-n", &format!("{entry:04X}")]).status()?;
    if !status.success() {
        bail!("efibootmgr -n failed");
    }
    println!("Next boot goes to NetBooty once. Rebooting...");
    reboot()
}

fn reboot() -> Result<()> {
    if dry() {
        println!("[preview] would reboot now");
        return Ok(());
    }
    let status = Command::new("systemctl").arg("reboot").status()?;
    if !status.success() {
        bail!("could not reboot; please reboot manually");
    }
    Ok(())
}
