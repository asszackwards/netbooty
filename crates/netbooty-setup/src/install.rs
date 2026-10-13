//! `keygen`, `install`, `uninstall` and `doctor`.
//!
//! Install is deliberately staged: it never puts NetBooty first in BootOrder
//! unless asked (`--first`), and refuses to do so while the signing key is not
//! enrolled, because shim would then stop every boot at a verification error.
//!
//! With shim, NetBooty gets its own copy of the distro's shim and MokManager in
//! `\EFI\netbooty\` and is installed next to them as shim's default second
//! stage (`grubx64.efi`). Its boot entry therefore points at a file no other
//! entry uses: some firmware (seen on AMI Aptio) deletes entries whose device
//! paths are identical, ignoring their optional data, so chaining through the
//! distro's own shim with a path argument can cost the distro its boot entry.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use netbooty_cfg::config::Config;
use netbooty_cfg::loadopt::{LoadOption, Resolution, resolve};

use crate::efivars::Store;
use crate::system::{self, Esp, MokState, SecureBoot};
use crate::{fmt_part, pe};

/// Where NetBooty lives on the ESP.
pub const NB_DIR: &str = "\\EFI\\netbooty";
/// NetBooty image when booted directly (own-keys / unsigned).
pub const NB_REL: &str = "\\EFI\\netbooty\\netbooty.efi";

/// Shim copy layout inside `NB_DIR`.
fn nb_file(name: &str) -> String {
    format!("{NB_DIR}\\{name}")
}
pub const ENTRY_LABEL: &str = "NetBooty";
pub const KEY_DIR: &str = "/var/lib/netbooty/keys";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Pick shim if Secure Boot is on or a shim is installed, else unsigned.
    Auto,
    /// Chain through the distro's signed shim; sign with a dedicated MOK.
    Shim,
    /// Boot directly; sign with your own db key (e.g. sbctl).
    OwnKeys,
    /// Boot directly, unsigned (Secure Boot off).
    Unsigned,
}

/// Prints and (unless dry-run) executes system changes.
pub struct Runner {
    pub dry: bool,
}

impl Runner {
    pub fn cmd(&self, cmd: &mut Command) -> Result<String> {
        let shown: Vec<String> = std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|a| {
                let s = a.to_string_lossy();
                if s.contains([' ', '\\']) { format!("'{s}'") } else { s.into_owned() }
            })
            .collect();
        println!("  $ {}", shown.join(" "));
        if self.dry {
            return Ok(String::new());
        }
        let out = cmd.output().with_context(|| format!("running {}", shown[0]))?;
        if !out.status.success() {
            bail!("{} failed: {}", shown[0], String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        println!("  write {}", path.display());
        if self.dry {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        // Write then rename so a crash never leaves a half-written loader.
        let tmp = path.with_extension("efi.new");
        std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        println!("  remove {}", path.display());
        if self.dry {
            return Ok(());
        }
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        println!("  remove {}", path.display());
        if self.dry || !path.exists() {
            return Ok(());
        }
        std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
    }
}

pub fn key_paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (dir.join("netbooty.key"), dir.join("netbooty.crt"), dir.join("netbooty.der"))
}

pub fn keygen(dir: &Path) -> Result<()> {
    let (key, crt, der) = key_paths(dir);
    if key.exists() || crt.exists() {
        bail!("{} already has a key; refusing to overwrite", dir.display());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {} (are you root?)", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let subj = format!("/CN=NetBooty Secure Boot signing key ({})/", host.trim());
    let r = Runner { dry: false };
    r.cmd(
        Command::new("openssl")
            .args(["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256"])
            .args(["-days", "36500", "-subj", &subj, "-addext", "extendedKeyUsage=codeSigning", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&crt),
    )?;
    r.cmd(Command::new("openssl").args(["x509", "-outform", "DER", "-in"]).arg(&crt).arg("-out").arg(&der))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("\nCreated {}.", dir.display());
    println!("Enroll it with shim (you will set a one-time password):");
    println!("  sudo mokutil --import {}", der.display());
    println!("then reboot and choose \"Enroll MOK\" in the blue MokManager screen.");
    Ok(())
}

/// The mounted ESP to install to.
fn pick_esp(esps: &[Esp], requested: Option<&Path>, want_shim: bool) -> Result<(Esp, PathBuf)> {
    let mounted: Vec<(&Esp, &PathBuf)> =
        esps.iter().filter_map(|e| e.mount.as_ref().map(|m| (e, m))).collect();
    if let Some(req) = requested {
        let (e, m) = mounted
            .iter()
            .find(|(_, m)| m.as_path() == req)
            .with_context(|| format!("{} is not a mounted EFI system partition", req.display()))?;
        return Ok(((*e).clone(), (*m).clone()));
    }
    let candidates: Vec<_> =
        mounted.iter().filter(|(_, m)| !want_shim || !system::shims(m).is_empty()).copied().collect();
    match candidates.as_slice() {
        [(e, m)] => Ok(((*e).clone(), (*m).clone())),
        [] if want_shim => bail!("no mounted ESP contains a {}; use --esp/--mode", system::SHIM_NAME),
        [] => bail!("no mounted EFI system partition found; mount it or pass --esp"),
        many => bail!(
            "several ESPs qualify ({}); choose one with --esp",
            many.iter().map(|(_, m)| m.display().to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

pub fn is_netbooty_entry(o: &LoadOption) -> bool {
    let in_nb_dir = o
        .loader_path
        .to_ascii_lowercase()
        .replace('/', "\\")
        .starts_with(&format!("{}\\", NB_DIR.to_ascii_lowercase()));
    o.description == ENTRY_LABEL || in_nb_dir || netbooty_cfg::loadopt::launches(o, NB_REL)
}

/// Other entries with the same partition and loader as `o`: firmware that
/// deduplicates boot entries may delete one of them.
fn twins<'a>(o: &LoadOption, entries: &'a [(u16, LoadOption)], skip: u16) -> Vec<&'a (u16, LoadOption)> {
    entries
        .iter()
        .filter(|(n, e)| {
            *n != skip && e.partition == o.partition && e.loader_path.eq_ignore_ascii_case(&o.loader_path)
        })
        .collect()
}

/// The distro shim NetBooty's private copy is taken from.
pub fn source_shim(mount: &Path, requested: Option<&str>) -> Result<String> {
    if let Some(s) = requested {
        return Ok(s.replace('/', "\\"));
    }
    let nb_prefix = format!("{}\\", NB_DIR.to_ascii_lowercase());
    let found: Vec<String> = system::shims(mount)
        .into_iter()
        .filter(|s| !s.to_ascii_lowercase().starts_with(&nb_prefix))
        .collect();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("no {} on {}; use --shim or --mode", system::SHIM_NAME, mount.display()),
        many => bail!("several shims on {} ({}); pick one with --shim", mount.display(), many.join(", ")),
    }
}

/// Is NetBooty's shim (and MokManager) copy identical to the distro's?
fn shim_copy_status(mount: &Path) -> Result<(String, bool)> {
    let src = source_shim(mount, None)?;
    let src_dir = src.rsplit_once('\\').map_or("", |(d, _)| d).to_string();
    let same = [system::SHIM_NAME, system::MM_NAME].iter().all(|name| {
        let a = std::fs::read(system::esp_file(mount, &format!("{src_dir}\\{name}")));
        let b = std::fs::read(system::esp_file(mount, &nb_file(name)));
        matches!((a, b), (Ok(a), Ok(b)) if a == b)
    });
    Ok((src, same))
}

/// Re-copy the distro's shim and MokManager next to NetBooty, e.g. after a
/// distro shim update (an outdated shim can be revoked via SBAT/dbx).
pub fn refresh_shim(esp: Option<PathBuf>, shim: Option<String>, dry_run: bool) -> Result<()> {
    if !dry_run && !system::is_root() {
        bail!("run refresh-shim with sudo (or use --dry-run)");
    }
    let r = Runner { dry: dry_run };
    let esps = system::esps()?;
    let (_, mount) = pick_esp(&esps, esp.as_deref(), true)?;
    if !system::esp_file(&mount, &nb_file(system::SHIM_NAME)).exists() {
        bail!("no NetBooty shim copy on {}; nothing to refresh", mount.display());
    }
    let src = source_shim(&mount, shim.as_deref())?;
    let src_dir = src.rsplit_once('\\').map_or("", |(d, _)| d).to_string();
    let mut changed = false;
    for name in [system::SHIM_NAME, system::MM_NAME] {
        let from = system::esp_file(&mount, &format!("{src_dir}\\{name}"));
        let to = system::esp_file(&mount, &nb_file(name));
        let bytes = std::fs::read(&from).with_context(|| format!("reading {}", from.display()))?;
        if std::fs::read(&to).ok().as_deref() != Some(bytes.as_slice()) {
            r.write(&to, &bytes)?;
            changed = true;
        }
    }
    println!("{}", if changed { "shim copy updated" } else { "shim copy already up to date" });
    Ok(())
}

pub struct InstallOpts {
    pub image: PathBuf,
    pub esp: Option<PathBuf>,
    pub mode: Mode,
    pub shim: Option<String>,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub first: bool,
    pub dry_run: bool,
}

pub fn install(
    opts: InstallOpts,
    build_config: impl FnOnce(Option<&Config>, bool) -> Result<Config>,
) -> Result<()> {
    let store = Store::new(None);
    if !store.dir().is_dir() {
        bail!("not booted in UEFI mode ({} missing)", store.dir().display());
    }
    if !opts.dry_run && !system::is_root() {
        bail!("install changes the ESP and firmware variables; run it with sudo (or use --dry-run)");
    }
    let r = Runner { dry: opts.dry_run };
    let mut image =
        std::fs::read(&opts.image).with_context(|| format!("reading {}", opts.image.display()))?;
    if image.windows(b"NetBootyTestHook".len()).any(|w| w == b"NetBootyTestHook") {
        bail!(
            "{} is a test build (test-hooks feature); install a normal release build",
            opts.image.display()
        );
    }
    pe::read_config(&image).context("not a NetBooty image")?;
    let sb = system::secure_boot(store.dir());
    let esps = system::esps()?;

    let mode = match opts.mode {
        Mode::Auto => {
            let any_shim = esps.iter().filter_map(|e| e.mount.as_ref()).any(|m| !system::shims(m).is_empty());
            match (sb, any_shim) {
                (_, true) => Mode::Shim,
                (SecureBoot::Enabled, false) => {
                    bail!("Secure Boot is on but no shim was found; use --mode own-keys with your db key")
                }
                _ => Mode::Unsigned,
            }
        }
        m => m,
    };
    if mode == Mode::Unsigned && sb == SecureBoot::Enabled {
        bail!("Secure Boot is on: an unsigned NetBooty would be refused by the firmware");
    }
    let (esp, mount) = pick_esp(&esps, opts.esp.as_deref(), mode == Mode::Shim)?;

    // Shim mode: the distro shim to copy, and where things go.
    let src_shim = match mode {
        Mode::Shim => Some(source_shim(&mount, opts.shim.as_deref())?),
        _ => None,
    };
    let (loader, image_rel) = match mode {
        Mode::Shim => (nb_file(system::SHIM_NAME), nb_file(system::GRUB_NAME)),
        _ => (NB_REL.to_string(), NB_REL.to_string()),
    };

    let (key, cert, der) = match mode {
        Mode::Shim => {
            let (k, c, d) = key_paths(Path::new(KEY_DIR));
            (Some(opts.key.unwrap_or(k)), Some(opts.cert.clone().unwrap_or(c)), Some(d))
        }
        Mode::OwnKeys => (
            Some(opts.key.context("--mode own-keys needs --key")?),
            Some(opts.cert.context("--mode own-keys needs --cert")?),
            None,
        ),
        _ => (None, None, None),
    };
    if let (Some(k), Some(c)) = (&key, &cert)
        && (!k.exists() || !c.exists())
    {
        let msg = format!(
            "signing key {} / {} not found; run `sudo netbooty-setup keygen` first",
            k.display(),
            c.display()
        );
        if !opts.dry_run {
            bail!(msg);
        }
        println!("warning: {msg}");
    }
    let mok = match (&der, mode) {
        (Some(d), Mode::Shim) => system::mok_state(d),
        _ => MokState::Unknown,
    };
    if opts.first && mode == Mode::Shim && sb == SecureBoot::Enabled && mok != MokState::Enrolled {
        bail!(
            "refusing --first: the NetBooty key is not enrolled ({mok:?}); shim would stop every boot at \
             \"Verification failed\". Enroll it, reboot, then rerun with --first."
        );
    }

    println!("ESP:          {} ({}) mounted at {}", esp.device, esp.part_uuid, mount.display());
    println!("mode:         {mode:?}; Secure Boot {sb:?}");
    match &src_shim {
        Some(src) => println!("loader:       {loader} (copy of {src}) -> {image_rel}"),
        None => println!("loader:       {loader}"),
    }
    if mode == Mode::Shim {
        println!("MOK:          {mok:?}");
    }

    // Keep the client ID of an existing install (either layout).
    let dest = system::esp_file(&mount, &image_rel);
    let existing = [nb_file(system::GRUB_NAME), NB_REL.to_string()].iter().find_map(|rel| {
        std::fs::read(system::esp_file(&mount, rel)).ok().and_then(|b| pe::read_config(&b).ok())
    });

    // Never create an entry that firmware could treat as a duplicate.
    let entries = store.boot_entries()?;
    let clash: Vec<String> = entries
        .iter()
        .filter(|(_, o)| !is_netbooty_entry(o) && o.loader_path.eq_ignore_ascii_case(&loader))
        .map(|(n, o)| format!("Boot{n:04X} \"{}\"", o.description))
        .collect();
    if !clash.is_empty() {
        bail!("{} already boot {loader}; NetBooty needs a loader no other entry uses", clash.join(", "));
    }
    let cfg = build_config(existing.as_ref(), opts.first)?;
    pe::write_config(&mut image, &cfg.encode().map_err(|e| anyhow::anyhow!("invalid config: {e:?}"))?)?;

    println!("\nSteps:");
    let work = std::env::temp_dir().join(format!("netbooty-install-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let unsigned = work.join("netbooty.efi");
    std::fs::write(&unsigned, &image)?;
    let payload = if let (Some(k), Some(c)) = (&key, &cert) {
        let signed = work.join("netbooty.signed.efi");
        r.cmd(
            Command::new("sbsign")
                .arg("--key")
                .arg(k)
                .arg("--cert")
                .arg(c)
                .arg("--output")
                .arg(&signed)
                .arg(&unsigned),
        )?;
        r.cmd(Command::new("sbverify").arg("--cert").arg(c).arg(&signed))?;
        signed
    } else {
        unsigned
    };
    let data = if r.dry { image } else { std::fs::read(&payload)? };
    if let Some(src) = &src_shim {
        // Shim and MokManager first, so a half-finished install never has a
        // NetBooty image without the shim that verifies it.
        let src_dir = src.rsplit_once('\\').map_or("", |(d, _)| d).to_string();
        for name in [system::SHIM_NAME, system::MM_NAME] {
            let from = system::esp_file(&mount, &format!("{src_dir}\\{name}"));
            let bytes = std::fs::read(&from).with_context(|| format!("reading {}", from.display()))?;
            r.write(&system::esp_file(&mount, &nb_file(name)), &bytes)?;
        }
    }
    r.write(&dest, &data)?;
    // Image from the other layout (e.g. the old shim-argument install).
    for rel in [NB_REL.to_string(), nb_file(system::GRUB_NAME)] {
        let p = system::esp_file(&mount, &rel);
        if rel != image_rel && p.exists() {
            r.remove_file(&p)?;
        }
    }

    // Boot entry: reuse a matching one, replace stale ones.
    let esp_uuid = esp.part_uuid.clone();
    let matches_wanted = |o: &LoadOption| {
        o.description == ENTRY_LABEL
            && o.loader_path.eq_ignore_ascii_case(&loader)
            && o.partition.is_some_and(|p| fmt_part(&p) == esp_uuid)
            && o.optional_data.is_empty()
    };
    let mut num = entries.iter().find(|(_, o)| matches_wanted(o)).map(|(n, _)| *n);
    for (n, o) in &entries {
        if Some(*n) != num && is_netbooty_entry(o) {
            println!("  (removing stale entry Boot{n:04X} \"{}\")", o.description);
            r.cmd(Command::new("efibootmgr").args(["-q", "-b", &format!("{n:04X}"), "-B"]))?;
        }
    }
    if num.is_none() {
        let mut c = Command::new("efibootmgr");
        c.args([
            "-q",
            "-C",
            "-d",
            &esp.disk,
            "-p",
            &esp.part_num.to_string(),
            "-L",
            ENTRY_LABEL,
            "-l",
            &loader,
        ]);
        let created = r.cmd(&mut c);
        let _ = std::fs::remove_dir_all(&work);
        created?;
        if !r.dry {
            let after = store.boot_entries()?;
            num = after.iter().find(|(_, o)| matches_wanted(o)).map(|(n, _)| *n);
            if num.is_none() {
                bail!("efibootmgr did not create the expected entry; check `efibootmgr -v`");
            }
        }
    }

    let _ = std::fs::remove_dir_all(&work);

    if opts.first {
        let order = store.boot_order();
        let n = num.unwrap_or(0xFFFF);
        if !r.dry {
            let now = store.boot_entries()?;
            if let Some((_, mine)) = now.iter().find(|(x, _)| *x == n) {
                let t = twins(mine, &now, n);
                if !t.is_empty() {
                    bail!(
                        "refusing --first: Boot{} share NetBooty's boot path and firmware may delete one of them",
                        t.iter().map(|(x, _)| format!("{x:04X}")).collect::<Vec<_>>().join(", Boot")
                    );
                }
            }
        }
        if order.first() != Some(&n) {
            let new: Vec<String> = std::iter::once(n)
                .chain(order.into_iter().filter(|&x| x != n))
                .map(|x| format!("{x:04X}"))
                .collect();
            r.cmd(Command::new("efibootmgr").args(["-q", "-o", &new.join(",")]))?;
        }
    }

    let n = num.map_or("????".to_string(), |n| format!("{n:04X}"));
    println!("\n{}NetBooty installed as Boot{n}.", if r.dry { "[dry run] " } else { "" });
    if mode == Mode::Shim && sb == SecureBoot::Enabled && mok != MokState::Enrolled {
        println!("\nThe signing key is not enrolled yet ({mok:?}).");
        if mok != MokState::Pending {
            println!("  sudo mokutil --import {}", der.as_ref().unwrap().display());
        }
        println!("Reboot and choose \"Enroll MOK\" in MokManager, then test as below.");
    }
    if !opts.first {
        println!("\nTest it once without changing the default boot:");
        println!("  sudo efibootmgr -n {n} && reboot");
        println!("When it works, make it the default:  rerun this command with --first");
    }
    Ok(())
}

pub fn uninstall(esp_mount: Option<PathBuf>, dry_run: bool) -> Result<()> {
    if !dry_run && !system::is_root() {
        bail!("run uninstall with sudo (or use --dry-run)");
    }
    let r = Runner { dry: dry_run };
    let store = Store::new(None);
    for (n, o) in store.boot_entries()? {
        if is_netbooty_entry(&o) {
            r.cmd(Command::new("efibootmgr").args(["-q", "-b", &format!("{n:04X}"), "-B"]))?;
        }
    }
    let mounts: Vec<PathBuf> = match esp_mount {
        Some(m) => vec![m],
        None => system::esps()?.into_iter().filter_map(|e| e.mount).collect(),
    };
    for m in mounts {
        let dir = system::esp_file(&m, NB_DIR);
        if dir.exists() {
            r.remove_dir(&dir)?;
        }
    }
    println!("\nSigning keys in {KEY_DIR} are kept. To also remove the enrolled MOK:");
    println!("  sudo mokutil --delete {KEY_DIR}/netbooty.der   (confirm in MokManager on next boot)");
    Ok(())
}

pub fn doctor() -> Result<()> {
    let store = Store::new(None);
    println!("== Firmware");
    if !store.dir().is_dir() {
        println!("  not booted in UEFI mode; NetBooty needs UEFI");
        return Ok(());
    }
    let sb = system::secure_boot(store.dir());
    println!("  UEFI:          yes");
    println!("  Secure Boot:   {sb:?}");
    let entries = store.boot_entries()?;
    let current = store.boot_current();
    let order = store.boot_order();
    println!("  BootOrder:     {}", order.iter().map(|n| format!("{n:04X}")).collect::<Vec<_>>().join(","));
    if let Some(n) = store.boot_next() {
        println!("  BootNext:      {n:04X} (pending one-shot boot)");
    }
    if let Some(t) = store.pending_next() {
        println!("  NetBootyNext:  {t} (pending one-shot request)");
    }

    println!("\n== Boot entries");
    for (n, o) in &entries {
        let mut tags = Vec::new();
        if Some(*n) == current {
            tags.push("current");
        }
        if is_netbooty_entry(o) {
            tags.push("netbooty");
        }
        if !o.active() {
            tags.push("inactive");
        }
        let part = o.partition.map(|p| fmt_part(&p)).unwrap_or_else(|| "-".into());
        let opt =
            o.optional_text().filter(|t| t.starts_with('\\')).map(|t| format!(" -> {t}")).unwrap_or_default();
        println!("  Boot{n:04X} {:<22} part={part} {}{opt} {}", o.description, o.loader_path, tags.join(","));
    }

    println!("\n== EFI system partitions");
    let esps = system::esps()?;
    for e in &esps {
        let m = e.mount.as_ref().map_or("not mounted".to_string(), |m| m.display().to_string());
        println!("  {} ({}) on {} part {} - {m}", e.device, e.part_uuid, e.disk, e.part_num);
        if let Some(mp) = &e.mount {
            for s in system::shims(mp) {
                println!("    shim: {s}");
            }
            let copy = system::esp_file(mp, &nb_file(system::SHIM_NAME));
            if copy.exists() {
                match shim_copy_status(mp) {
                    Ok((src, true)) => println!("    shim copy: {} (same as {src})", copy.display()),
                    Ok((src, false)) => println!(
                        "    shim copy: {} DIFFERS from {src}; run `sudo netbooty-setup refresh-shim`",
                        copy.display()
                    ),
                    Err(e) => println!("    shim copy: {} ({e})", copy.display()),
                }
            }
            let nb = [nb_file(system::GRUB_NAME), NB_REL.to_string()]
                .iter()
                .map(|rel| system::esp_file(mp, rel))
                .find(|p| p.exists())
                .unwrap_or_default();
            if let Ok(b) = std::fs::read(&nb) {
                println!("    NetBooty installed: {}", nb.display());
                match pe::read_config(&b) {
                    Ok(cfg) => {
                        let own = entries.iter().find(|(_, o)| is_netbooty_entry(o)).map(|(n, _)| *n);
                        for t in &cfg.targets {
                            let res = match resolve(t, &entries, own) {
                                Resolution::Found(n) => format!("-> Boot{n:04X}"),
                                r => format!("{r:?}"),
                            };
                            println!("      target {:<15} {res}", t.name);
                        }
                    }
                    Err(err) => println!("      unreadable config: {err}"),
                }
            }
        }
    }

    println!("\n== Signing key");
    let (_, _, der) = key_paths(Path::new(KEY_DIR));
    match std::fs::metadata(&der) {
        Ok(_) => println!("  {}: MOK {:?}", der.display(), system::mok_state(&der)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("  {KEY_DIR} not readable (run doctor with sudo to check)")
        }
        Err(_) => println!("  none yet (`sudo netbooty-setup keygen` creates one)"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netbooty_cfg::loadopt::build;

    fn entry(desc: &str, part: [u8; 16], path: &str, opt: &[u8]) -> LoadOption {
        let mut fpl = build::hd_node(1, 2048, 1 << 20, 2, part);
        fpl.extend(build::file_node(path));
        fpl.extend(build::end_node());
        LoadOption::parse(&build::load_option(1, desc, &fpl, opt)).unwrap()
    }

    #[test]
    fn netbooty_entries_and_twins() {
        let ubuntu = entry("ubuntu", [1; 16], "\\EFI\\ubuntu\\shimx64.efi", b"");
        let copy = entry("NetBooty", [1; 16], "\\EFI\\netbooty\\shimx64.efi", b"");
        let legacy_opt: Vec<u8> =
            "\\EFI\\netbooty\\netbooty.efi".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let legacy = entry("x", [1; 16], "\\EFI\\ubuntu\\shimx64.efi", &legacy_opt);
        assert!(!is_netbooty_entry(&ubuntu));
        assert!(is_netbooty_entry(&copy));
        assert!(is_netbooty_entry(&legacy));

        // The old layout shared Ubuntu's boot path: the dedupe hazard.
        let all = vec![(2, ubuntu.clone()), (1, legacy.clone()), (4, copy.clone())];
        assert_eq!(twins(&legacy, &all, 1).len(), 1);
        assert!(twins(&copy, &all, 4).is_empty());
        // Same path on another disk is not a twin.
        let other_disk = entry("ubuntu", [2; 16], "\\EFI\\netbooty\\shimx64.efi", b"");
        assert!(twins(&copy, &[(4, copy.clone()), (7, other_disk)], 4).is_empty());
    }
}
