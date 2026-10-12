//! `keygen`, `install`, `uninstall` and `doctor`.
//!
//! Install is deliberately staged: it never puts NetBooty first in BootOrder
//! unless asked (`--first`), and refuses to do so while the signing key is not
//! enrolled, because shim would then stop every boot at a verification error.

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
pub const NB_REL: &str = "\\EFI\\netbooty\\netbooty.efi";
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
    o.description == ENTRY_LABEL || netbooty_cfg::loadopt::launches(o, NB_REL)
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

    let loader = match mode {
        Mode::Shim => match opts.shim {
            Some(s) => s.replace('/', "\\"),
            None => match system::shims(&mount).as_slice() {
                [one] => one.clone(),
                many => {
                    bail!("several shims on {} ({}); pick one with --shim", mount.display(), many.join(", "))
                }
            },
        },
        _ => NB_REL.to_string(),
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
    println!(
        "loader:       {loader}{}",
        if mode == Mode::Shim { format!(" -> {NB_REL}") } else { String::new() }
    );
    if mode == Mode::Shim {
        println!("MOK:          {mok:?}");
    }

    // Keep the client ID of an existing install.
    let dest = system::esp_file(&mount, NB_REL);
    let existing = std::fs::read(&dest).ok().and_then(|b| pe::read_config(&b).ok());
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
    r.write(&dest, &data)?;
    let _ = std::fs::remove_dir_all(&work);

    // Boot entry: reuse a matching one, replace stale ones.
    let entries = store.boot_entries()?;
    let want_opt = (mode == Mode::Shim).then_some(NB_REL);
    let esp_uuid = esp.part_uuid.clone();
    let matches_wanted = |o: &LoadOption| {
        o.description == ENTRY_LABEL
            && o.loader_path.eq_ignore_ascii_case(&loader)
            && o.partition.is_some_and(|p| fmt_part(&p) == esp_uuid)
            && o.optional_text().as_deref().map(|t| t.eq_ignore_ascii_case(NB_REL)) == want_opt.map(|_| true)
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
        if let Some(o) = want_opt {
            c.args(["-u", o]);
        }
        r.cmd(&mut c)?;
        if !r.dry {
            let after = store.boot_entries()?;
            num = after.iter().find(|(_, o)| matches_wanted(o)).map(|(n, _)| *n);
            if num.is_none() {
                bail!("efibootmgr did not create the expected entry; check `efibootmgr -v`");
            }
        }
    }

    if opts.first {
        let order = store.boot_order();
        let n = num.unwrap_or(0xFFFF);
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
            let nb = system::esp_file(mp, NB_REL);
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
