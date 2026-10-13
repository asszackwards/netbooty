//! `keygen`, `install`, `maintain`, `uninstall` and `doctor`.
//!
//! Install is deliberately staged: it never puts NetBooty first in BootOrder
//! unless asked (`--first` / `activate`), and refuses to do so while the
//! signing key is not enrolled, because shim would then stop every boot at a
//! verification error.
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
use netbooty_cfg::loadopt::{LoadOption, Resolution, resolve};
use serde::{Deserialize, Serialize};

use crate::efivars::Store;
use crate::pe;
use crate::settings::{self, Settings};
use crate::spec::{build_config, fmt_part, print_config};
use crate::system::{self, Esp, MokState, SecureBoot};

/// Where NetBooty lives on the ESP.
pub const NB_DIR: &str = "\\EFI\\netbooty";
/// NetBooty image when booted directly (own-keys / unsigned).
pub const NB_REL: &str = "\\EFI\\netbooty\\netbooty.efi";
pub const ENTRY_LABEL: &str = "NetBooty";
pub const KEY_DIR: &str = "/var/lib/netbooty/keys";

/// Shim copy layout inside `NB_DIR`.
fn nb_file(name: &str) -> String {
    format!("{NB_DIR}\\{name}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Pick shim if Secure Boot is on or a shim is installed, else unsigned.
    Auto,
    /// Chain through a private copy of the distro's signed shim; sign with a dedicated MOK.
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
    fn show(cmd: &Command) -> Vec<String> {
        std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|a| {
                let s = a.to_string_lossy();
                if s.contains([' ', '\\']) { format!("'{s}'") } else { s.into_owned() }
            })
            .collect()
    }

    pub fn cmd(&self, cmd: &mut Command) -> Result<String> {
        let shown = Self::show(cmd);
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

    /// Run with the terminal attached (for commands that prompt).
    fn interactive(&self, cmd: &mut Command) -> Result<()> {
        let shown = Self::show(cmd);
        println!("  $ {}", shown.join(" "));
        if self.dry {
            return Ok(());
        }
        let status = cmd.status().with_context(|| format!("running {}", shown[0]))?;
        if !status.success() {
            bail!("{} failed", shown[0]);
        }
        Ok(())
    }

    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        println!("  write {}", path.display());
        if self.dry {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        // Write then rename so a crash never leaves a half-written file.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".new");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    }

    /// `write`, but only when the content differs; returns whether it wrote.
    fn update(&self, path: &Path, data: &[u8]) -> Result<bool> {
        if std::fs::read(path).ok().as_deref() == Some(data) {
            return Ok(false);
        }
        self.write(path, data)?;
        Ok(true)
    }

    fn chmod(&self, path: &Path, mode: u32) -> Result<()> {
        if self.dry {
            return Ok(());
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", path.display()))
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

fn create_key(dir: &Path, r: &Runner) -> Result<()> {
    let (key, crt, der) = key_paths(dir);
    if !r.dry {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {} (are you root?)", dir.display()))?;
        r.chmod(dir, 0o700)?;
    }
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let subj = format!("/CN=NetBooty Secure Boot signing key ({})/", host.trim());
    r.cmd(
        Command::new("openssl")
            .args(["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256"])
            .args(["-days", "36500", "-subj", &subj, "-addext", "extendedKeyUsage=codeSigning", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&crt),
    )?;
    r.cmd(Command::new("openssl").args(["x509", "-outform", "DER", "-in"]).arg(&crt).arg("-out").arg(&der))?;
    if !r.dry {
        r.chmod(&key, 0o600)?;
    }
    Ok(())
}

pub fn keygen(dir: &Path) -> Result<()> {
    let (key, crt, der) = key_paths(dir);
    if key.exists() || crt.exists() {
        bail!("{} already has a key; refusing to overwrite", dir.display());
    }
    create_key(dir, &Runner { dry: false })?;
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

fn dir_of(rel: &str) -> String {
    rel.rsplit_once('\\').map_or("", |(d, _)| d).to_string()
}

/// Is NetBooty's shim (and MokManager) copy identical to the distro's?
fn shim_copy_status(mount: &Path, shim: Option<&str>) -> Result<(String, bool)> {
    let src = source_shim(mount, shim)?;
    let src_dir = dir_of(&src);
    let same = [system::SHIM_NAME, system::MM_NAME].iter().all(|name| {
        let a = std::fs::read(system::esp_file(mount, &format!("{src_dir}\\{name}")));
        let b = std::fs::read(system::esp_file(mount, &nb_file(name)));
        matches!((a, b), (Ok(a), Ok(b)) if a == b)
    });
    Ok((src, same))
}

/// Copy the distro's shim and MokManager next to NetBooty if they differ.
/// An outdated shim can be revoked (SBAT/dbx), so the copy must follow
/// distro updates.
fn sync_shim(r: &Runner, mount: &Path, src: &str) -> Result<bool> {
    let src_dir = dir_of(src);
    let mut changed = false;
    for name in [system::SHIM_NAME, system::MM_NAME] {
        let from = system::esp_file(mount, &format!("{src_dir}\\{name}"));
        let bytes = std::fs::read(&from).with_context(|| format!("reading {}", from.display()))?;
        changed |= r.update(&system::esp_file(mount, &nb_file(name)), &bytes)?;
    }
    Ok(changed)
}

pub fn refresh_shim(esp: Option<PathBuf>, shim: Option<String>, dry_run: bool) -> Result<()> {
    if !dry_run && !system::is_root() {
        bail!("run refresh-shim with sudo (or use --dry-run)");
    }
    let r = Runner { dry: dry_run };
    let (_, mount) = pick_esp(&system::esps()?, esp.as_deref(), true)?;
    if !system::esp_file(&mount, &nb_file(system::SHIM_NAME)).exists() {
        bail!("no NetBooty shim copy on {}; nothing to refresh", mount.display());
    }
    let src = source_shim(&mount, shim.as_deref())?;
    let changed = sync_shim(&r, &mount, &src)?;
    println!("{}", if changed { "shim copy updated" } else { "shim copy already up to date" });
    Ok(())
}

/// Configuration of a NetBooty already on a mounted ESP (any layout).
pub fn installed_config() -> Option<netbooty_cfg::config::Config> {
    let esps = system::esps().ok()?;
    esps.iter().filter_map(|e| e.mount.as_ref()).find_map(|m| {
        [nb_file(system::GRUB_NAME), NB_REL.to_string()].iter().find_map(|rel| {
            std::fs::read(system::esp_file(m, rel)).ok().and_then(|b| pe::read_config(&b).ok())
        })
    })
}

/// Default NetBooty image: the installed copy, else the build next to this
/// tool (`target/<profile>/netbooty-setup` -> `target/x86_64-unknown-uefi/release/netbooty.efi`).
pub fn default_image() -> Option<PathBuf> {
    let installed = PathBuf::from(settings::IMAGE_PATH);
    if installed.exists() {
        return Some(installed);
    }
    let exe = std::env::current_exe().ok()?;
    let triple = if cfg!(target_arch = "aarch64") { "aarch64-unknown-uefi" } else { "x86_64-unknown-uefi" };
    let built = exe.parent()?.parent()?.join(triple).join("release").join("netbooty.efi");
    built.exists().then_some(built)
}

pub struct InstallOpts {
    pub image: Option<PathBuf>,
    pub dry_run: bool,
    /// May run `mokutil --import` (prompts for a password).
    pub interactive: bool,
}

struct Plan {
    sb: SecureBoot,
    mode: Mode,
    esp: Esp,
    mount: PathBuf,
    src_shim: Option<String>,
    loader: String,
    image_rel: String,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    der: Option<PathBuf>,
}

fn plan(s: &Settings, store: &Store) -> Result<Plan> {
    let sb = system::secure_boot(store.dir());
    let esps = system::esps()?;
    let mode = match s.mode {
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
    let (esp, mount) = pick_esp(&esps, s.esp.as_deref(), mode == Mode::Shim)?;
    let src_shim = match mode {
        Mode::Shim => Some(source_shim(&mount, s.shim.as_deref())?),
        _ => None,
    };
    let (loader, image_rel) = match mode {
        Mode::Shim => (nb_file(system::SHIM_NAME), nb_file(system::GRUB_NAME)),
        _ => (NB_REL.to_string(), NB_REL.to_string()),
    };
    let (key, cert, der) = match mode {
        Mode::Shim => {
            let (k, c, d) = key_paths(Path::new(KEY_DIR));
            (Some(s.key.clone().unwrap_or(k)), Some(s.cert.clone().unwrap_or(c)), Some(d))
        }
        Mode::OwnKeys => (
            Some(s.key.clone().context("--mode own-keys needs --key")?),
            Some(s.cert.clone().context("--mode own-keys needs --cert")?),
            None,
        ),
        _ => (None, None, None),
    };
    Ok(Plan { sb, mode, esp, mount, src_shim, loader, image_rel, key, cert, der })
}

/// Install or repair NetBooty according to `s`, then save `s` and install the
/// tool and its systemd units so it stays maintained.
pub fn install(s: &Settings, opts: InstallOpts) -> Result<()> {
    let store = Store::new(None);
    if !store.dir().is_dir() {
        bail!("not booted in UEFI mode ({} missing)", store.dir().display());
    }
    if !opts.dry_run && !system::is_root() {
        bail!("install changes the ESP and firmware variables; run it with sudo (or use --dry-run)");
    }
    let r = Runner { dry: opts.dry_run };
    let image_src = opts.image.clone().or_else(default_image).context(
        "no NetBooty image found; build it (scripts/bootstrap.sh) or pass --image path/to/netbooty.efi",
    )?;
    let mut image = std::fs::read(&image_src).with_context(|| format!("reading {}", image_src.display()))?;
    if image.windows(b"NetBootyTestHook".len()).any(|w| w == b"NetBootyTestHook") {
        bail!("{} is a test build (test-hooks feature); install a normal release build", image_src.display());
    }
    pe::read_config(&image).context("not a NetBooty image")?;
    let p = plan(s, &store)?;

    println!("ESP:          {} ({}) mounted at {}", p.esp.device, p.esp.part_uuid, p.mount.display());
    println!("mode:         {:?}; Secure Boot {:?}", p.mode, p.sb);
    match &p.src_shim {
        Some(src) => println!("loader:       {} (copy of {src}) -> {}", p.loader, p.image_rel),
        None => println!("loader:       {}", p.loader),
    }

    // Signing key: create one for shim mode if there is none yet.
    println!("\nSteps:");
    if let (Mode::Shim, Some(k), Some(c)) = (p.mode, &p.key, &p.cert)
        && !k.exists()
        && !c.exists()
        && s.key.is_none()
    {
        println!("  (no signing key yet: creating one in {KEY_DIR})");
        create_key(Path::new(KEY_DIR), &r)?;
    }
    if let (Some(k), Some(c)) = (&p.key, &p.cert)
        && !r.dry
        && (!k.exists() || !c.exists())
    {
        bail!("signing key {} / {} not found", k.display(), c.display());
    }
    let mut mok = match (&p.der, p.mode) {
        (Some(d), Mode::Shim) => system::mok_state(d),
        _ => MokState::Unknown,
    };
    let needs_mok = p.mode == Mode::Shim && p.sb == SecureBoot::Enabled;
    if needs_mok && mok == MokState::NotEnrolled && opts.interactive {
        println!("  (queueing the signing key for enrollment; choose a one-time password)");
        r.interactive(Command::new("mokutil").arg("--import").arg(p.der.as_ref().unwrap()))?;
        mok = MokState::Pending;
    }
    if s.first && needs_mok && mok != MokState::Enrolled && !r.dry {
        bail!(
            "refusing to make NetBooty the default: its key is not enrolled yet ({mok:?}); shim would stop \
             every boot at \"Verification failed\". Reboot, enroll it in MokManager, then run \
             `sudo netbooty-setup activate`."
        );
    }

    // Keep the client ID of an existing install (either layout).
    let dest = system::esp_file(&p.mount, &p.image_rel);
    let existing = [nb_file(system::GRUB_NAME), NB_REL.to_string()].iter().find_map(|rel| {
        std::fs::read(system::esp_file(&p.mount, rel)).ok().and_then(|b| pe::read_config(&b).ok())
    });

    // Never create an entry that firmware could treat as a duplicate.
    let entries = store.boot_entries()?;
    let clash: Vec<String> = entries
        .iter()
        .filter(|(_, o)| !is_netbooty_entry(o) && o.loader_path.eq_ignore_ascii_case(&p.loader))
        .map(|(n, o)| format!("Boot{n:04X} \"{}\"", o.description))
        .collect();
    if !clash.is_empty() {
        bail!("{} already boot {}; NetBooty needs a loader no other entry uses", clash.join(", "), p.loader);
    }
    let mut cfg = build_config(s, existing.as_ref(), &store)?;
    // Until NetBooty is the default, it must not promote itself when started
    // through a one-shot BootNext test.
    cfg.reassert_bootorder &= s.first;
    pe::write_config(&mut image, &cfg.encode().map_err(|e| anyhow::anyhow!("invalid config: {e:?}"))?)?;

    let work = std::env::temp_dir().join(format!("netbooty-install-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let result = (|| -> Result<Vec<u8>> {
        let unsigned = work.join("netbooty.efi");
        std::fs::write(&unsigned, &image)?;
        let (Some(k), Some(c)) = (&p.key, &p.cert) else { return Ok(image.clone()) };
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
        Ok(if r.dry { image.clone() } else { std::fs::read(&signed)? })
    })();
    let _ = std::fs::remove_dir_all(&work);
    let data = result?;

    if let Some(src) = &p.src_shim {
        // Shim and MokManager first, so a half-finished install never has a
        // NetBooty image without the shim that verifies it.
        sync_shim(&r, &p.mount, src)?;
    }
    r.update(&dest, &data)?;
    // Image from the other layout (e.g. the old shim-argument install).
    for rel in [NB_REL.to_string(), nb_file(system::GRUB_NAME)] {
        let f = system::esp_file(&p.mount, &rel);
        if rel != p.image_rel && f.exists() {
            r.remove_file(&f)?;
        }
    }

    // Boot entry: reuse a matching one, replace stale ones.
    let esp_uuid = p.esp.part_uuid.clone();
    let loader = p.loader.clone();
    let matches_wanted = |o: &LoadOption| {
        o.description == ENTRY_LABEL
            && o.loader_path.eq_ignore_ascii_case(&loader)
            && o.partition.is_some_and(|x| fmt_part(&x) == esp_uuid)
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
        r.cmd(Command::new("efibootmgr").args([
            "-q",
            "-C",
            "-d",
            &p.esp.disk,
            "-p",
            &p.esp.part_num.to_string(),
            "-L",
            ENTRY_LABEL,
            "-l",
            &p.loader,
        ]))?;
        if !r.dry {
            num = store.boot_entries()?.iter().find(|(_, o)| matches_wanted(o)).map(|(n, _)| *n);
            if num.is_none() {
                bail!("efibootmgr did not create the expected entry; check `efibootmgr -v`");
            }
        }
    }
    if s.first
        && let Some(n) = num
    {
        ensure_first(&r, &store, n)?;
    }

    install_self(&r, s, &image_src, &p)?;

    print_config(&cfg);
    let n = num.map_or("????".to_string(), |n| format!("{n:04X}"));
    println!("\n{}NetBooty installed as Boot{n}.", if r.dry { "[dry run] " } else { "" });
    if needs_mok && matches!(mok, MokState::NotEnrolled | MokState::Pending) {
        println!("\nNext: reboot. In the blue MokManager screen press a key within 10 seconds, then");
        println!("choose Enroll MOK -> Continue -> Yes, enter the password you just set, and Reboot.");
    }
    if !s.first {
        println!("\nThen try NetBooty once without changing the default boot:");
        println!("  sudo efibootmgr -n {n} && sudo reboot");
        println!("When it works, make it the default:");
        println!("  sudo netbooty-setup activate");
    }
    Ok(())
}

/// Move `n` to the front of BootOrder, refusing if firmware could treat its
/// entry as a duplicate of another.
fn ensure_first(r: &Runner, store: &Store, n: u16) -> Result<bool> {
    let order = store.boot_order();
    if order.first() == Some(&n) {
        return Ok(false);
    }
    let now = store.boot_entries()?;
    if let Some((_, mine)) = now.iter().find(|(x, _)| *x == n) {
        let t = twins(mine, &now, n);
        if !t.is_empty() {
            bail!(
                "not putting NetBooty first: Boot{} share its boot path and firmware may delete one of them",
                t.iter().map(|(x, _)| format!("{x:04X}")).collect::<Vec<_>>().join(", Boot")
            );
        }
    }
    let new: Vec<String> =
        std::iter::once(n).chain(order.into_iter().filter(|&x| x != n)).map(|x| format!("{x:04X}")).collect();
    r.cmd(Command::new("efibootmgr").args(["-q", "-o", &new.join(",")]))?;
    Ok(true)
}

/// Install this tool, the image and settings to fixed locations, and the
/// systemd units that keep the install healthy.
fn install_self(r: &Runner, s: &Settings, image_src: &Path, p: &Plan) -> Result<()> {
    let exe = std::env::current_exe().context("locating netbooty-setup")?;
    let sbin = Path::new(settings::SBIN_PATH);
    if exe != sbin && r.update(sbin, &std::fs::read(&exe)?)? {
        r.chmod(sbin, 0o755)?;
    }
    let image_dst = Path::new(settings::IMAGE_PATH);
    if image_src != image_dst {
        r.update(image_dst, &std::fs::read(image_src)?)?;
    }
    // Store the resolved mode so maintenance never has to guess again.
    let mut saved = s.clone();
    saved.mode = p.mode;
    if Settings::load()?.as_ref() != Some(&saved) {
        r.write(Path::new(settings::SETTINGS_PATH), saved.to_toml()?.as_bytes())?;
    }

    if !Path::new("/run/systemd/system").is_dir() {
        println!("  (systemd not running: run `netbooty-setup maintain` at boot and shutdown yourself)");
        return Ok(());
    }
    let watched = p.src_shim.as_ref().map(|src| system::esp_file(&p.mount, src));
    let units = settings::systemd_units(&p.mount, watched.as_deref());
    let mut changed = false;
    for (name, text) in &units {
        changed |= r.update(&Path::new(settings::UNIT_DIR).join(name), text.as_bytes())?;
    }
    if !watched.is_some() {
        for stale in [settings::PATH_UNIT, settings::REFRESH_UNIT] {
            let f = Path::new(settings::UNIT_DIR).join(stale);
            if f.exists() {
                r.cmd(Command::new("systemctl").args(["disable", "--now", stale]))?;
                r.remove_file(&f)?;
                changed = true;
            }
        }
    }
    if changed {
        r.cmd(Command::new("systemctl").arg("daemon-reload"))?;
        r.cmd(Command::new("systemctl").args(["enable", settings::MAINTAIN_UNIT]))?;
        if watched.is_some() {
            r.cmd(Command::new("systemctl").args(["enable", "--now", settings::PATH_UNIT]))?;
        }
    }
    // Start the maintain unit so its shutdown pass (ExecStop) covers this
    // session too. Not from inside NetBooty's own units (a repair run by
    // `maintain`): starting the unit from inside itself would wait on itself.
    // (INVOCATION_ID is no signal: desktop sessions inherit it too.)
    let in_own_unit = std::fs::read_to_string("/proc/self/cgroup")
        .is_ok_and(|c| c.contains(settings::MAINTAIN_UNIT) || c.contains(settings::REFRESH_UNIT));
    if !in_own_unit {
        let active = Command::new("systemctl")
            .args(["is-active", "--quiet", settings::MAINTAIN_UNIT])
            .status()
            .is_ok_and(|s| s.success());
        if !active {
            r.cmd(Command::new("systemctl").args(["start", settings::MAINTAIN_UNIT]))?;
        }
    }
    Ok(())
}

/// Keep an installed NetBooty healthy: re-run the install if its entry or
/// files are gone, refresh the shim copy after distro updates, and move
/// NetBooty back to the front of BootOrder if something else took it.
/// Changes nothing when all is well. Run by systemd at boot and shutdown.
pub fn maintain(dry_run: bool) -> Result<()> {
    let Some(s) = Settings::load()? else {
        println!("NetBooty is not installed ({} missing); nothing to do", settings::SETTINGS_PATH);
        return Ok(());
    };
    if !dry_run && !system::is_root() {
        bail!("run maintain as root (or use --dry-run)");
    }
    let r = Runner { dry: dry_run };
    let store = Store::new(None);
    let p = plan(&s, &store)?;
    let entries = store.boot_entries()?;
    let entry = entries
        .iter()
        .find(|(_, o)| o.description == ENTRY_LABEL && o.loader_path.eq_ignore_ascii_case(&p.loader))
        .map(|(n, _)| *n);
    let files_ok = system::esp_file(&p.mount, &p.image_rel).exists()
        && (p.mode != Mode::Shim || system::esp_file(&p.mount, &nb_file(system::SHIM_NAME)).exists());

    let Some(n) = entry.filter(|_| files_ok) else {
        println!("NetBooty's boot entry or files are missing: reinstalling");
        let opts = InstallOpts { image: Some(settings::IMAGE_PATH.into()), dry_run, interactive: false };
        return install(&s, opts);
    };
    if let Some(src) = &p.src_shim
        && sync_shim(&r, &p.mount, src)?
    {
        println!("updated NetBooty's shim copy from {src}");
    }
    if s.first && ensure_first(&r, &store, n)? {
        println!("moved NetBooty (Boot{n:04X}) back to the front of BootOrder");
    }
    Ok(())
}

pub fn uninstall(esp_mount: Option<PathBuf>, dry_run: bool) -> Result<()> {
    if !dry_run && !system::is_root() {
        bail!("run uninstall with sudo (or use --dry-run)");
    }
    let r = Runner { dry: dry_run };
    let units = Path::new(settings::UNIT_DIR);
    for unit in [settings::PATH_UNIT, settings::REFRESH_UNIT, settings::MAINTAIN_UNIT] {
        if units.join(unit).exists() {
            r.cmd(Command::new("systemctl").args(["disable", unit]))?;
            r.remove_file(&units.join(unit))?;
        }
    }
    if Path::new("/run/systemd/system").is_dir() {
        r.cmd(Command::new("systemctl").arg("daemon-reload"))?;
    }
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
    for f in [settings::SETTINGS_PATH, settings::IMAGE_PATH, settings::SBIN_PATH] {
        if Path::new(f).exists() {
            r.remove_file(Path::new(f))?;
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
    if let Some(n) = store.net_status() {
        println!("  Last network:  {n}");
    }
    // AMI Aptio keeps its "Network Stack" setup option here; the first byte is
    // the switch. Purely informational.
    let ami = store.dir().join("NetworkStackVar-d1405d16-7afc-4695-bb12-41459d3695a2");
    if let Some(&enabled) = std::fs::read(ami).ok().as_ref().and_then(|d| d.get(4)) {
        println!(
            "  Net. stack:    {} in firmware setup (AMI)",
            if enabled != 0 { "enabled" } else { "DISABLED: enable \"Network Stack\"" }
        );
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
        let Some(mp) = &e.mount else { continue };
        for s in system::shims(mp) {
            println!("    shim: {s}");
        }
        let copy = system::esp_file(mp, &nb_file(system::SHIM_NAME));
        if copy.exists() {
            match shim_copy_status(mp, None) {
                Ok((src, true)) => println!("    shim copy: {} (same as {src})", copy.display()),
                Ok((src, false)) => println!(
                    "    shim copy: {} DIFFERS from {src}; run `sudo netbooty-setup maintain`",
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

    println!("\n== Installation");
    match Settings::load() {
        Ok(Some(s)) => {
            println!(
                "  settings:      {} (mode {:?}, default {})",
                settings::SETTINGS_PATH,
                s.mode,
                s.default
            );
            println!(
                "  default boot:  {}",
                if s.first { "NetBooty" } else { "not yet (`sudo netbooty-setup activate`)" }
            );
        }
        Ok(None) => println!("  settings:      none (not installed with this version)"),
        Err(e) => println!("  settings:      {e}"),
    }
    for (label, path) in [("tool", settings::SBIN_PATH), ("image", settings::IMAGE_PATH)] {
        println!("  {label:<14} {}{}", path, if Path::new(path).exists() { "" } else { " (missing)" });
    }
    if Path::new("/run/systemd/system").is_dir() {
        for unit in [settings::MAINTAIN_UNIT, settings::PATH_UNIT] {
            let state = Command::new("systemctl")
                .args(["is-enabled", unit])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            println!("  {unit:<26} {}", if state.is_empty() { "not installed" } else { &state });
        }
    }

    println!("\n== Signing key");
    let (_, _, der) = key_paths(Path::new(KEY_DIR));
    match std::fs::metadata(&der) {
        Ok(_) => println!("  {}: MOK {:?}", der.display(), system::mok_state(&der)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("  {KEY_DIR} not readable (run doctor with sudo to check)")
        }
        Err(_) => println!("  none yet (install creates one in shim mode)"),
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
