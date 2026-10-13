//! Host-side NetBooty tool: installs and configures NetBooty, keeps it
//! maintained, and sets one-shot boot requests from a running OS.
//! Run without arguments for the interactive setup.

mod efivars;
mod install;
mod pe;
mod settings;
mod spec;
mod system;
mod wizard;

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use install::Mode;
use settings::{FallbackArg, MenuArg, ResetArg, Settings};

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "NetBooty setup. Run without arguments for the interactive installer."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

/// Configuration written into the `.nbtycfg` section.
#[derive(Args)]
struct ConfigArgs {
    /// Target spec: name=<n>[,path=<loader path>][,desc=<text>][,part=<guid>|auto][,hint=<hex>|auto][,key=<c>].
    /// `auto` fills the value from the matching Boot#### entry on this machine.
    #[arg(long = "target")]
    targets: Vec<String>,
    /// Add a target for every OS boot entry found in the firmware.
    #[arg(long)]
    auto_targets: bool,
    /// Target name to boot when nothing else decides, or `exit` (default with
    /// --auto-targets: the OS this is run from).
    #[arg(long)]
    default: Option<String>,
    #[arg(long, value_enum, default_value = "on-key")]
    menu: MenuArg,
    /// Seconds the menu counts down before continuing automatically (`--menu always`).
    #[arg(long, default_value_t = 10)]
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

impl ConfigArgs {
    fn given(&self) -> bool {
        !self.targets.is_empty() || self.auto_targets
    }

    fn to_settings(&self, mode: Mode) -> Result<Settings> {
        let store = efivars::Store::new(self.efivars.clone());
        let mut targets = Vec::new();
        let mut auto_default = None;
        if self.auto_targets {
            let entries = store.boot_entries()?;
            let found = spec::discover(&entries);
            let current = store.boot_current();
            auto_default = found
                .iter()
                .find(|d| Some(d.boot_num) == current)
                .or_else(|| found.first())
                .map(|d| d.name.clone());
            targets.extend(found.into_iter().map(|d| d.spec));
        }
        targets.extend(self.targets.iter().cloned());
        if targets.is_empty() {
            bail!("no targets: pass --target specs or --auto-targets");
        }
        Ok(Settings {
            targets,
            default: self.default.clone().or(auto_default).unwrap_or_else(|| "exit".into()),
            menu: self.menu,
            menu_timeout: self.menu_timeout,
            reset: self.reset,
            fallback: self.fallback,
            no_reassert: self.no_reassert,
            client_id: self.client_id.clone(),
            mode,
            esp: None,
            shim: None,
            key: None,
            cert: None,
            first: false,
        })
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive installer and configurator (the default).
    Setup {
        /// Walk through everything without changing the system.
        #[arg(long)]
        dry_run: bool,
    },
    /// Install or update NetBooty. Without --target/--auto-targets it reapplies
    /// the saved settings in /etc/netbooty/netbooty.toml.
    Install {
        #[command(flatten)]
        cfg: ConfigArgs,
        /// NetBooty image to install (default: installed copy or local build).
        #[arg(long)]
        image: Option<PathBuf>,
        /// Mount point of the ESP to install to (default: auto-detect).
        #[arg(long)]
        esp: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "auto")]
        mode: Mode,
        /// ESP-relative distro shim to copy, e.g. \EFI\ubuntu\shimx64.efi (default: auto-detect).
        #[arg(long)]
        shim: Option<String>,
        /// Signing key and certificate (default: NetBooty's own key in shim mode).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Make NetBooty the default boot entry (refused while its key is not enrolled).
        #[arg(long)]
        first: bool,
        /// Show what would be done without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Make the installed NetBooty the default boot entry.
    Activate {
        #[arg(long)]
        dry_run: bool,
    },
    /// Repair and update an installed NetBooty (run by systemd at boot and shutdown).
    Maintain {
        #[arg(long)]
        dry_run: bool,
    },
    /// Ask NetBooty to boot <target> once on the next boot (`clear` cancels).
    Next {
        target: String,
        #[arg(long)]
        efivars: Option<PathBuf>,
    },
    /// Read-only report of firmware, boot entries, ESPs and NetBooty state.
    Doctor,
    /// Remove NetBooty, its boot entry, files and services (keeps signing keys).
    Uninstall {
        #[arg(long)]
        esp: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Write a configuration into a NetBooty binary (development).
    Patch {
        #[command(flatten)]
        cfg: ConfigArgs,
        input: PathBuf,
        output: PathBuf,
    },
    /// Print the configuration embedded in a NetBooty binary.
    Show { file: PathBuf },
    /// Create a dedicated Secure Boot signing key (MOK); install does this automatically.
    Keygen {
        #[arg(long, default_value = install::KEY_DIR)]
        dir: PathBuf,
    },
    /// Update NetBooty's copy of shim and MokManager; maintain does this automatically.
    RefreshShim {
        #[arg(long)]
        esp: Option<PathBuf>,
        #[arg(long)]
        shim: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
}

fn saved_settings() -> Result<Settings> {
    Settings::load()?.with_context(|| {
        format!("no saved settings in {}; run `sudo netbooty-setup` to set up", settings::SETTINGS_PATH)
    })
}

fn main() -> Result<()> {
    let interactive = std::io::stdin().is_terminal();
    let cmd = Cli::parse().cmd.unwrap_or(Cmd::Setup { dry_run: false });
    match cmd {
        Cmd::Setup { dry_run } => {
            if !interactive {
                bail!("the interactive setup needs a terminal; see `netbooty-setup --help` for commands");
            }
            wizard::run(dry_run)?;
        }
        Cmd::Install { cfg, image, esp, mode, shim, key, cert, first, dry_run } => {
            let mut s = if cfg.given() {
                let mut s = cfg.to_settings(mode)?;
                (s.esp, s.shim, s.key, s.cert) = (esp, shim, key, cert);
                s
            } else {
                saved_settings()?
            };
            s.first |= first;
            install::install(&s, install::InstallOpts { image, dry_run, interactive })?;
        }
        Cmd::Activate { dry_run } => {
            let mut s = saved_settings()?;
            s.first = true;
            install::install(&s, install::InstallOpts { image: None, dry_run, interactive })?;
        }
        Cmd::Maintain { dry_run } => install::maintain(dry_run)?,
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
        Cmd::Doctor => install::doctor()?,
        Cmd::Uninstall { esp, dry_run } => install::uninstall(esp, dry_run)?,
        Cmd::Patch { cfg, input, output } => {
            let mut image = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let current = pe::read_config(&image)?;
            let store = efivars::Store::new(cfg.efivars.clone());
            let c = spec::build_config(&cfg.to_settings(Mode::Auto)?, Some(&current), &store)?;
            pe::write_config(&mut image, &c.encode().map_err(|e| anyhow::anyhow!("invalid config: {e:?}"))?)?;
            std::fs::write(&output, &image).with_context(|| format!("writing {}", output.display()))?;
            spec::print_config(&c);
            println!("wrote {}", output.display());
        }
        Cmd::Show { file } => spec::print_config(&pe::read_config(&std::fs::read(&file)?)?),
        Cmd::Keygen { dir } => install::keygen(&dir)?,
        Cmd::RefreshShim { esp, shim, dry_run } => install::refresh_shim(esp, shim, dry_run)?,
    }
    Ok(())
}
