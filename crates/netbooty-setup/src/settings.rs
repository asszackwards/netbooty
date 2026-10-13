//! Saved install settings (`/etc/netbooty/netbooty.toml`) and the locations
//! NetBooty installs itself to. A bare `netbooty-setup install` reapplies
//! the saved settings; `maintain` (run by systemd) uses them for repairs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::install::Mode;

pub const SETTINGS_PATH: &str = "/etc/netbooty/netbooty.toml";
pub const SBIN_PATH: &str = "/usr/local/sbin/netbooty-setup";
pub const IMAGE_PATH: &str = "/usr/local/lib/netbooty/netbooty.efi";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const MAINTAIN_UNIT: &str = "netbooty-maintain.service";
pub const REFRESH_UNIT: &str = "netbooty-refresh.service";
pub const PATH_UNIT: &str = "netbooty-refresh.path";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MenuArg {
    OnKey,
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResetArg {
    Warm,
    Cold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackArg {
    Exit,
    Chainload,
}

fn default_timeout() -> u16 {
    10
}

fn yes() -> bool {
    true
}

fn default_port() -> u16 {
    netbooty_cfg::config::DEFAULT_PORT
}

/// Generous on purpose: a slow link can make the firmware's first DHCP
/// request get lost, and its retry only goes out ~4 s later. The wait runs
/// during the menu countdown, so it normally costs nothing.
fn default_net_timeout() -> u16 {
    10_000
}

fn default_retries() -> u8 {
    2
}

/// Asking a boot server on the LAN. On by default: it is the point of NetBooty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NetworkSettings {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Also ask this server directly (unicast) besides broadcasting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<std::net::Ipv4Addr>,
    /// How long to wait for a network address (DHCP), in milliseconds. The
    /// server then gets another 1.5 s to answer.
    #[serde(default = "default_net_timeout")]
    pub timeout_ms: u16,
    #[serde(default = "default_retries")]
    pub retries: u8,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_port(),
            server: None,
            timeout_ms: default_net_timeout(),
            retries: default_retries(),
        }
    }
}

/// Everything needed to (re)build and install NetBooty on this machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Target specs, e.g. `name=windows,path=\EFI\Microsoft\Boot\bootmgfw.efi,part=auto,hint=auto,key=w`.
    pub targets: Vec<String>,
    /// Target name booted when nothing else decides, or `exit`.
    pub default: String,
    pub menu: MenuArg,
    #[serde(default = "default_timeout")]
    pub menu_timeout: u16,
    pub reset: ResetArg,
    pub fallback: FallbackArg,
    #[serde(default)]
    pub no_reassert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    /// NetBooty is the default boot entry (first in BootOrder).
    #[serde(default)]
    pub first: bool,
    #[serde(default)]
    pub network: NetworkSettings,
}

impl Settings {
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(Path::new(SETTINGS_PATH))
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).map(Some).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn to_toml(&self) -> Result<String> {
        let body = toml::to_string_pretty(self).context("serializing settings")?;
        Ok(format!(
            "# NetBooty install settings, written by `netbooty-setup install`.\n\
             # Edit and run `sudo netbooty-setup install` to apply.\n\n{body}"
        ))
    }
}

/// Unit files: `maintain` at boot and shutdown (catches BootOrder changes and
/// shim updates made during the session, on any distro), plus an immediate
/// refresh when the distro shim file changes.
pub fn systemd_units(esp_mount: &Path, watched_shim: Option<&Path>) -> Vec<(&'static str, String)> {
    let mount = esp_mount.display();
    let mut units = vec![(
        MAINTAIN_UNIT,
        format!(
            "[Unit]\n\
             Description=Keep NetBooty first in the firmware boot order and its shim copy current\n\
             RequiresMountsFor={mount}\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             RemainAfterExit=yes\n\
             ExecStart={SBIN_PATH} maintain\n\
             ExecStop={SBIN_PATH} maintain\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        ),
    )];
    if let Some(shim) = watched_shim {
        units.push((
            REFRESH_UNIT,
            format!(
                "[Unit]\n\
                 Description=Refresh NetBooty after a distro shim update\n\
                 RequiresMountsFor={mount}\n\
                 \n\
                 [Service]\n\
                 Type=oneshot\n\
                 ExecStart={SBIN_PATH} maintain\n"
            ),
        ));
        units.push((
            PATH_UNIT,
            format!(
                "[Unit]\n\
                 Description=Watch the distro shim for NetBooty\n\
                 \n\
                 [Path]\n\
                 PathChanged={}\n\
                 Unit={REFRESH_UNIT}\n\
                 \n\
                 [Install]\n\
                 WantedBy=multi-user.target\n",
                shim.display()
            ),
        ));
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Settings {
        Settings {
            targets: vec![
                "name=windows,path=\\EFI\\Microsoft\\Boot\\bootmgfw.efi,part=auto,hint=auto,key=w".into(),
                "name=linux,path=\\EFI\\ubuntu\\shimx64.efi,part=auto,hint=auto,key=l".into(),
            ],
            default: "linux".into(),
            menu: MenuArg::Always,
            menu_timeout: 10,
            reset: ResetArg::Warm,
            fallback: FallbackArg::Exit,
            no_reassert: false,
            client_id: None,
            mode: Mode::Shim,
            esp: None,
            shim: None,
            key: None,
            cert: None,
            first: true,
            network: NetworkSettings::default(),
        }
    }

    #[test]
    fn toml_round_trip() {
        let s = sample();
        let text = s.to_toml().unwrap();
        assert!(text.contains("menu = \"always\""));
        assert!(text.contains("mode = \"shim\""));
        assert!(!text.contains("client-id"));
        assert_eq!(toml::from_str::<Settings>(&text).unwrap(), s);
    }

    #[test]
    fn network_defaults_on_for_older_settings() {
        let mut text = sample().to_toml().unwrap();
        let cut = text.find("[network]").unwrap();
        text.truncate(cut);
        let s: Settings = toml::from_str(&text).unwrap();
        assert_eq!(s.network, NetworkSettings::default());
        assert!(s.network.enabled);
    }

    #[test]
    fn units_reference_installed_tool() {
        let u = systemd_units(Path::new("/boot/efi"), Some(Path::new("/boot/efi/EFI/ubuntu/shimx64.efi")));
        assert_eq!(u.len(), 3);
        assert!(u[0].1.contains("ExecStop=/usr/local/sbin/netbooty-setup maintain"));
        assert!(u[0].1.contains("RequiresMountsFor=/boot/efi"));
        assert!(u[2].1.contains("PathChanged=/boot/efi/EFI/ubuntu/shimx64.efi"));
        assert_eq!(systemd_units(Path::new("/efi"), None).len(), 1);
    }
}
