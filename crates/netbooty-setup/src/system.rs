//! Read-only inspection of the running system: ESPs, shims, Secure Boot and
//! MOK state. Uses only util-linux (`lsblk`) and sysfs, so it works on any
//! distro.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";

#[cfg(target_arch = "x86_64")]
pub const SHIM_NAME: &str = "shimx64.efi";
#[cfg(target_arch = "x86_64")]
pub const MM_NAME: &str = "mmx64.efi";
/// The second stage shim loads by default from its own directory.
#[cfg(target_arch = "x86_64")]
pub const GRUB_NAME: &str = "grubx64.efi";
#[cfg(target_arch = "aarch64")]
pub const SHIM_NAME: &str = "shimaa64.efi";
#[cfg(target_arch = "aarch64")]
pub const MM_NAME: &str = "mmaa64.efi";
#[cfg(target_arch = "aarch64")]
pub const GRUB_NAME: &str = "grubaa64.efi";

#[derive(Clone, Debug)]
pub struct Esp {
    /// e.g. /dev/nvme1n1p1
    pub device: String,
    /// e.g. /dev/nvme1n1
    pub disk: String,
    pub part_num: u32,
    pub part_uuid: String,
    pub mount: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Lsblk {
    blockdevices: Vec<Dev>,
}

#[derive(Deserialize)]
struct Dev {
    path: String,
    parttype: Option<String>,
    partuuid: Option<String>,
    pkname: Option<String>,
    partn: Option<u32>,
    #[serde(default)]
    mountpoints: Vec<Option<String>>,
}

fn parse_lsblk(json: &str) -> Result<Vec<Esp>> {
    let l: Lsblk = serde_json::from_str(json).context("parsing lsblk output")?;
    Ok(l.blockdevices
        .into_iter()
        .filter(|d| d.parttype.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(ESP_TYPE)))
        .filter_map(|d| {
            Some(Esp {
                disk: format!("/dev/{}", d.pkname?),
                part_num: d.partn?,
                part_uuid: d.partuuid?.to_ascii_lowercase(),
                mount: d.mountpoints.into_iter().flatten().next().map(PathBuf::from),
                device: d.path,
            })
        })
        .collect())
}

/// All EFI system partitions, mounted or not.
pub fn esps() -> Result<Vec<Esp>> {
    let out = Command::new("lsblk")
        .args(["-J", "-l", "-o", "PATH,PARTTYPE,PARTUUID,PKNAME,PARTN,MOUNTPOINTS"])
        .output()
        .context("running lsblk")?;
    if !out.status.success() {
        bail!("lsblk failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    parse_lsblk(&String::from_utf8_lossy(&out.stdout))
}

/// Shims installed on a mounted ESP, as ESP-relative paths (`\EFI\ubuntu\shimx64.efi`).
pub fn shims(esp_mount: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let efi = ["EFI", "efi"].iter().map(|d| esp_mount.join(d)).find(|p| p.is_dir());
    let Some(efi) = efi else { return out };
    let Ok(rd) = std::fs::read_dir(&efi) else { return out };
    for vendor in rd.flatten() {
        let Ok(files) = std::fs::read_dir(vendor.path()) else { continue };
        for f in files.flatten() {
            let name = f.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case(SHIM_NAME) {
                let rel = f.path().strip_prefix(esp_mount).unwrap().to_string_lossy().replace('/', "\\");
                out.push(format!("\\{rel}"));
            }
        }
    }
    out.sort();
    out
}

/// `\EFI\x\y.efi` on the ESP -> host path.
pub fn esp_file(esp_mount: &Path, rel: &str) -> PathBuf {
    esp_mount.join(rel.trim_start_matches('\\').replace('\\', "/"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureBoot {
    Enabled,
    Disabled,
    SetupMode,
    Unknown,
}

fn efivar_byte(dir: &Path, name: &str) -> Option<u8> {
    let data = std::fs::read(dir.join(format!("{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c"))).ok()?;
    data.get(4).copied()
}

pub fn secure_boot(efivars: &Path) -> SecureBoot {
    match (efivar_byte(efivars, "SecureBoot"), efivar_byte(efivars, "SetupMode")) {
        (_, Some(1)) => SecureBoot::SetupMode,
        (Some(1), _) => SecureBoot::Enabled,
        (Some(0), _) => SecureBoot::Disabled,
        _ => SecureBoot::Unknown,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MokState {
    Enrolled,
    /// Queued with `mokutil --import`; completes in MokManager on next boot.
    Pending,
    NotEnrolled,
    Unknown,
}

pub fn mok_state(cert_der: &Path) -> MokState {
    let Ok(out) = Command::new("mokutil").arg("--test-key").arg(cert_der).output() else {
        return MokState::Unknown;
    };
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase()
        + &String::from_utf8_lossy(&out.stderr).to_lowercase();
    if text.contains("already enrolled") {
        MokState::Enrolled
    } else if text.contains("already in the enrollment request") {
        MokState::Pending
    } else if text.contains("not enrolled") {
        MokState::NotEnrolled
    } else {
        MokState::Unknown
    }
}

pub fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_esps_on_two_disks() {
        let json = r#"{"blockdevices":[
          {"path":"/dev/nvme1n1","parttype":null,"partuuid":null,"pkname":null,"partn":null,"mountpoints":[null]},
          {"path":"/dev/nvme1n1p1","parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","partuuid":"3980F2D7-4E9B-4301-BF27-9DABA1FD142E","pkname":"nvme1n1","partn":1,"mountpoints":["/boot/efi"]},
          {"path":"/dev/nvme1n1p2","parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4","partuuid":"8f6e949b","pkname":"nvme1n1","partn":2,"mountpoints":["/"]},
          {"path":"/dev/nvme0n1p1","parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","partuuid":"7be512cf-5ef4-493f-b1a1-fad7452080cf","pkname":"nvme0n1","partn":1,"mountpoints":[null]}
        ]}"#;
        let e = parse_lsblk(json).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].disk, "/dev/nvme1n1");
        assert_eq!(e[0].part_num, 1);
        assert_eq!(e[0].part_uuid, "3980f2d7-4e9b-4301-bf27-9daba1fd142e");
        assert_eq!(e[0].mount.as_deref(), Some(Path::new("/boot/efi")));
        assert_eq!(e[1].mount, None);
    }

    #[test]
    fn esp_relative_paths() {
        assert_eq!(
            esp_file(Path::new("/boot/efi"), "\\EFI\\netbooty\\netbooty.efi"),
            PathBuf::from("/boot/efi/EFI/netbooty/netbooty.efi")
        );
    }
}
