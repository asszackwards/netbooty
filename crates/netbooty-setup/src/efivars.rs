//! efivarfs access (Linux). Each file is a 4-byte attribute word followed by
//! the variable data. New files can be created directly; existing ones are
//! immutable and need `chattr -i` before being rewritten or removed.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use netbooty_cfg::config::name_bytes;
use netbooty_cfg::loadopt::{LoadOption, boot_var_number};
use netbooty_cfg::{VAR_NEXT, VENDOR_GUID};

const GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const NV_BS_RT: u32 = 0x7;

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: Option<PathBuf>) -> Self {
        Self { dir: dir.unwrap_or_else(|| "/sys/firmware/efi/efivars".into()) }
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    fn global(&self, name: &str) -> Option<Vec<u8>> {
        let data = std::fs::read(self.dir.join(format!("{name}-{GLOBAL_GUID}"))).ok()?;
        Some(data.get(4..)?.to_vec())
    }

    fn global_u16(&self, name: &str) -> Option<u16> {
        self.global(name).filter(|d| d.len() == 2).map(|d| u16::from_le_bytes([d[0], d[1]]))
    }

    pub fn boot_order(&self) -> Vec<u16> {
        self.global("BootOrder")
            .map(|d| d.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect())
            .unwrap_or_default()
    }

    pub fn boot_current(&self) -> Option<u16> {
        self.global_u16("BootCurrent")
    }

    pub fn boot_next(&self) -> Option<u16> {
        self.global_u16("BootNext")
    }

    /// What NetBooty's network step reported on the last boot that ran it.
    pub fn net_status(&self) -> Option<String> {
        let data =
            std::fs::read(self.dir.join(format!("{}-{VENDOR_GUID}", netbooty_cfg::VAR_NET_STATUS))).ok()?;
        Some(String::from_utf8_lossy(data.get(4..)?).into_owned())
    }

    /// Target name of a pending NetBootyNext request.
    pub fn pending_next(&self) -> Option<String> {
        let data = std::fs::read(self.next_path()).ok()?;
        let name = data.get(4..)?;
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        Some(String::from_utf8_lossy(&name[..end]).into_owned())
    }

    fn next_path(&self) -> PathBuf {
        self.dir.join(format!("{VAR_NEXT}-{VENDOR_GUID}"))
    }

    pub fn boot_entries(&self) -> Result<Vec<(u16, LoadOption)>> {
        let rd = std::fs::read_dir(&self.dir).with_context(|| format!("reading {}", self.dir.display()))?;
        let mut out = Vec::new();
        for e in rd.flatten() {
            let fname = e.file_name().to_string_lossy().into_owned();
            let Some((var, guid)) = fname.split_once('-') else { continue };
            if !guid.eq_ignore_ascii_case(GLOBAL_GUID) {
                continue;
            }
            let Some(n) = boot_var_number(var) else { continue };
            let data = std::fs::read(e.path())?;
            if let Some(opt) = data.get(4..).and_then(LoadOption::parse) {
                out.push((n, opt));
            }
        }
        out.sort_by_key(|(n, _)| *n);
        Ok(out)
    }

    fn make_mutable(&self, p: &PathBuf) {
        // Best effort: plain directories (tests) have no immutable flag.
        let _ = Command::new("chattr").arg("-i").arg(p).status();
    }

    pub fn set_next(&self, target: &str) -> Result<()> {
        let Some(name) = name_bytes(target) else { bail!("invalid target name {target:?}") };
        let mut data = NV_BS_RT.to_le_bytes().to_vec();
        data.extend_from_slice(&name);
        let p = self.next_path();
        if p.exists() {
            self.make_mutable(&p);
        }
        std::fs::write(&p, data).with_context(|| format!("writing {} (are you root?)", p.display()))
    }

    pub fn delete_next(&self) -> Result<()> {
        let p = self.next_path();
        if !p.exists() {
            return Ok(());
        }
        self.make_mutable(&p);
        std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))
    }
}
