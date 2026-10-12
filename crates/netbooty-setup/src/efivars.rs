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
