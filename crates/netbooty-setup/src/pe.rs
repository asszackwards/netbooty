//! Locate and rewrite the `.nbtycfg` section in a PE image, in place.

use anyhow::{Context, Result, bail};
use netbooty_cfg::config::{self, Config, MAGIC, SECTION_NAME};
use object::{Object, ObjectSection};

fn section_range(image: &[u8]) -> Result<std::ops::Range<usize>> {
    let file = object::File::parse(image).context("not a PE image")?;
    let sec = file.section_by_name(SECTION_NAME).with_context(|| format!("no {SECTION_NAME} section"))?;
    let (off, len) = sec.file_range().context("section has no file data")?;
    let (off, len) = (off as usize, len as usize);
    if len < config::SIZE || off + config::SIZE > image.len() {
        bail!("{SECTION_NAME} is {len} bytes, need {}", config::SIZE);
    }
    if image[off..off + MAGIC.len()] != MAGIC {
        bail!("{SECTION_NAME} does not start with the NetBooty magic (wrong binary or version?)");
    }
    Ok(off..off + config::SIZE)
}

pub fn read_config(image: &[u8]) -> Result<Config> {
    let r = section_range(image)?;
    Config::decode(image[r].try_into().unwrap()).map_err(|e| anyhow::anyhow!("bad embedded config: {e:?}"))
}

pub fn write_config(image: &mut [u8], cfg: &[u8; config::SIZE]) -> Result<()> {
    let r = section_range(image)?;
    image[r].copy_from_slice(cfg);
    Ok(())
}
