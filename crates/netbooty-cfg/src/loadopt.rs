//! `EFI_LOAD_OPTION` parsing and target resolution against `Boot####` entries.
//!
//! Pure byte handling so it can be unit-tested on the host; the UEFI side only
//! enumerates variables and feeds the bytes in.

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{PartitionSig, Target};

pub const LOAD_OPTION_ACTIVE: u32 = 0x1;

const DP_END: u8 = 0x7F;
const DP_MEDIA: u8 = 0x04;
const DP_MEDIA_HD: u8 = 0x01;
const DP_MEDIA_FILE: u8 = 0x04;

/// A device path node as it appears in the raw path list.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    pub ty: u8,
    pub sub: u8,
    /// Whole node including the 4-byte header.
    pub raw: &'a [u8],
}

/// Iterate over the nodes of the first instance of a device path.
/// Stops at the end node or on malformed input.
pub fn nodes(dp: &[u8]) -> impl Iterator<Item = Node<'_>> {
    let mut rest = dp;
    core::iter::from_fn(move || {
        if rest.len() < 4 {
            return None;
        }
        let ty = rest[0];
        let sub = rest[1];
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if ty == DP_END || len < 4 || len > rest.len() {
            return None;
        }
        let (raw, tail) = rest.split_at(len);
        rest = tail;
        Some(Node { ty, sub, raw })
    })
}

/// Byte offset of the hard-drive node within `dp`, if any.
pub fn hd_node_offset(dp: &[u8]) -> Option<usize> {
    let mut off = 0;
    for n in nodes(dp) {
        if n.ty == DP_MEDIA && n.sub == DP_MEDIA_HD {
            return Some(off);
        }
        off += n.raw.len();
    }
    None
}

/// Partition signature from an HD node (`HARDDRIVE_DEVICE_PATH`, 42 bytes).
pub fn hd_signature(node: &[u8]) -> Option<PartitionSig> {
    if node.len() < 42 {
        return None;
    }
    let sig_type = node[41];
    if sig_type != 1 && sig_type != 2 {
        return None;
    }
    let mut sig: [u8; 16] = node[24..40].try_into().ok()?;
    if sig_type == 1 {
        sig[4..].fill(0);
    }
    Some(PartitionSig { sig_type, sig })
}

fn utf16_nul(bytes: &[u8]) -> (String, usize) {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let consumed = (units.len() + 1) * 2;
    (String::from_utf16_lossy(&units), consumed)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    /// Raw `FilePathList` (first instance up to the end node, inclusive).
    pub file_path_list: Vec<u8>,
    /// Concatenated media file path nodes, e.g. `\EFI\ubuntu\shimx64.efi`.
    pub loader_path: String,
    pub partition: Option<PartitionSig>,
    /// Bytes after the device path (e.g. the second-stage path shim reads).
    pub optional_data: Vec<u8>,
}

impl LoadOption {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 6 {
            return None;
        }
        let attributes = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let fpl_len = u16::from_le_bytes([b[4], b[5]]) as usize;
        let (description, used) = utf16_nul(&b[6..]);
        let fpl_start = 6 + used;
        let file_path_list = b.get(fpl_start..fpl_start + fpl_len)?.to_vec();

        let mut loader_path = String::new();
        let mut partition = None;
        for n in nodes(&file_path_list) {
            match (n.ty, n.sub) {
                (DP_MEDIA, DP_MEDIA_HD) => partition = hd_signature(n.raw),
                (DP_MEDIA, DP_MEDIA_FILE) => {
                    let (part, _) = utf16_nul(&n.raw[4..]);
                    if !loader_path.is_empty() && !loader_path.ends_with('\\') && !part.starts_with('\\') {
                        loader_path.push('\\');
                    }
                    loader_path.push_str(&part);
                }
                _ => {}
            }
        }
        let optional_data = b[fpl_start + fpl_len..].to_vec();
        Some(Self { attributes, description, file_path_list, loader_path, partition, optional_data })
    }

    /// Optional data read as a NUL-terminated UCS-2 string, as shim does.
    pub fn optional_text(&self) -> Option<String> {
        if self.optional_data.len() < 2 || !self.optional_data.len().is_multiple_of(2) {
            return None;
        }
        Some(utf16_nul(&self.optional_data).0)
    }

    pub fn active(&self) -> bool {
        self.attributes & LOAD_OPTION_ACTIVE != 0
    }
}

/// Normalize a loader path for comparison: backslashes, no leading separator,
/// ASCII-lowercased (FAT is case-insensitive).
fn norm_path(p: &str) -> String {
    let p: String = p.chars().map(|c| if c == '/' { '\\' } else { c.to_ascii_lowercase() }).collect();
    String::from(p.trim_start_matches('\\'))
}

/// `entry` ends with `want` on a path-component boundary.
fn path_suffix_match(entry: &str, want: &str) -> bool {
    let (e, w) = (norm_path(entry), norm_path(want));
    if w.is_empty() || !e.ends_with(&w) {
        return false;
    }
    let cut = e.len() - w.len();
    cut == 0 || e.as_bytes()[cut - 1] == b'\\'
}

fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    let hay = hay.to_lowercase();
    hay.contains(&needle.to_lowercase())
}

/// Does this entry start `image_path` (an ESP-relative path such as
/// `\\EFI\\netbooty\\grubx64.efi`)? Either directly, as shim's second stage
/// via a path argument, or through a loader in the same directory (a private
/// shim copy whose default second stage is the image).
pub fn launches(opt: &LoadOption, image_path: &str) -> bool {
    let want = norm_path(image_path);
    if want.is_empty() {
        return false;
    }
    let loader = norm_path(&opt.loader_path);
    let dir = |p: &str| p.rsplit_once('\\').map(|(d, _)| String::from(d));
    loader == want
        || opt.optional_text().is_some_and(|t| norm_path(&t) == want)
        || (dir(&want).is_some() && dir(&loader) == dir(&want))
}

/// Does this `Boot####` entry satisfy every enabled match rule of `t`?
pub fn matches(t: &Target, opt: &LoadOption) -> bool {
    let m = t.matching;
    if !m.any() {
        return false;
    }
    if m.path && !path_suffix_match(&opt.loader_path, &t.loader_path) {
        return false;
    }
    if m.description && (t.description.is_empty() || !contains_ignore_case(&opt.description, &t.description))
    {
        return false;
    }
    if m.partition && (t.partition.is_none() || opt.partition != t.partition) {
        return false;
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Found(u16),
    NotFound,
    /// Several entries match and they point at different things.
    Ambiguous,
}

/// Resolve `t` against the given `(boot_num, option)` list.
///
/// The hint wins if it still matches. Otherwise exactly one distinct match is
/// required; firmware-duplicated entries (same partition and path) count as one,
/// and active entries are preferred over inactive ones.
pub fn resolve(t: &Target, entries: &[(u16, LoadOption)], exclude: Option<u16>) -> Resolution {
    let candidates: Vec<&(u16, LoadOption)> =
        entries.iter().filter(|(n, o)| Some(*n) != exclude && matches(t, o)).collect();

    if let Some(h) = t.boot_num_hint
        && candidates.iter().any(|(n, _)| *n == h)
    {
        return Resolution::Found(h);
    }

    let active: Vec<_> = candidates.iter().filter(|(_, o)| o.active()).copied().collect();
    let pool = if active.is_empty() { candidates } else { active };
    let Some(&&(first, ref first_opt)) = pool.first() else {
        return Resolution::NotFound;
    };
    let same_thing = |o: &LoadOption| {
        o.partition == first_opt.partition && norm_path(&o.loader_path) == norm_path(&first_opt.loader_path)
    };
    if pool.iter().all(|(_, o)| same_thing(o)) {
        Resolution::Found(pool.iter().map(|(n, _)| *n).min().unwrap_or(first))
    } else {
        Resolution::Ambiguous
    }
}

/// Parse `Boot####` (exactly four uppercase hex digits).
pub fn boot_var_number(name: &str) -> Option<u16> {
    let hex = name.strip_prefix("Boot")?;
    if hex.len() != 4 || !hex.bytes().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)) {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

/// Builders used by tests here and by host tools that synthesize entries.
pub mod build {
    use alloc::vec::Vec;

    pub fn hd_node(part_num: u32, start: u64, size: u64, sig_type: u8, sig: [u8; 16]) -> Vec<u8> {
        let mut n = Vec::with_capacity(42);
        n.extend_from_slice(&[0x04, 0x01, 42, 0]);
        n.extend_from_slice(&part_num.to_le_bytes());
        n.extend_from_slice(&start.to_le_bytes());
        n.extend_from_slice(&size.to_le_bytes());
        n.extend_from_slice(&sig);
        n.push(if sig_type == 2 { 2 } else { 1 }); // partition format: 1 MBR, 2 GPT
        n.push(sig_type);
        n
    }

    pub fn file_node(path: &str) -> Vec<u8> {
        let units: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();
        let len = 4 + units.len() * 2;
        let mut n = Vec::with_capacity(len);
        n.extend_from_slice(&[0x04, 0x04]);
        n.extend_from_slice(&(len as u16).to_le_bytes());
        for u in units {
            n.extend_from_slice(&u.to_le_bytes());
        }
        n
    }

    pub fn end_node() -> [u8; 4] {
        [0x7F, 0xFF, 4, 0]
    }

    pub fn load_option(
        attributes: u32,
        description: &str,
        file_path_list: &[u8],
        optional: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&attributes.to_le_bytes());
        b.extend_from_slice(&(file_path_list.len() as u16).to_le_bytes());
        for u in description.encode_utf16().chain(core::iter::once(0)) {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b.extend_from_slice(file_path_list);
        b.extend_from_slice(optional);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;
    use crate::config::MatchFlags;
    use alloc::string::ToString;
    use alloc::vec;

    const GUID_A: [u8; 16] = [0xA; 16];
    const GUID_B: [u8; 16] = [0xB; 16];

    fn entry(attr: u32, desc: &str, sig: Option<[u8; 16]>, path: &str) -> LoadOption {
        let mut fpl = Vec::new();
        if let Some(s) = sig {
            fpl.extend(hd_node(1, 2048, 1 << 20, 2, s));
        }
        fpl.extend(file_node(path));
        fpl.extend(end_node());
        LoadOption::parse(&load_option(attr, desc, &fpl, b"opt")).unwrap()
    }

    fn target(path: &str, desc: &str, part: Option<[u8; 16]>) -> Target {
        Target {
            name: "t".to_string(),
            hotkey: None,
            matching: MatchFlags {
                path: !path.is_empty(),
                description: !desc.is_empty(),
                partition: part.is_some(),
            },
            boot_num_hint: None,
            partition: part.map(|sig| PartitionSig { sig_type: 2, sig }),
            description: desc.to_string(),
            loader_path: path.to_string(),
        }
    }

    #[test]
    fn parses_entry() {
        let o = entry(1, "Windows Boot Manager", Some(GUID_A), "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        assert!(o.active());
        assert_eq!(o.description, "Windows Boot Manager");
        assert_eq!(o.loader_path, "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        assert_eq!(o.partition, Some(PartitionSig { sig_type: 2, sig: GUID_A }));
        assert_eq!(hd_node_offset(&o.file_path_list), Some(0));
        assert_eq!(o.optional_data, b"opt");
        assert_eq!(o.optional_text(), None);

        let mut fpl = file_node("\\EFI\\ubuntu\\shimx64.efi");
        fpl.extend(end_node());
        let data: Vec<u8> =
            "\\EFI\\netbooty\\netbooty.efi".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let o = LoadOption::parse(&load_option(1, "NetBooty", &fpl, &data)).unwrap();
        assert_eq!(o.optional_text().as_deref(), Some("\\EFI\\netbooty\\netbooty.efi"));
    }

    #[test]
    fn rejects_truncated() {
        let b = load_option(1, "x", &[0x04, 0x04, 0x40, 0x00], b"");
        assert!(LoadOption::parse(&b[..b.len() - 1]).is_none());
        assert!(LoadOption::parse(&[1, 0, 0]).is_none());
    }

    #[test]
    fn path_matching() {
        assert!(path_suffix_match(
            "\\EFI\\Microsoft\\Boot\\BOOTMGFW.EFI",
            "/efi/microsoft/boot/bootmgfw.efi"
        ));
        assert!(path_suffix_match("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", "bootmgfw.efi"));
        assert!(!path_suffix_match("\\EFI\\x\\notbootmgfw.efi", "bootmgfw.efi"));
        assert!(!path_suffix_match("\\EFI\\x\\a.efi", ""));
    }

    #[test]
    fn vendor_style_description() {
        let e = vec![(
            3,
            entry(
                1,
                "Windows Boot Manager (P1: Samsung SSD 980)",
                Some(GUID_B),
                "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            ),
        )];
        assert_eq!(resolve(&target("", "windows boot manager", None), &e, None), Resolution::Found(3));
    }

    #[test]
    fn two_disks_same_fallback_path() {
        let e = vec![
            (1, entry(1, "UEFI OS", Some(GUID_A), "\\EFI\\BOOT\\BOOTX64.EFI")),
            (2, entry(1, "UEFI OS", Some(GUID_B), "\\EFI\\BOOT\\BOOTX64.EFI")),
        ];
        assert_eq!(resolve(&target("\\EFI\\BOOT\\BOOTX64.EFI", "", None), &e, None), Resolution::Ambiguous);
        assert_eq!(
            resolve(&target("\\EFI\\BOOT\\BOOTX64.EFI", "", Some(GUID_B)), &e, None),
            Resolution::Found(2)
        );
    }

    #[test]
    fn hint_renumber_duplicates_and_exclude() {
        let mut t = target("\\EFI\\ubuntu\\shimx64.efi", "", Some(GUID_A));
        let e = vec![
            (5, entry(1, "ubuntu", Some(GUID_A), "\\EFI\\ubuntu\\shimx64.efi")),
            (9, entry(1, "ubuntu", Some(GUID_A), "\\EFI\\ubuntu\\shimx64.efi")),
        ];
        // Firmware duplicates resolve to the lowest number.
        assert_eq!(resolve(&t, &e, None), Resolution::Found(5));
        // A still-valid hint wins.
        t.boot_num_hint = Some(9);
        assert_eq!(resolve(&t, &e, None), Resolution::Found(9));
        // A stale hint falls back to matching.
        t.boot_num_hint = Some(1);
        assert_eq!(resolve(&t, &e, None), Resolution::Found(5));
        // NetBooty's own entry is never a target.
        assert_eq!(resolve(&t, &e, Some(5)), Resolution::Found(9));
        assert_eq!(resolve(&target("\\EFI\\fedora\\shimx64.efi", "", None), &e, None), Resolution::NotFound);
    }

    #[test]
    fn prefers_active() {
        let e = vec![
            (1, entry(0, "old", Some(GUID_A), "\\EFI\\Microsoft\\Boot\\bootmgfw.efi")),
            (2, entry(1, "new", Some(GUID_B), "\\EFI\\Microsoft\\Boot\\bootmgfw.efi")),
        ];
        assert_eq!(resolve(&target("bootmgfw.efi", "", None), &e, None), Resolution::Found(2));
    }

    #[test]
    fn recognizes_entries_that_launch_netbooty() {
        let direct = entry(1, "NetBooty", Some(GUID_A), "\\EFI\\netbooty\\netbooty.efi");
        assert!(launches(&direct, "\\EFI\\NETBOOTY\\netbooty.efi"));
        let mut fpl = hd_node(1, 2048, 1 << 20, 2, GUID_A);
        fpl.extend(file_node("\\EFI\\ubuntu\\shimx64.efi"));
        fpl.extend(end_node());
        let data: Vec<u8> =
            "\\EFI\\netbooty\\netbooty.efi".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let chained = LoadOption::parse(&load_option(1, "x", &fpl, &data)).unwrap();
        assert!(launches(&chained, "\\EFI\\netbooty\\netbooty.efi"));
        let ubuntu = entry(1, "ubuntu", Some(GUID_A), "\\EFI\\ubuntu\\shimx64.efi");
        assert!(!launches(&ubuntu, "\\EFI\\netbooty\\netbooty.efi"));
        assert!(!launches(&ubuntu, ""));
        // Private shim copy next to NetBooty (installed as grubx64.efi).
        let copy = entry(1, "NetBooty", Some(GUID_A), "\\EFI\\netbooty\\shimx64.efi");
        assert!(launches(&copy, "\\EFI\\netbooty\\grubx64.efi"));
        assert!(!launches(&ubuntu, "\\EFI\\netbooty\\grubx64.efi"));
    }

    #[test]
    fn boot_var_names() {
        assert_eq!(boot_var_number("Boot00A1"), Some(0xA1));
        assert_eq!(boot_var_number("BootOrder"), None);
        assert_eq!(boot_var_number("Boot00a1"), None);
        assert_eq!(boot_var_number("Boot1"), None);
    }
}
