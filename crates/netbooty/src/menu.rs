//! Local full-screen menu (physical-presence override), styled after GRUB:
//! a framed list with the selection highlighted, arrow keys to move, Enter to
//! boot. The first row, "Automatic", is what the countdown falls through to
//! (OS request, network, default).

use alloc::format;
use alloc::string::String;
use core::time::Duration;

use netbooty_cfg::config::MenuMode;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::console::gop::{BltOp, BltPixel, GraphicsOutput};
use uefi::proto::console::text::{Color, Key, ScanCode};
use uefi::{print, system};

const TICK: Duration = Duration::from_millis(20);
const HOLD_WINDOW_MS: u32 = 250;
const IDLE_LIMIT_S: u32 = 60;

const FG: Color = Color::LightGray;
const BG: Color = Color::Black;
const HIGHLIGHT: (Color, Color) = (Color::Black, Color::LightGray);
const DIM: Color = Color::DarkGray;

const LOGO: [&str; 8] = [
    r#"          ((o))"#,
    r#"            |"#,
    r#"    .-"""-. | .-"""-."#,
    r#"   /       \|/       \"#,
    r#"  |         |         |"#,
    r#"  |         |         |"#,
    r#"   \        |        /"#,
    r#"    '-.___.-'-.___.-'"#,
];
/// Column of the mast (`|`) in `LOGO`.
const LOGO_MAST: usize = 12;

pub struct Item<'a> {
    pub name: &'a str,
    pub hotkey: Option<char>,
    pub available: bool,
}

/// Network progress for the menu: the status line, and the server's verified
/// choice once known (shown on the Automatic row).
pub struct NetUpdate {
    pub line: String,
    pub server: Option<String>,
}

pub enum Outcome {
    Pick(usize),
    /// Continue with the automatic decision (OS request, network, default).
    Auto,
}

fn read_key() -> Option<Key> {
    system::with_stdin(|i| i.read_key().ok().flatten())
}

fn key_char(k: &Key) -> Option<char> {
    match k {
        Key::Printable(c) => Some(char::from(*c).to_ascii_lowercase()),
        Key::Special(_) => None,
    }
}

/// Paint every graphics output black. Clearing the text console only clears
/// its character grid; firmware often uses a grid smaller than the screen, so
/// the vendor logo and POST messages outside it would otherwise stay visible.
fn blank_framebuffers() {
    let Ok(handles) = boot::find_handles::<GraphicsOutput>() else { return };
    for handle in handles {
        // Shared access: the console driver keeps drawing through this GOP.
        let params = OpenProtocolParams { handle, agent: boot::image_handle(), controller: None };
        let Ok(mut gop) =
            (unsafe { boot::open_protocol::<GraphicsOutput>(params, OpenProtocolAttributes::GetProtocol) })
        else {
            continue;
        };
        let dims = gop.current_mode_info().resolution();
        let _ = gop.blt(BltOp::VideoFill { color: BltPixel::new(0, 0, 0), dest: (0, 0), dims });
    }
}

/// Screen geometry and drawing helpers.
struct Screen {
    cols: usize,
    rows: usize,
}

impl Screen {
    fn open() -> Self {
        blank_framebuffers();
        system::with_stdout(|o| {
            let _ = o.set_color(FG, BG);
            let _ = o.clear();
            let _ = o.enable_cursor(false);
            let (cols, rows) = o.current_mode().ok().flatten().map_or((80, 25), |m| (m.columns(), m.rows()));
            Screen { cols, rows }
        })
    }

    fn close(&self) {
        system::with_stdout(|o| {
            let _ = o.set_color(FG, BG);
            let _ = o.clear();
            let _ = o.enable_cursor(true);
        });
    }

    fn at(&self, col: usize, row: usize, fg: Color, bg: Color, text: &str) {
        if row >= self.rows {
            return;
        }
        system::with_stdout(|o| {
            let _ = o.set_cursor_position(col, row);
            let _ = o.set_color(fg, bg);
        });
        // Never write into the last column of the last row: that scrolls.
        let max = self.cols.saturating_sub(col + usize::from(row + 1 == self.rows));
        let clipped: String = text.chars().take(max).collect();
        print!("{clipped}");
        system::with_stdout(|o| {
            let _ = o.set_color(FG, BG);
        });
    }

    /// Text centered on `row`, padded to clear what was there before.
    fn line(&self, row: usize, text: &str) {
        let w = self.cols.saturating_sub(1);
        let n = text.chars().count().min(w);
        let pad = (w - n) / 2;
        let s = format!("{:pad$}{text}{:rest$}", "", "", rest = w - n - pad);
        self.at(0, row, FG, BG, &s);
    }
}

struct Layout {
    left: usize,
    width: usize,
    top: usize,
}

struct Menu<'a> {
    scr: Screen,
    lay: Layout,
    items: &'a [Item<'a>],
    auto_label: String,
}

impl Menu<'_> {
    fn rows(&self) -> usize {
        self.items.len() + 1
    }

    fn label(&self, i: usize) -> (String, bool) {
        if i == 0 {
            return (self.auto_label.clone(), true);
        }
        let it = &self.items[i - 1];
        let key = it.hotkey.map(|c| format!("  [{c}]")).unwrap_or_default();
        let na = if it.available { "" } else { "  (not available)" };
        (format!("{}) {}{key}{na}", i, it.name), it.available)
    }

    fn draw_row(&self, i: usize, selected: bool) {
        let (text, available) = self.label(i);
        let inner = self.lay.width - 2;
        let mut s = format!(" {text}");
        let len = s.chars().count();
        if len < inner {
            s.extend(core::iter::repeat_n(' ', inner - len));
        }
        let (fg, bg) = if selected {
            HIGHLIGHT
        } else if available {
            (FG, BG)
        } else {
            (DIM, BG)
        };
        self.scr.at(self.lay.left + 1, self.lay.top + 1 + i, fg, bg, &s);
    }

    fn draw_frame(&self) {
        let w = self.lay.width;
        let bar: String = core::iter::repeat_n('─', w - 2).collect();
        let (l, t) = (self.lay.left, self.lay.top);
        self.scr.at(l, t, FG, BG, &format!("┌{bar}┐"));
        for r in 0..self.rows() {
            self.scr.at(l, t + 1 + r, FG, BG, "│");
            self.scr.at(l + w - 1, t + 1 + r, FG, BG, "│");
        }
        self.scr.at(l, t + 1 + self.rows(), FG, BG, &format!("└{bar}┘"));
    }

    fn help_row(&self) -> usize {
        self.lay.top + self.rows() + 3
    }

    fn draw_help(&self, pending: Option<&str>) {
        let r = self.help_row();
        self.scr.line(r, "Use the ↑ and ↓ keys to select an entry, Enter to boot it,");
        self.scr.line(r + 1, "or press its number or key.");
        if let Some(p) = pending {
            self.scr.line(r + 3, &format!("pending request from OS: {p}"));
        }
    }

    fn status(&self, text: &str) {
        self.scr.line(self.help_row() + 5, text);
    }

    fn network(&self, text: &str) {
        self.scr.line(self.help_row() + 7, &format!("Network: {text}"));
    }

    /// Logo above the title, starting at row 1.
    fn draw_logo(&self) {
        // Put the mast on the box's center column.
        let left = (self.lay.left + (self.lay.width - 1) / 2).saturating_sub(LOGO_MAST);
        for (i, l) in LOGO.iter().enumerate() {
            self.scr.at(left, 1 + i, FG, BG, l);
        }
    }

    fn movable(&self, i: usize) -> bool {
        i == 0 || self.items[i - 1].available
    }

    fn step(&self, from: usize, down: bool) -> usize {
        let n = self.rows();
        let mut i = from;
        loop {
            i = if down { (i + 1) % n } else { (i + n - 1) % n };
            if i == from || self.movable(i) {
                return i;
            }
        }
    }
}

/// Run the menu step. Returns `Auto` when the menu is not requested or the
/// countdown expires. `tick` is called every few milliseconds (to drive the
/// network query) and returns new network status text to show.
pub fn run(
    mode: MenuMode,
    timeout_s: u16,
    items: &[Item],
    pending: Option<&str>,
    auto_hint: Option<&str>,
    tick: &mut dyn FnMut() -> Option<NetUpdate>,
) -> Outcome {
    let triggered = match mode {
        MenuMode::Always => true,
        MenuMode::OnKey => {
            let mut waited = 0;
            loop {
                if read_key().is_some() {
                    break true;
                }
                if waited >= HOLD_WINDOW_MS {
                    break false;
                }
                let _ = tick();
                boot::stall(TICK);
                waited += TICK.as_millis() as u32;
            }
        }
    };
    if !triggered {
        return Outcome::Auto;
    }
    // Swallow the rest of a held key's auto-repeat.
    while read_key().is_some() {}

    let scr = Screen::open();
    let width = scr.cols.saturating_sub(4).clamp(20, 78);
    // The logo goes above the title only if the network line still fits below.
    let logo_h = if 3 + LOGO.len() + items.len() + 1 + 10 < scr.rows { LOGO.len() } else { 0 };
    let lay = Layout { left: (scr.cols.saturating_sub(width)) / 2, width, top: 3 + logo_h };
    let auto_label = match (pending, auto_hint) {
        (Some(p), _) => format!("Automatic (OS requested {p})"),
        (None, Some(h)) => format!("Automatic ({h})"),
        (None, None) => String::from("Automatic"),
    };
    let mut menu = Menu { scr, lay, items, auto_label };

    if logo_h > 0 {
        menu.draw_logo();
    }
    menu.scr.line(1 + logo_h, concat!("NetBooty ", env!("CARGO_PKG_VERSION")));
    menu.draw_frame();
    let mut sel = 0;
    for i in 0..menu.rows() {
        menu.draw_row(i, i == sel);
    }
    menu.draw_help(pending);

    // `always` counts down until the first key; a key-triggered menu waits.
    let mut countdown = (mode == MenuMode::Always).then_some(timeout_s as u32 * 1000);
    let mut idle_ms = 0u32;
    let mut last_shown = u32::MAX;
    let outcome = loop {
        if let Some(net) = tick() {
            menu.network(&net.line);
            // An OS request outranks the server, so keep showing it.
            if let (Some(choice), None) = (net.server, pending) {
                menu.auto_label = format!("Automatic (server: {choice})");
                menu.draw_row(0, sel == 0);
            }
        }
        if let Some(k) = read_key() {
            idle_ms = 0;
            if countdown.take().is_some() {
                menu.status("");
            }
            let mut target = None;
            match k {
                Key::Special(ScanCode::UP) => target = Some(menu.step(sel, false)),
                Key::Special(ScanCode::DOWN) => target = Some(menu.step(sel, true)),
                Key::Special(ScanCode::HOME) => target = Some(0),
                Key::Special(ScanCode::END) => {
                    target = (1..menu.rows()).rev().find(|&i| menu.movable(i)).or(Some(sel))
                }
                _ => {}
            }
            if let Some(t) = target {
                if t != sel {
                    menu.draw_row(sel, false);
                    menu.draw_row(t, true);
                    sel = t;
                }
            } else if let Some(c) = key_char(&k) {
                if c == '\r' || c == '\n' {
                    break if sel == 0 { Outcome::Auto } else { Outcome::Pick(sel - 1) };
                }
                let pick = c
                    .to_digit(10)
                    .and_then(|d| (d as usize).checked_sub(1))
                    .filter(|&i| i < items.len())
                    .or_else(|| items.iter().position(|it| it.hotkey == Some(c)));
                if let Some(i) = pick.filter(|&i| items[i].available) {
                    break Outcome::Pick(i);
                }
            }
        }
        if let Some(left) = countdown.as_mut() {
            let secs = left.div_ceil(1000);
            if secs != last_shown {
                menu.status(&format!("Automatic boot in {secs}s"));
                last_shown = secs;
            }
            if *left == 0 {
                break Outcome::Auto;
            }
            *left = left.saturating_sub(TICK.as_millis() as u32);
        } else {
            idle_ms += TICK.as_millis() as u32;
            if idle_ms >= IDLE_LIMIT_S * 1000 {
                break Outcome::Auto;
            }
        }
        boot::stall(TICK);
    };
    menu.scr.close();
    outcome
}
