//! Local text menu (physical-presence override).

use core::time::Duration;

use netbooty_cfg::config::MenuMode;
use uefi::boot;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::{print, println, system};

const TICK: Duration = Duration::from_millis(20);
const HOLD_WINDOW_MS: u32 = 250;
const IDLE_LIMIT_S: u32 = 60;

pub struct Item<'a> {
    pub name: &'a str,
    pub hotkey: Option<char>,
    pub available: bool,
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

/// Map a key press to a menu action. `None` means "not a menu key".
fn action(k: &Key, items: &[Item]) -> Option<Outcome> {
    if matches!(k, Key::Special(ScanCode::ESCAPE)) {
        return Some(Outcome::Auto);
    }
    let c = key_char(k)?;
    if c == '\r' || c == '\n' {
        return Some(Outcome::Auto);
    }
    let pick = c
        .to_digit(10)
        .and_then(|d| (d as usize).checked_sub(1))
        .filter(|&i| i < items.len())
        .or_else(|| items.iter().position(|it| it.hotkey == Some(c)))?;
    items[pick].available.then_some(Outcome::Pick(pick))
}

fn draw(items: &[Item], pending: Option<&str>) {
    println!();
    println!("NetBooty - choose what to boot:");
    for (i, it) in items.iter().enumerate() {
        let key = it.hotkey.map(|c| alloc::format!(" [{c}]")).unwrap_or_default();
        let na = if it.available { "" } else { "  (not available)" };
        println!("  {}) {}{}{}", i + 1, it.name, key, na);
    }
    if let Some(p) = pending {
        println!("  pending request from OS: {p}");
    }
    println!("  Enter) automatic");
}

/// Run the menu step. Returns `Auto` when the menu is not requested or the
/// countdown expires.
pub fn run(mode: MenuMode, timeout_s: u16, items: &[Item], pending: Option<&str>) -> Outcome {
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

    draw(items, pending);
    // A key-triggered menu waits for a choice; `always` counts down until a key.
    let mut countdown = (mode == MenuMode::Always).then_some(timeout_s as u32 * 1000);
    let mut idle_ms = 0u32;
    let mut last_shown = u32::MAX;
    loop {
        if let Some(k) = read_key() {
            idle_ms = 0;
            if countdown.take().is_some() {
                println!();
                println!("countdown stopped");
            }
            if let Some(o) = action(&k, items) {
                println!();
                return o;
            }
        }
        if let Some(left) = countdown.as_mut() {
            let secs = left.div_ceil(1000);
            if secs != last_shown {
                print!("\rautomatic in {secs}s ");
                last_shown = secs;
            }
            if *left == 0 {
                println!();
                return Outcome::Auto;
            }
            *left = left.saturating_sub(TICK.as_millis() as u32);
        } else {
            idle_ms += TICK.as_millis() as u32;
            if idle_ms >= IDLE_LIMIT_S * 1000 {
                println!("no input for {IDLE_LIMIT_S}s, continuing automatically");
                return Outcome::Auto;
            }
        }
        boot::stall(TICK);
    }
}
