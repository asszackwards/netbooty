//! Asking the boot server over the firmware's own network stack.
//!
//! [`Query`] is a non-blocking state machine: `poll()` it from the menu loop
//! (or a wait loop) until it is done, so the network step overlaps the menu
//! countdown. In milestone 3 replies are only reported, never acted on.

mod udp4;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

use netbooty_cfg::config::Config;
use netbooty_cfg::proto;
use uefi::boot::{
    self, EventType, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol, SearchType, TimerTrigger,
    Tpl,
};
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::{Event, Handle, Status};
use uefi_raw::protocol::network::ip4_config2::{Ip4Config2DataType, Ip4Config2Policy};

use crate::entropy;
use udp4::{
    CompletionToken, ConfigData, FragmentData, Ipv4, ReceiveData, SessionData, TransmitData, Udp4,
    Udp4ServiceBinding,
};

const BROADCAST: Ipv4 = [255, 255, 255, 255];
/// Time the server gets once we have an address (the configured timeout
/// covers getting the address, which is the slow part).
const REPLY_WINDOW_MS: u32 = 1500;
const MAX_REPLY: usize = 512;

/// Most signed replies to remember nonces for (one per send).
const MAX_NONCES: usize = 8;

pub enum Outcome {
    /// The firmware exposes no UDP4 network stack (or no NIC); carries the
    /// per-layer handle report.
    NoStack(String),
    /// No DHCP lease within this many ms.
    NoAddress(u32),
    /// Nothing valid arrived; counts datagrams that failed verification.
    NoReply { rejected: u32 },
    /// No server is paired: a reply is only reported.
    Unpaired { from: Ipv4, len: usize },
    /// A correctly signed answer from the paired server.
    Answer { from: Ipv4, reply: proto::Reply },
}

fn ip(a: Ipv4) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn timer(trigger: TimerTrigger) -> Option<Event> {
    // SAFETY: no notification function; the event is only polled.
    let ev = unsafe { boot::create_event(EventType::TIMER, Tpl::CALLBACK, None, None) }.ok()?;
    boot::set_timer(&ev, trigger).ok()?;
    Some(ev)
}

/// A plain event for completion tokens; the driver signals it and we only
/// look at the token's status.
fn token_event() -> Option<Event> {
    // SAFETY: no notification function.
    unsafe { boot::create_event(EventType::empty(), Tpl::CALLBACK, None, None) }.ok()
}

fn ms(n: u32) -> core::time::Duration {
    core::time::Duration::from_millis(n as u64)
}

struct Tx {
    token: CompletionToken,
    data: TransmitData,
    session: SessionData,
    payload: [u8; proto::REQUEST_LEN],
    pending: bool,
}

/// One UDP4 child on one NIC. Boxed: tokens point into it while pending.
struct Session {
    sb: ScopedProtocol<Udp4ServiceBinding>,
    child: Handle,
    udp: Option<ScopedProtocol<Udp4>>,
    config: ConfigData,
    configured: bool,
    rx: CompletionToken,
    rx_pending: bool,
    tx: [Tx; 2],
}

impl Session {
    fn open(nic: Handle) -> Option<Box<Self>> {
        let params = OpenProtocolParams { handle: nic, agent: boot::image_handle(), controller: None };
        // SAFETY: shared access to the service binding; we only create/destroy our child.
        let mut sb =
            unsafe { boot::open_protocol::<Udp4ServiceBinding>(params, OpenProtocolAttributes::GetProtocol) }
                .ok()?;
        let mut child = ptr::null_mut();
        // SAFETY: valid protocol pointer and out-parameter.
        let st = unsafe { (sb.0.create_child)(&mut sb.0, &mut child) };
        let child = (st == Status::SUCCESS).then(|| unsafe { Handle::from_ptr(child.cast()) }).flatten()?;
        let udp = boot::open_protocol_exclusive::<Udp4>(child).ok();
        let tx = || Tx {
            token: CompletionToken {
                event: ptr::null_mut(),
                status: Status::SUCCESS,
                packet: ptr::null_mut(),
            },
            data: TransmitData {
                udp_session_data: ptr::null_mut(),
                gateway_address: ptr::null_mut(),
                data_length: 0,
                fragment_count: 1,
                fragment_table: [FragmentData { fragment_length: 0, fragment_buffer: ptr::null_mut() }],
            },
            session: SessionData::default(),
            payload: [0; proto::REQUEST_LEN],
            pending: false,
        };
        let mut s = Box::new(Session {
            sb,
            child,
            udp,
            config: ConfigData {
                time_to_live: 64,
                use_default_address: 1,
                // Ephemeral local port, no fixed peer: destinations are per packet.
                ..ConfigData::default()
            },
            configured: false,
            rx: CompletionToken { event: ptr::null_mut(), status: Status::SUCCESS, packet: ptr::null_mut() },
            rx_pending: false,
            tx: [tx(), tx()],
        });
        s.udp.as_ref()?;
        s.rx.event = token_event()?.as_ptr();
        for t in &mut s.tx {
            t.token.event = token_event()?.as_ptr();
        }
        Some(s)
    }

    fn proto(&mut self) -> *mut udp4::Udp4Protocol {
        &mut self.udp.as_mut().unwrap().0
    }

    /// Try to configure; succeeds once the interface has an address
    /// (UseDefaultAddress returns NO_MAPPING until DHCP completes, and the
    /// attempt itself starts DHCP on EDK2-based firmware).
    fn try_configure(&mut self) -> Result<bool, Status> {
        let p = self.proto();
        // SAFETY: valid protocol and config.
        let st = unsafe { ((*p).configure)(p, &self.config) };
        match st {
            Status::SUCCESS => {
                self.configured = true;
                Ok(true)
            }
            Status::NO_MAPPING => Ok(false),
            e => Err(e),
        }
    }

    fn local_address(&mut self) -> Ipv4 {
        let p = self.proto();
        let mut cfg = ConfigData::default();
        // SAFETY: valid protocol; unused outputs are null.
        let st =
            unsafe { ((*p).get_mode_data)(p, &mut cfg, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
        if st == Status::SUCCESS { cfg.station_address } else { [0; 4] }
    }

    fn post_receive(&mut self) {
        if self.rx_pending {
            return;
        }
        self.rx.status = Status::NOT_READY;
        self.rx.packet = ptr::null_mut();
        let p = self.proto();
        // SAFETY: the token lives in this boxed session until cancelled in Drop.
        let st = unsafe { ((*p).receive)(p, &mut self.rx) };
        self.rx_pending = st == Status::SUCCESS;
    }

    fn send(&mut self, slot: usize, dest: Ipv4, port: u16, payload: &[u8; proto::REQUEST_LEN]) {
        let p = self.proto();
        let t = &mut self.tx[slot];
        if t.pending {
            return; // previous send to this destination still in flight
        }
        t.payload = *payload;
        t.session =
            SessionData { destination_address: dest, destination_port: port, ..SessionData::default() };
        t.data.udp_session_data = &mut t.session;
        t.data.data_length = t.payload.len() as u32;
        t.data.fragment_table[0] = FragmentData {
            fragment_length: t.payload.len() as u32,
            fragment_buffer: t.payload.as_mut_ptr().cast(),
        };
        t.token.status = Status::NOT_READY;
        t.token.packet = (&mut t.data as *mut TransmitData).cast();
        // SAFETY: token, data, session and payload live in this boxed session.
        let st = unsafe { ((*p).transmit)(p, &mut t.token) };
        t.pending = st == Status::SUCCESS;
    }

    /// Drive the stack; returns a completed datagram, if any.
    fn poll(&mut self) -> Option<(Ipv4, Vec<u8>)> {
        let p = self.proto();
        // SAFETY: valid protocol.
        let _ = unsafe { ((*p).poll)(p) };
        for t in &mut self.tx {
            if t.pending && t.token.status != Status::NOT_READY {
                t.pending = false;
            }
        }
        if !self.rx_pending || self.rx.status == Status::NOT_READY {
            return None;
        }
        self.rx_pending = false;
        if self.rx.status != Status::SUCCESS || self.rx.packet.is_null() {
            return None;
        }
        // SAFETY: on success the driver hands us a valid RECEIVE_DATA until
        // we signal its RecycleSignal.
        let rx = unsafe { &*(self.rx.packet as *const ReceiveData) };
        let from = rx.udp_session.source_address;
        let mut data = Vec::new();
        let frags = rx.fragment_table.as_ptr();
        for i in 0..rx.fragment_count as usize {
            // SAFETY: fragment_count entries follow the declared first one.
            let f = unsafe { &*frags.add(i) };
            let take = (f.fragment_length as usize).min(MAX_REPLY - data.len());
            // SAFETY: the driver guarantees fragment_length readable bytes.
            data.extend_from_slice(unsafe {
                core::slice::from_raw_parts(f.fragment_buffer as *const u8, take)
            });
        }
        // SAFETY: the recycle event belongs to the driver; signalling returns the buffer.
        if let Some(ev) = unsafe { Event::from_ptr(rx.recycle_signal) } {
            let _ = boot::signal_event(&ev);
        }
        Some((from, data))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.udp.is_some() {
            let p = self.proto();
            // SAFETY: cancel everything pending, then reset the instance.
            unsafe {
                let _ = ((*p).cancel)(p, ptr::null_mut());
                let _ = ((*p).configure)(p, ptr::null());
            }
        }
        self.udp = None;
        // SAFETY: the child was created by this service binding.
        let _ = unsafe { (self.sb.0.destroy_child)(&mut self.sb.0, self.child.as_ptr().cast()) };
        for ev in [self.rx.event].into_iter().chain(self.tx.iter().map(|t| t.token.event)) {
            // SAFETY: events created in `open`, no longer referenced.
            if let Some(e) = unsafe { Event::from_ptr(ev) } {
                let _ = boot::close_event(e);
            }
        }
    }
}

enum Phase {
    /// Waiting for an address on any NIC. Boxed so completion tokens keep a
    /// stable address while the firmware holds pointers into them.
    #[allow(clippy::vec_box)]
    Address(Vec<Box<Session>>),
    Asking {
        session: Box<Session>,
        sends_left: u8,
    },
    Done,
}

pub struct Query {
    client_id: [u8; 16],
    keys: Vec<[u8; 32]>,
    targets: Vec<String>,
    /// Every nonce sent this boot: a reply to any of them is fresh.
    nonces: Vec<[u8; 16]>,
    rejected: u32,
    answer: Option<proto::Reply>,
    retries: u8,
    timeout_ms: u32,
    port: u16,
    server: Option<Ipv4>,
    deadline: Event,
    resend: Event,
    phase: Phase,
    status: String,
    changed: bool,
    /// Log lines, printed by the caller once the menu is closed.
    notes: Vec<String>,
}

/// NICs with a UDP4 service binding. Connects all drivers once if none are
/// found (fast-boot firmware may not have started the network stack).
fn nics() -> Vec<Handle> {
    let find = || boot::find_handles::<Udp4ServiceBinding>().unwrap_or_default();
    let mut found = find();
    if found.is_empty() {
        if let Ok(all) = boot::locate_handle_buffer(SearchType::AllHandles) {
            for h in all.iter() {
                let _ = boot::connect_controller(*h, &[], None, true);
            }
        }
        found = find();
    }
    found
}

/// Which network layers the firmware exposes, for diagnosing "no network
/// stack" (NIC driver -> MNP -> IP4 -> UDP4).
fn stack_report() -> String {
    let count = |g: uefi::Guid| boot::locate_handle_buffer(SearchType::ByProtocol(&g)).map_or(0, |h| h.len());
    let snp = count(uefi::guid!("a19832b9-ac25-11d3-9a2d-0090273fc14d"));
    let mnp = count(uefi::guid!("f36ff770-a7e1-42cf-9ed2-56f0f271f44c"));
    let mut report = format!(
        "handles: SNP {snp} MNP {mnp} IP4 {} IP4Config2 {} DHCP4 {} UDP4 {}",
        count(uefi::guid!("c51711e7-b4bf-404a-bfb8-0a048ef1ffe4")),
        count(uefi::guid!("5b446ed1-e30b-4faa-871a-3654eca36080")),
        count(uefi::guid!("9d9a39d8-bd42-4a73-a4d5-8ee94be11380")),
        count(uefi::guid!("83f01464-99bd-45e5-b383-af6305d8e9e6")),
    );
    if snp == 0 {
        report.push_str(" (no network card driver: enable the network stack / PXE in firmware setup)");
    } else if mnp == 0 {
        // EDK2 2025.02+ refuses to start its network stack without an RNG.
        report.push_str(
            " (network card found but the firmware network stack is not running: it may be \
                         disabled in firmware setup, or the firmware lacks a random number generator)",
        );
    }
    report
}

/// Make sure IPv4 on `nic` uses DHCP; only writes when it does not already
/// (the policy is stored in NVRAM).
fn ensure_dhcp(nic: Handle) -> bool {
    let Ok(mut cfg) = Ip4Config2::new(nic) else { return false };
    let current = cfg
        .get_data(Ip4Config2DataType::POLICY)
        .ok()
        .and_then(|d| d.get(..4).map(|b| i32::from_le_bytes(b.try_into().unwrap())));
    current != Some(Ip4Config2Policy::DHCP.0) && cfg.set_policy(Ip4Config2Policy::DHCP).is_ok()
}

impl Query {
    /// Start asking, or `None` when the network step is not configured.
    pub fn start(cfg: &Config) -> Option<Self> {
        if !cfg.network {
            return None;
        }
        let timeout = (cfg.net_timeout_ms as u32).max(500);
        let deadline = timer(TimerTrigger::Relative(ms(timeout)))?;
        // Armed when the address arrives (see `Phase::Asking`).
        let resend = timer(TimerTrigger::Cancel)?;
        let mut q = Query {
            client_id: cfg.client_id,
            keys: cfg.keys.clone(),
            targets: cfg.targets.iter().map(|t| t.name.clone()).collect(),
            nonces: Vec::new(),
            rejected: 0,
            answer: None,
            retries: cfg.retries,
            timeout_ms: timeout,
            port: cfg.port,
            server: cfg.server_ip,
            deadline,
            resend,
            phase: Phase::Done,
            status: String::new(),
            changed: false,
            notes: Vec::new(),
        };
        let handles = nics();
        let sessions: Vec<Box<Session>> = handles
            .into_iter()
            .filter_map(|h| {
                if ensure_dhcp(h) {
                    q.notes.push(String::from("network: switched IPv4 to DHCP"));
                }
                Session::open(h)
            })
            .collect();
        if sessions.is_empty() {
            q.finish(Outcome::NoStack(stack_report()));
        } else {
            q.set_status(String::from("waiting for an address"));
            q.phase = Phase::Address(sessions);
        }
        Some(q)
    }

    fn set_status(&mut self, s: String) {
        if s != self.status {
            self.notes.push(format!("network: {s}"));
            self.status = s;
            self.changed = true;
        }
    }

    fn finish(&mut self, outcome: Outcome) {
        let text = match &outcome {
            Outcome::NoStack(report) => format!("no network stack; {report}"),
            Outcome::NoAddress(ms) => format!("no address (DHCP) within {}.{} s", ms / 1000, ms % 1000 / 100),
            Outcome::NoReply { rejected: 0 } => String::from("no reply"),
            Outcome::NoReply { rejected } => format!("no valid reply ({rejected} rejected)"),
            Outcome::Unpaired { from, len } => format!("reply from {} ({len} bytes; not paired)", ip(*from)),
            Outcome::Answer { from, reply } => {
                self.answer = Some(reply.clone());
                match reply {
                    proto::Reply::Target(t) => format!("server {}: {t}", ip(*from)),
                    proto::Reply::NoPreference => format!("server {}: no preference", ip(*from)),
                }
            }
        };
        self.set_status(text);
        self.phase = Phase::Done;
    }

    pub fn status(&self) -> &str {
        &self.status
    }

    /// New status text since the last call, for the menu.
    pub fn take_change(&mut self) -> Option<&str> {
        core::mem::take(&mut self.changed).then_some(self.status.as_str())
    }

    pub fn take_notes(&mut self) -> Vec<String> {
        core::mem::take(&mut self.notes)
    }

    pub fn done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    /// The paired server's verified answer, once there is one.
    pub fn answer(&self) -> Option<&proto::Reply> {
        self.answer.as_ref()
    }

    /// Check a datagram: `Some` finishes the query, `None` keeps waiting.
    fn judge(&mut self, from: Ipv4, data: &[u8]) -> Option<Outcome> {
        if self.keys.is_empty() {
            return Some(Outcome::Unpaired { from, len: data.len() });
        }
        match proto::verify(data, &self.client_id, &self.nonces, &self.keys) {
            Some(proto::Reply::Target(t)) => match self.targets.iter().find(|n| n.eq_ignore_ascii_case(&t)) {
                Some(name) => Some(Outcome::Answer { from, reply: proto::Reply::Target(name.clone()) }),
                None => {
                    self.notes.push(format!("network: server named unknown target {t}; ignored"));
                    self.rejected += 1;
                    None
                }
            },
            Some(proto::Reply::NoPreference) => {
                Some(Outcome::Answer { from, reply: proto::Reply::NoPreference })
            }
            None => {
                self.rejected += 1;
                None
            }
        }
    }

    fn send_requests(&mut self) {
        let (nonce, source) = entropy::nonce();
        if source == entropy::Source::Counter {
            self.notes.push(String::from("network: no hardware RNG; using a counter nonce"));
        }
        if self.nonces.len() == MAX_NONCES {
            self.nonces.remove(0);
        }
        self.nonces.push(nonce);
        let req = proto::request(&self.client_id, &nonce);
        let (port, server) = (self.port, self.server);
        if let Phase::Asking { session, sends_left, .. } = &mut self.phase {
            session.send(0, BROADCAST, port, &req);
            if let Some(s) = server {
                session.send(1, s, port, &req);
            }
            *sends_left = sends_left.saturating_sub(1);
        }
    }

    /// Advance; cheap enough to call every ~20 ms.
    pub fn poll(&mut self) {
        if self.done() {
            return;
        }
        let expired = boot::check_event(&self.deadline).unwrap_or(false);
        match &mut self.phase {
            Phase::Address(sessions) => {
                let mut ready = None;
                let notes = &mut self.notes;
                sessions.retain_mut(|s| match s.try_configure() {
                    Ok(true) => {
                        ready.get_or_insert(());
                        true
                    }
                    Ok(false) => true,
                    Err(e) => {
                        notes.push(format!("network: UDP4 configure failed: {e:?}"));
                        false
                    }
                });
                if ready.is_some() {
                    let pos = sessions.iter().position(|s| s.configured).unwrap();
                    let mut session = sessions.swap_remove(pos);
                    sessions.clear(); // other NICs: release their children
                    let local = session.local_address();
                    session.post_receive();
                    self.phase = Phase::Asking { session, sends_left: u8::MAX };
                    let interval = REPLY_WINDOW_MS / (self.retries as u32 + 1);
                    let _ = boot::set_timer(&self.deadline, TimerTrigger::Relative(ms(REPLY_WINDOW_MS)));
                    let _ = boot::set_timer(&self.resend, TimerTrigger::Periodic(ms(interval.max(200))));
                    self.set_status(format!("asking server (from {})", ip(local)));
                    self.send_requests();
                } else if sessions.is_empty() {
                    self.finish(Outcome::NoStack(stack_report()));
                } else if expired {
                    self.finish(Outcome::NoAddress(self.timeout_ms));
                }
            }
            Phase::Asking { session, .. } => {
                let datagram = session.poll();
                session.post_receive();
                if let Some((from, data)) = datagram
                    && let Some(outcome) = self.judge(from, &data)
                {
                    self.finish(outcome);
                    return;
                }
                if expired {
                    self.finish(Outcome::NoReply { rejected: self.rejected });
                } else if boot::check_event(&self.resend).unwrap_or(false) {
                    self.send_requests();
                }
            }
            Phase::Done => {}
        }
    }

    /// Poll until done (bounded by the deadline).
    pub fn wait(&mut self) {
        while !self.done() {
            self.poll();
            boot::stall(core::time::Duration::from_millis(10));
        }
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        self.phase = Phase::Done; // releases any session first
        for ev in [&self.deadline, &self.resend] {
            // SAFETY: our own timers; closing also cancels them.
            if let Some(e) = unsafe { Event::from_ptr(ev.as_ptr()) } {
                let _ = boot::close_event(e);
            }
        }
    }
}
