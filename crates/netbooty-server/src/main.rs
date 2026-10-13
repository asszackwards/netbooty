//! NetBooty boot server: answers NetBooty's requests on the LAN with signed
//! replies naming the OS each approved PC should boot. It is the only holder
//! of the private key; the web app only edits the state file.

mod serve;
mod store;

use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use netbooty_cfg::config::valid_name;

use store::{Client, Once, Store, hex, now};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Data directory (key/ and state/ live here).
    #[arg(long, env = "NETBOOTY_DATA", default_value = "/var/lib/netbooty", global = true)]
    data: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Net {
    #[arg(long, env = "NETBOOTY_PORT", default_value_t = netbooty_cfg::proto::DEFAULT_PORT)]
    port: u16,
    /// Address put in the pairing code so PCs also ask this server directly
    /// (default: this host's LAN address; `none` to leave it out).
    #[arg(long, env = "NETBOOTY_ADVERTISE_IP")]
    advertise_ip: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the responder (creates a key on first start).
    Serve {
        #[command(flatten)]
        net: Net,
        #[arg(long, env = "NETBOOTY_BIND", default_value = "0.0.0.0")]
        bind: Ipv4Addr,
    },
    /// Create the signing key; `--next` starts a rotation, `--promote` finishes it.
    Keygen {
        #[arg(long, conflicts_with = "promote")]
        next: bool,
        #[arg(long)]
        promote: bool,
        #[command(flatten)]
        net: Net,
    },
    /// Print the pairing code for `netbooty-setup pair`.
    Pair {
        #[command(flatten)]
        net: Net,
    },
    /// Approved PCs and pairing requests.
    #[command(subcommand)]
    Client(ClientCmd),
    /// Set a PC's persistent choice (`none` = no preference).
    Set { pc: String, target: String },
    /// Boot a target once on the PC's next boot.
    Next { pc: String, target: String },
    /// Show PCs, requests and what each was last told.
    Status,
}

#[derive(Subcommand)]
enum ClientCmd {
    /// List approved PCs and pending pairing requests.
    List,
    /// Approve a pending request (by client ID, ID prefix or hostname).
    Approve {
        request: String,
        #[arg(long)]
        name: Option<String>,
        /// Comma-separated target names (default: those the PC announced).
        #[arg(long)]
        targets: Option<String>,
    },
    /// Approve a PC by its client ID without a pending request.
    Add {
        client_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        targets: Option<String>,
    },
    /// Remove an approved PC.
    Rm { pc: String },
    /// Dismiss a pending request.
    Dismiss { request: String },
}

/// This host's LAN address: the source address the OS would use to reach
/// the internet. No packet is sent.
fn lan_ip() -> Option<[u8; 4]> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip.octets()),
        _ => None,
    }
}

/// The address for the pairing code, and whether it was set explicitly.
fn advertise(net: &Net) -> Result<(Option<[u8; 4]>, bool)> {
    match net.advertise_ip.as_deref() {
        Some("none") => Ok((None, true)),
        Some(s) => {
            Ok((Some(s.parse::<Ipv4Addr>().with_context(|| format!("bad address {s:?}"))?.octets()), true))
        }
        None => Ok((lan_ip(), false)),
    }
}

/// Detected inside a container that is not on the host's network (its
/// address is on a Docker bridge): broadcasts from PCs will not reach it.
fn container_network_warning(ip: Option<[u8; 4]>, port: u16) -> Option<String> {
    let ip = ip?;
    let in_container =
        std::path::Path::new("/.dockerenv").exists() || std::path::Path::new("/run/.containerenv").exists();
    let bridge = ip[0] == 172 && (16..32).contains(&ip[1]);
    (in_container && bridge).then(|| {
        format!(
            "warning: this responder seems to be on a container network ({}). PCs find it by broadcast, which \
             only works with host networking (`network_mode: host` in compose.yaml); otherwise publish UDP \
             {port} and set NETBOOTY_ADVERTISE_IP to the host's LAN address.",
            Ipv4Addr::from(ip),
        )
    })
}

fn random_seed() -> Result<[u8; 32]> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(s)
}

fn parse_targets(s: &str) -> Result<Vec<String>> {
    let t: Vec<String> = s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
    if let Some(bad) = t.iter().find(|x| !valid_name(x)) {
        bail!("invalid target name {bad:?}");
    }
    Ok(t)
}

/// Find an approved PC by name, client ID or ID prefix.
fn find_pc(state: &store::State, key: &str) -> Result<String> {
    let k = key.to_ascii_lowercase();
    let hits: Vec<&String> = state
        .clients
        .iter()
        .filter(|(id, c)| {
            c.name.eq_ignore_ascii_case(&k) || **id == k || (k.len() >= 6 && id.starts_with(&k))
        })
        .map(|(id, _)| id)
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no approved PC named {key:?} (see `netbooty-server client list`)"),
        _ => bail!("{key:?} matches several PCs"),
    }
}

fn find_request(reqs: &store::Requests, key: &str) -> Result<String> {
    let k = key.to_ascii_lowercase();
    let hits: Vec<&String> = reqs
        .requests
        .iter()
        .filter(|(id, r)| {
            **id == k
                || (k.len() >= 6 && id.starts_with(&k))
                || r.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(&k))
        })
        .map(|(id, _)| id)
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no pending request matches {key:?}"),
        _ => bail!("{key:?} matches several requests"),
    }
}

fn check_target(client: &Client, target: &str) -> Result<()> {
    if !valid_name(target) {
        bail!("invalid target name {target:?}");
    }
    if !client.targets.is_empty() && !client.targets.iter().any(|t| t.eq_ignore_ascii_case(target)) {
        bail!("{} has no target {target:?} (targets: {})", client.name, client.targets.join(", "));
    }
    Ok(())
}

fn print_status(st: &Store) -> Result<()> {
    let state = st.state()?;
    let status = st.status()?;
    let reqs = st.requests()?;
    println!("PCs:");
    if state.clients.is_empty() {
        println!("  (none approved)");
    }
    for (id, c) in &state.clients {
        let s = status.clients.get(id);
        let once =
            c.once.as_ref().filter(|o| s.and_then(|s| s.once_served.as_ref()).is_none_or(|x| x.id != o.id));
        println!(
            "  {:<15} choice={:<12} {}targets={} id={}",
            c.name,
            c.choice.as_deref().unwrap_or("(none)"),
            once.map(|o| format!("once={} ", o.target)).unwrap_or_default(),
            c.targets.join(","),
            &id[..12],
        );
        if let Some(s) = s {
            let ago = now().saturating_sub(s.last_seen);
            let ans = if s.last_answer.is_empty() { "no preference" } else { &s.last_answer };
            println!("  {:<15} last asked {ago}s ago from {}, answered {ans}", "", s.from);
        }
    }
    println!("Pairing requests:");
    if reqs.requests.is_empty() {
        println!("  (none)");
    }
    for (id, r) in reqs
        .requests
        .iter()
        .filter(|(id, _)| !state.clients.contains_key(*id) && !state.dismissed.contains(id))
    {
        println!(
            "  {} host={} from={} targets={}",
            &id[..12],
            r.hostname.as_deref().unwrap_or("?"),
            r.from,
            if r.targets.is_empty() { "?".into() } else { r.targets.join(",") }
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let st = Store::new(&cli.data);
    match cli.cmd {
        Cmd::Serve { net, bind } => {
            if st.seed("current")?.is_none() {
                st.write_seed("current", &random_seed()?)?;
                println!("created a new signing key");
            }
            let (ip, configured) = advertise(&net)?;
            if !configured && let Some(w) = container_network_warning(ip, net.port) {
                eprintln!("{w}");
            }
            let public = st.publish(net.port, ip, configured)?;
            println!("fingerprint {}", public.fingerprints.join(" / "));
            println!("pairing code: {}", public.pairing_code);
            serve::serve(&st, bind, net.port, &public.pairing_code)?;
        }
        Cmd::Keygen { next, promote, net } => {
            if promote {
                let n = st.seed("next")?.context("no next key; run `keygen --next` first")?;
                st.write_seed("current", &n)?;
                st.remove_seed("next")?;
                println!("the next key is now the current key");
            } else {
                let name = if next { "next" } else { "current" };
                if st.seed(name)?.is_some() {
                    bail!("a {name} key already exists");
                }
                st.write_seed(name, &random_seed()?)?;
                println!("created the {name} key");
            }
            let (ip, configured) = advertise(&net)?;
            let public = st.publish(net.port, ip, configured)?;
            println!("pairing code: {}", public.pairing_code);
            if next {
                println!("re-pair each PC with this code, then run `netbooty-server keygen --promote`");
            }
        }
        Cmd::Pair { net } => {
            let (ip, configured) = advertise(&net)?;
            let public = st.publish(net.port, ip, configured)?;
            println!("{}", public.pairing_code);
            eprintln!("fingerprint {}", public.fingerprints.join(" / "));
            eprintln!("on the PC: sudo netbooty-setup pair '{}'", public.pairing_code);
        }
        Cmd::Client(c) => {
            let mut state = st.state()?;
            match c {
                ClientCmd::List => return print_status(&st),
                ClientCmd::Approve { request, name, targets } => {
                    let reqs = st.requests()?;
                    let id = find_request(&reqs, &request)?;
                    let r = &reqs.requests[&id];
                    let name = name.or_else(|| r.hostname.clone()).context("give the PC a --name")?;
                    let targets = match targets {
                        Some(t) => parse_targets(&t)?,
                        None => r.targets.clone(),
                    };
                    state.clients.insert(id, Client { name: name.clone(), targets, ..Client::default() });
                    println!("approved {name}");
                }
                ClientCmd::Add { client_id, name, targets } => {
                    let id = store::unhex::<16>(&client_id)
                        .map(|b| hex(&b))
                        .context("client ID must be 32 hex digits")?;
                    let targets = targets.as_deref().map(parse_targets).transpose()?.unwrap_or_default();
                    state.clients.insert(id, Client { name: name.clone(), targets, ..Client::default() });
                    println!("added {name}");
                }
                ClientCmd::Rm { pc } => {
                    let id = find_pc(&state, &pc)?;
                    state.clients.remove(&id);
                    println!("removed {pc}");
                }
                ClientCmd::Dismiss { request } => {
                    let id = find_request(&st.requests()?, &request)?;
                    state.dismissed.push(id);
                    println!("dismissed");
                }
            }
            st.save_state(&state)?;
        }
        Cmd::Set { pc, target } => {
            let mut state = st.state()?;
            let id = find_pc(&state, &pc)?;
            let c = state.clients.get_mut(&id).unwrap();
            c.choice = if target == "none" {
                None
            } else {
                check_target(c, &target)?;
                Some(target.clone())
            };
            println!("{}: {}", c.name, c.choice.as_deref().unwrap_or("no preference"));
            st.save_state(&state)?;
        }
        Cmd::Next { pc, target } => {
            let mut state = st.state()?;
            let id = find_pc(&state, &pc)?;
            let c = state.clients.get_mut(&id).unwrap();
            check_target(c, &target)?;
            let mut nonce = [0u8; 8];
            getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            c.once = Some(Once { id: hex(&nonce), target: target.clone() });
            println!("{} boots {target} once on its next boot", c.name);
            st.save_state(&state)?;
        }
        Cmd::Status => print_status(&st)?,
    }
    Ok(())
}
