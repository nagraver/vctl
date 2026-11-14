//! Bounded, cancellable TCP reachability checks. This does not test VPN authentication.
use crate::model::{Node, State};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub struct LatencyResult {
    pub id: String,
    pub milliseconds: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn nodes(state: &State, subscription: Option<&str>, server: Option<&str>) -> Result<Vec<Node>> {
    let candidates = match subscription {
        Some(name) => state
            .subscriptions
            .get(name)
            .context("Subscription not found")?
            .nodes
            .clone(),
        None => state.nodes(),
    };
    let mut seen = HashSet::new();
    let result: Vec<_> = candidates
        .into_iter()
        .filter(|node| server.is_none_or(|id| id == node.id) && seen.insert(node.id.clone()))
        .collect();
    if server.is_some() && result.is_empty() {
        bail!("Server not found in selected subscription");
    }
    Ok(result)
}

fn physical_interface() -> Result<u32> {
    let output = crate::runtime::command_output(
        Command::new("/sbin/route").args(["-n", "get", "default"]),
        Duration::from_secs(5),
        16384,
    )?;
    if !output.success {
        bail!("Physical default interface unavailable");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let name = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .context("Physical default interface unavailable")?;
    if name.starts_with("utun") || name.starts_with("lo") {
        bail!("Physical default interface unavailable");
    }
    let name = std::ffi::CString::new(name)?;
    // if_nametoindex reads interface metadata; it does not change routing.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        bail!("Physical default interface unavailable");
    }
    Ok(index)
}

fn connect(
    address: SocketAddr,
    interface: u32,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("Cancelled");
    }
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    #[cfg(target_os = "macos")]
    if interface != 0 {
        let (level, option) = if address.is_ipv6() {
            (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
        } else {
            (libc::IPPROTO_IP, libc::IP_BOUND_IF)
        };
        // Bind only this probe socket to the physical interface.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&interface as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = interface;
    socket.set_nonblocking(true)?;
    match socket.connect(&address.into()) {
        Ok(()) => return Ok(()),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS) | Some(libc::EWOULDBLOCK)
            ) => {}
        Err(error) => return Err(error.into()),
    }
    loop {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Cancelled");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("Timeout");
        }
        let mut fd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = remaining.as_millis().clamp(1, 100) as i32;
        let ready = unsafe { libc::poll(&mut fd, 1, millis) };
        if ready > 0 {
            if let Some(error) = socket.take_error()? {
                return Err(error.into());
            }
            return Ok(());
        }
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn probe(node: &Node, interface: u32, cancelled: &AtomicBool) -> LatencyResult {
    let mut result = LatencyResult {
        id: node.id.clone(),
        milliseconds: 0,
        error: Some("Unreachable".into()),
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(3);
    let host = node.outbound["server"].as_str().unwrap_or("").to_owned();
    let port = node.outbound["server_port"]
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(0);
    // getaddrinfo is blocking. Its bounded result channel lets the probe cancel promptly.
    static RESOLVERS: AtomicUsize = AtomicUsize::new(0);
    if RESOLVERS
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
            (active < 8).then_some(active + 1)
        })
        .is_err()
    {
        result.error = Some("Timeout".into());
        return result;
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map(|v| v.collect::<Vec<_>>());
        RESOLVERS.fetch_sub(1, Ordering::SeqCst);
        let _ = sender.send(addresses);
    });
    let addresses = loop {
        if cancelled.load(Ordering::Relaxed) {
            return result;
        }
        if Instant::now() >= deadline {
            result.error = Some("Timeout".into());
            return result;
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(addresses)) => break addresses,
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    for address in addresses {
        if connect(address, interface, deadline, cancelled).is_ok() {
            result.milliseconds = started.elapsed().as_millis().max(1);
            result.error = None;
            return result;
        }
        if cancelled.load(Ordering::Relaxed) {
            return result;
        }
    }
    if Instant::now() >= deadline {
        result.error = Some("Timeout".into());
    }
    result
}

pub fn stream_with(
    nodes: &[Node],
    cancelled: &AtomicBool,
    probe: impl Fn(&Node, &AtomicBool) -> LatencyResult + Sync,
    output: &mut impl Write,
) -> Result<()> {
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(8);
        for _ in 0..nodes.len().min(8) {
            let sender = sender.clone();
            let next = &next;
            let probe = &probe;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let Some(node) = nodes.get(next.fetch_add(1, Ordering::Relaxed)) else {
                        break;
                    };
                    let result = probe(node, cancelled);
                    if cancelled.load(Ordering::Relaxed) || sender.send(result).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        for result in receiver {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            if let Err(error) = serde_json::to_writer(&mut *output, &result)
                .map_err(anyhow::Error::from)
                .and_then(|()| Ok(output.write_all(b"\n")?))
                .and_then(|()| Ok(output.flush()?))
            {
                cancelled.store(true, Ordering::Relaxed);
                return Err(error);
            }
        }
        Ok(())
    })
}

pub fn run(nodes: &[Node], output: &mut impl Write) -> Result<()> {
    if nodes.is_empty() {
        return Ok(());
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let terminate = signal_hook::flag::register(libc::SIGTERM, Arc::clone(&cancelled))?;
    let interrupt = signal_hook::flag::register(libc::SIGINT, Arc::clone(&cancelled))?;
    let result = physical_interface().and_then(|interface| {
        stream_with(
            nodes,
            &cancelled,
            |node, stop| probe(node, interface, stop),
            output,
        )
    });
    signal_hook::low_level::unregister(terminate);
    signal_hook::low_level::unregister(interrupt);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Subscription;
    #[test]
    fn latency_scope_deduplicates_and_rejects_cross_subscription_server() {
        let mut state = State::default();
        let a = Node {
            id: "a".into(),
            ..Default::default()
        };
        state.subscriptions.insert(
            "one".into(),
            Subscription {
                nodes: vec![a.clone(), a],
                ..Default::default()
            },
        );
        state.subscriptions.insert(
            "two".into(),
            Subscription {
                nodes: vec![Node {
                    id: "b".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert_eq!(nodes(&state, Some("one"), None).unwrap().len(), 1);
        assert!(nodes(&state, Some("one"), Some("b")).is_err());
        assert!(nodes(&state, Some("missing"), None).is_err());
    }
    #[test]
    fn probes_stop_when_output_closes_and_no_more_than_eight_run() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let stop = AtomicBool::new(false);
        let active = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let many = vec![Node::default(); 1000];
        assert!(
            stream_with(
                &many,
                &stop,
                |node, _| {
                    let running = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(running, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(1));
                    active.fetch_sub(1, Ordering::SeqCst);
                    LatencyResult {
                        id: node.id.clone(),
                        milliseconds: 1,
                        error: None,
                    }
                },
                &mut Closed
            )
            .is_err()
        );
        assert!(stop.load(Ordering::Relaxed));
        assert!(maximum.load(Ordering::Relaxed) <= 8);
    }
    #[test]
    fn loopback_probe_connects_and_pre_cancelled_socket_stops() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(
            connect(
                address,
                0,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false)
            )
            .is_ok()
        );
        assert!(
            connect(
                address,
                0,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true)
            )
            .is_err()
        );
    }
}
