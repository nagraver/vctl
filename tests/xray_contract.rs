//! Actual bundled-engine checks. Never start a TUN or mutate system networking.
use std::path::PathBuf;
use whale::{
    config,
    model::{State, Subscription},
    profiles, runtime,
};

fn engine() -> Option<PathBuf> {
    let path = std::env::var_os("WHALE_TEST_CORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".tools/xray"));
    if path.is_file() {
        Some(path)
    } else {
        eprintln!(
            "Bundled Xray absent; run make integration with WHALE_TEST_CORE to validate the engine contract"
        );
        None
    }
}

#[test]
fn bundled_engine_accepts_supported_protocols_and_transports() {
    let Some(core) = engine() else {
        return;
    };
    let temporary = tempfile::tempdir().unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../internal/whale/testdata/legacy.json")).unwrap();
    let mut uris: Vec<String> = fixture["uris"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    uris.push("trojan://test@example.org:443?type=httpupgrade&path=%2Fconnect#Upgrade".into());
    for uri in uris {
        let node = profiles::parse_uri(&uri).unwrap();
        let mut state = State {
            selected: node.id.clone(),
            ..Default::default()
        };
        state.subscriptions.insert(
            "test".into(),
            Subscription {
                nodes: vec![node],
                interval: 43200,
                ..Default::default()
            },
        );
        runtime::validate_config(&core, temporary.path(), &state, "proxy", 2180).unwrap();
        runtime::validate_config(&core, temporary.path(), &state, "tun", 2180).unwrap();
    }
}

#[test]
fn bundled_engine_accepts_process_routing_and_automatic_balancer() {
    let Some(core) = engine() else {
        return;
    };
    let temporary = tempfile::tempdir().unwrap();
    let node = profiles::parse_uri("trojan://test@127.0.0.1:443#Local").unwrap();
    let mut state = State::default();
    state.subscriptions.insert(
        "test".into(),
        Subscription {
            nodes: vec![node],
            interval: 43200,
            ..Default::default()
        },
    );
    for (kind, value, action) in [
        ("process", "curl", "direct"),
        ("path", "/Applications/Example.app", "proxy"),
        ("cidr", "192.0.2.0/24", "block"),
        ("suffix", "example.org", "direct"),
    ] {
        state
            .rules
            .push(config::make_rule(kind, value, action).unwrap());
    }
    runtime::validate_config(&core, temporary.path(), &state, "tun", 2180).unwrap();
}

#[test]
fn helper_mutations_use_real_xray_and_keep_legacy_profile_fields() {
    let Some(core) = engine() else {
        return;
    };
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("profile");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        home.join("state.json"),
        br#"{"version":1,"ui":{"language":"ru"}}"#,
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_whale-helper"))
        .arg("--home")
        .arg(&home)
        .arg("--core")
        .arg(&core)
        .args(["rule", "add", "suffix", "example.org", "direct"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = whale::store::Store::new(&home).unwrap().read().unwrap();
    assert_eq!(state.rules[0].value, "example.org");
    assert_eq!(state.extra["ui"]["language"], "ru");
    let before = std::fs::read(home.join("state.json")).unwrap();
    let failure = std::process::Command::new(env!("CARGO_BIN_EXE_whale-helper"))
        .arg("--home")
        .arg(&home)
        .arg("--core")
        .arg(&core)
        .args(["rule", "add", "suffix", "https://invalid", "direct"])
        .output()
        .unwrap();
    assert!(!failure.status.success());
    assert_eq!(std::fs::read(home.join("state.json")).unwrap(), before);
}

/// Exercises the generated SOCKS -> VLESS -> HTTP path on loopback, then proves
/// that stopping the VLESS server breaks that path (it cannot pass via direct).
#[test]
fn generated_proxy_round_trips_through_a_real_local_vless_server() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};
    let Some(core) = engine() else {
        return;
    };
    struct Engine(Child);
    impl Drop for Engine {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn start(
        core: &std::path::Path,
        config: &serde_json::Value,
        path: &std::path::Path,
        port: u16,
    ) -> Engine {
        let mut diagnostic_config = config.clone();
        diagnostic_config["log"] = serde_json::json!({"loglevel":"debug","error":path.with_extension("log"),"access":path.with_extension("access.log")});
        std::fs::write(path, serde_json::to_vec(&diagnostic_config).unwrap()).unwrap();
        let mut process = Engine(
            Command::new(core)
                .args(["run", "-c"])
                .arg(path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "test Xray exited during startup"
            );
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "test Xray did not listen");
            std::thread::sleep(Duration::from_millis(20));
        }
        process
    }
    fn vacant_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    let directory = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    origin.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let http = std::thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            match origin.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut request = [0_u8; 8192];
                    if socket.read(&mut request).unwrap_or(0) > 0 {
                        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nwhale-rust-e2e!");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("loopback HTTP listener failed: {error}"),
            }
        }
    });
    struct Origin {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Origin {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
    let _origin = Origin {
        stop,
        thread: Some(http),
    };
    let server_port = vacant_port();
    let uuid = "11111111-1111-4111-8111-111111111111";
    // Xray 26.9.9 deliberately blocks private targets after remote-proxy
    // inbounds. Permit only this ephemeral loopback origin on the test server.
    // The generated client configuration remains unmodified.
    let server_config = serde_json::json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":server_port,"protocol":"vless","settings":{"clients":[{"id":uuid}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":origin_port.to_string()}]}}]});
    let server = start(
        &core,
        &server_config,
        &directory.path().join("server.json"),
        server_port,
    );
    let node = profiles::parse_uri(&format!(
        "vless://{uuid}@127.0.0.1:{server_port}?security=none#Loopback"
    ))
    .unwrap();
    let mut state = State {
        selected: node.id.clone(),
        ..Default::default()
    };
    state.subscriptions.insert(
        "local".into(),
        Subscription {
            nodes: vec![node],
            interval: 43200,
            ..Default::default()
        },
    );
    state
        .rules
        .push(config::make_rule("cidr", "127.0.0.0/8", "proxy").unwrap());
    let client_port = vacant_port();
    assert_ne!(client_port, u16::MAX);
    let mut client_config = config::generate(&state, "proxy", client_port).unwrap();
    client_config["inbounds"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    let _client = start(
        &core,
        &client_config,
        &directory.path().join("client.json"),
        client_port,
    );
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{client_port}")).unwrap())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{origin_port}/contract");
    let response = client.get(&url).send().unwrap_or_else(|error| {
        panic!(
            "loopback request failed: {error}; server log: {}; client log: {}",
            std::fs::read_to_string(directory.path().join("server.log")).unwrap_or_default(),
            std::fs::read_to_string(directory.path().join("client.log")).unwrap_or_default()
        )
    });
    assert_eq!(response.text().unwrap(), "whale-rust-e2e!");
    drop(server);
    assert!(
        client.get(&url).send().is_err(),
        "traffic unexpectedly bypassed the VLESS server"
    );
}
