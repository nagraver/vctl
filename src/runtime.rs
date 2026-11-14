//! Owns Xray children and applies validated configurations transactionally.
use crate::{
    model::State,
    store::{Store, atomic_write},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

trait Engine {
    fn start(&mut self, config: &Value) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn ready(&mut self) -> Result<()>;
}
#[derive(Debug, PartialEq, Eq)]
enum Replacement {
    Applied,
    Restored,
    Failed,
}
fn replace(
    engine: &mut impl Engine,
    candidate: &Value,
    previous: Option<&Value>,
    force: bool,
) -> Result<Replacement> {
    if !force && previous == Some(candidate) {
        return Ok(Replacement::Applied);
    }
    engine.stop()?;
    if engine
        .start(candidate)
        .and_then(|()| engine.ready())
        .is_ok()
    {
        return Ok(Replacement::Applied);
    }
    engine.stop()?;
    if let Some(previous) = previous {
        if engine.start(previous).and_then(|()| engine.ready()).is_ok() {
            return Ok(Replacement::Restored);
        }
        engine.stop()?;
    }
    Ok(Replacement::Failed)
}

pub struct CommandOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
}

/// Internal engine authorization entry point; the controller supplies stdin.
const ENGINE_AUTHORIZATION: &[u8] = b"whale-engine-start-v1\n";
pub fn engine_entry(core: &Path, config: &Path, assets: &Path) -> Result<()> {
    let mut token = vec![0_u8; ENGINE_AUTHORIZATION.len()];
    std::io::stdin()
        .read_exact(&mut token)
        .context("Engine startup authorization was cancelled")?;
    if token != ENGINE_AUTHORIZATION {
        bail!("Invalid engine startup authorization")
    }
    if !core.is_absolute() || !config.is_absolute() || !assets.is_absolute() {
        bail!("Engine paths must be absolute")
    }
    // exec preserves the journaled wrapper PID and process group. No core code,
    // including its version command, runs before the parent durably journals it.
    let _error = Command::new(core)
        .args(["run", "-c"])
        .arg(config)
        .env("XRAY_LOCATION_ASSET", assets)
        .stdin(Stdio::null())
        .exec();
    bail!("The authorized network engine could not be executed")
}

fn drain(mut source: impl Read, limit: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match source.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(size) => {
                let keep = size.min(limit.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
        }
    }
    output
}

fn prepare_child_reaping() -> std::io::Result<()> {
    static PREPARED: OnceLock<std::result::Result<(), i32>> = OnceLock::new();
    let result = PREPARED.get_or_init(|| {
        // Ignored SIGCHLD/SA_NOCLDWAIT can be inherited across exec and discard
        // child exit statuses. Normalize only auto-reaping; preserve other
        // handlers and the caller's mask. Our waits do not need signal delivery.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) != 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            let ignored = action.sa_sigaction == libc::SIG_IGN;
            let no_wait = action.sa_flags & libc::SA_NOCLDWAIT != 0;
            if ignored || no_wait {
                if ignored {
                    action.sa_sigaction = libc::SIG_DFL;
                    action.sa_flags &= !libc::SA_SIGINFO;
                }
                action.sa_flags &= !libc::SA_NOCLDWAIT;
                if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO));
                }
            }
            Ok(())
        }
    });
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(std::io::Error::from_raw_os_error(*error)),
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => (),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

/// All platform subprocesses are owned, timed out, killed as a group and reaped.
/// Raw stderr is deliberately not returned: Xray errors can contain credentials.
pub fn command_output(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<CommandOutput> {
    prepare_child_reaping().context("Could not prepare child process supervision")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .context("Could not start required system tool")?;
    let stdout = child.stdout.take().context("Missing command output")?;
    let stderr = child
        .stderr
        .take()
        .context("Missing command error stream")?;
    let out_reader = thread::spawn(move || drain(stdout, limit.saturating_add(1)));
    let err_reader = thread::spawn(move || drain(stderr, 16384));
    let waiting = wait_for_exit(&mut child, timeout);
    if !matches!(waiting, Ok(Some(_))) {
        signal_group(&child, libc::SIGKILL);
        let _ = child.wait();
    }
    // Also close pipes inherited by descendants after their original parent exits.
    signal_group(&child, libc::SIGKILL);
    let body = out_reader.join().unwrap_or_default();
    let _ = err_reader.join();
    let status = waiting
        .context("Could not wait for required system tool")?
        .context("System operation timed out")?;
    if body.len() > limit {
        bail!("System response exceeded size limit")
    }
    Ok(CommandOutput {
        success: status.success(),
        exit_code: status.code(),
        stdout: body,
    })
}

fn signal_group(child: &Child, signal: i32) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // Every child is started in its own process group; never signal the app's group.
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

pub(crate) struct OwnedChild {
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
    stopped: bool,
}
impl OwnedChild {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        Self::spawn_with_input(command, Stdio::null())
    }
    fn spawn_with_input(command: &mut Command, input: Stdio) -> Result<Self> {
        prepare_child_reaping().context("Could not prepare child process supervision")?;
        command
            .stdin(input)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().context("Could not start child process")?;
        let mut pipe = child.stderr.take().context("Missing child diagnostics")?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let target = Arc::clone(&stderr);
        let reader = thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(size) => {
                        if let Ok(mut recent) = target.lock() {
                            recent.extend_from_slice(&buffer[..size]);
                            let excess = recent.len().saturating_sub(16384);
                            recent.drain(..excess);
                        }
                    }
                }
            }
        });
        Ok(Self {
            child,
            stderr,
            reader: Some(reader),
            stopped: false,
        })
    }
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }
    fn authorize_engine(&mut self) -> Result<()> {
        let mut input = self
            .child
            .stdin
            .take()
            .context("Engine authorization channel is unavailable")?;
        input
            .write_all(ENGINE_AUTHORIZATION)
            .context("Engine authorization could not be delivered")?;
        Ok(())
    }
    pub(crate) fn exited(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_some())
    }
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.stop_timeout(Duration::from_secs(8))
    }
    pub(crate) fn stop_timeout(&mut self, timeout: Duration) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            signal_group(&self.child, libc::SIGTERM);
            if !matches!(wait_for_exit(&mut self.child, timeout), Ok(Some(_))) {
                signal_group(&self.child, libc::SIGKILL);
                self.child.wait()?;
            }
        }
        // A subprocess may have left descendants holding stderr open.
        signal_group(&self.child, libc::SIGKILL);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.stopped = true;
        Ok(())
    }
    fn safe_diagnostic(&self) -> &'static str {
        let bytes = self
            .stderr
            .lock()
            .map(|bytes| bytes.clone())
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        if text.contains("address already in use") {
            "A required local port is already in use"
        } else if text.contains("permission denied") {
            "The network engine was denied permission"
        } else {
            "The network engine exited; inspect the application configuration"
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn open_child_directory(parent: &File, name: &str) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        bail!("Cannot safely open profile assets")
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn copy_assets(profile: &Path, state: &State, target: &Path) -> Result<()> {
    if state.geodata.is_empty() {
        return Ok(());
    }
    let parent =
        crate::store::open_directory(profile).context("Cannot safely read profile assets")?;
    let geodata = open_child_directory(&parent, "geodata")?;
    let owner = parent.metadata()?.uid();
    let directory_metadata = geodata.metadata()?;
    if directory_metadata.uid() != owner || directory_metadata.mode() & 0o022 != 0 {
        bail!("Unsafe geodata directory ownership or permissions")
    }
    fs::create_dir_all(target)?;
    for (kind, asset) in &state.geodata {
        if !matches!(kind.as_str(), "geoip" | "geosite")
            || asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("Invalid geodata reference")
        }
        let name = std::ffi::CString::new(format!("{}.dat", asset.sha256))?;
        let fd = unsafe {
            libc::openat(
                geodata.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            bail!("Cannot safely read geodata")
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1 {
            bail!("Geodata must be a regular file owned exclusively by the profile owner")
        }
        let mut body = Vec::new();
        file.take(64_000_001).read_to_end(&mut body)?;
        if body.len() > 64_000_000 || hex::encode(Sha256::digest(&body)) != asset.sha256 {
            bail!("Geodata checksum mismatch")
        }
        atomic_write(&target.join(format!("{}.dat", asset.sha256)), &body, 0o600)?;
    }
    Ok(())
}

fn test_config(core: &Path, config: &Value, directory: &Path, assets: &Path) -> Result<()> {
    let path = directory.join("validation.json");
    atomic_write(&path, &serde_json::to_vec(config)?, 0o600)?;
    let output = command_output(
        Command::new(core)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .env("XRAY_LOCATION_ASSET", assets),
        Duration::from_secs(20),
        65536,
    )?;
    let _ = fs::remove_file(path);
    if !output.success {
        bail!("Xray rejected the proposed configuration; existing settings were preserved")
    }
    Ok(())
}

pub fn validate_config(
    core: &Path,
    profile: &Path,
    state: &State,
    mode: &str,
    port: u16,
) -> Result<()> {
    crate::config::validate_state(state)?;
    let temporary = tempfile::Builder::new()
        .prefix("whale-validation-")
        .tempdir_in("/private/tmp")?;
    let assets = temporary.path().join("geodata");
    copy_assets(profile, state, &assets)?;
    let config = crate::config::generate(state, mode, port)?;
    test_config(core, &config, temporary.path(), &assets)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Stopped,
    Starting,
    Connected,
    Stopping,
    Failed,
}
fn terminal_state(
    operation_failed: bool,
    cleanup_failed: bool,
    cancelled: bool,
) -> ConnectionState {
    if !cleanup_failed && (!operation_failed || cancelled) {
        ConnectionState::Stopped
    } else {
        ConnectionState::Failed
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub connection_state: ConnectionState,
    pub applied_selected: Option<String>,
    pub server: Option<Value>,
    pub error: Option<String>,
    pub updated: f64,
    pub pid: u32,
    pub core_pid: Option<u32>,
    #[serde(default)]
    pub completed_operation: Option<String>,
    #[serde(default)]
    pub operation_error: Option<String>,
}
impl Status {
    pub fn new(connection_state: ConnectionState) -> Self {
        Self {
            connection_state,
            applied_selected: None,
            server: None,
            error: None,
            updated: crate::model::now(),
            pid: std::process::id(),
            core_pid: None,
            completed_operation: None,
            operation_error: None,
        }
    }
    pub(crate) fn save(&mut self, runtime: &Path) -> Result<()> {
        self.updated = crate::model::now();
        atomic_write(
            &runtime.join("status.json"),
            &serde_json::to_vec(self)?,
            0o600,
        )
    }
    pub(crate) fn native(&self, installed: bool) -> Value {
        let legacy = match self.connection_state {
            ConnectionState::Connected => "on",
            ConnectionState::Starting | ConnectionState::Stopping => "starting",
            ConnectionState::Stopped => "off",
            ConnectionState::Failed => "unknown",
        };
        json!({"state":legacy,"connection_state":self.connection_state,"installed":installed,"server":self.server,"applied_selected":self.applied_selected,"error":self.error,"protocol":crate::PROTOCOL_VERSION})
    }
}
pub(crate) fn read_status(runtime: &Path) -> Result<Status> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(runtime.join("status.json"))?;
    if !file.metadata()?.is_file() {
        bail!("Invalid runtime status")
    }
    let mut body = Vec::new();
    file.take(65537).read_to_end(&mut body)?;
    if body.len() > 65536 {
        bail!("Runtime status exceeded limit")
    }
    serde_json::from_slice(&body).context("Invalid runtime status")
}

struct Xray {
    core: PathBuf,
    directory: PathBuf,
    assets: PathBuf,
    child: Option<OwnedChild>,
    port: u16,
    test_url: String,
    cancel: Arc<AtomicBool>,
    tun: bool,
    probe_urls: Vec<(Value, String)>,
}
impl Xray {
    fn new(
        core: &Path,
        directory: &Path,
        assets: &Path,
        port: u16,
        test_url: &str,
        cancel: Arc<AtomicBool>,
        tun: bool,
    ) -> Self {
        Self {
            core: core.into(),
            directory: directory.into(),
            assets: assets.into(),
            child: None,
            port,
            test_url: test_url.into(),
            cancel,
            tun,
            probe_urls: Vec::new(),
        }
    }
}
impl Engine for Xray {
    fn start(&mut self, config: &Value) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            bail!("Connection cancelled")
        }
        if let Some((_, url)) = self.probe_urls.iter().find(|(known, _)| known == config) {
            self.test_url = url.clone();
        }
        let path = self.directory.join("config.json");
        atomic_write(&path, &serde_json::to_vec(config)?, 0o600)?;
        let _ = fs::remove_file(self.directory.join("api.sock"));
        let mut child = OwnedChild::spawn_with_input(
            Command::new(std::env::current_exe()?)
                .arg("--core")
                .arg(&self.core)
                .args(["_engine", "--config"])
                .arg(&path)
                .arg("--assets")
                .arg(&self.assets),
            Stdio::piped(),
        )?;
        let wrapper_command = process_command(child.id())?;
        if wrapper_command.is_empty() {
            bail!("Engine wrapper exited before authorization")
        }
        let core_command = format!("{} run -c {}", self.core.display(), path.display());
        let journal = json!({"pid":child.id(),"core":self.core,"config":path,"commands":[wrapper_command,core_command]});
        atomic_write(
            &self.directory.join("engine.json"),
            &serde_json::to_vec(&journal)?,
            0o600,
        )?;
        child.authorize_engine()?;
        self.child = Some(child);
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.stop()?;
        }
        match fs::remove_file(self.directory.join("engine.json")) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    fn ready(&mut self) -> Result<()> {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", self.port))?;
        let client = reqwest::blocking::Client::builder()
            .proxy(proxy)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() == "https" && attempt.previous().len() < 5 {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()?;
        let url = url::Url::parse(&self.test_url)?;
        if url.scheme() != "https" {
            bail!("Readiness URL must use HTTPS")
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && !self.cancel.load(Ordering::Relaxed) {
            let child = self
                .child
                .as_mut()
                .context("Network engine is not running")?;
            if child.exited()? {
                bail!(child.safe_diagnostic())
            }
            if let Ok(response) = client.get(url.clone()).send()
                && response.status().is_success()
                && !child.exited()?
                && (!self.tun || tun_route_ready())
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("The proxy did not pass its HTTPS readiness check")
    }
}

fn tun_route_ready() -> bool {
    command_output(
        Command::new("/sbin/route").args(["-n", "get", crate::dns::TUN_DNS]),
        Duration::from_secs(2),
        8192,
    )
    .is_ok_and(|result| {
        result.success
            && String::from_utf8_lossy(&result.stdout).contains("gateway: 172.28.0.1")
            && String::from_utf8_lossy(&result.stdout).contains("interface: utun")
    })
}
fn process_command(pid: u32) -> Result<String> {
    let result = command_output(
        Command::new("/bin/ps").args(["-p", &pid.to_string(), "-o", "command="]),
        Duration::from_secs(2),
        8192,
    )?;
    if !result.success {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

/// Recovery reads only the verified root runtime. A PID alone never authorizes a signal.
fn recover_engine(runtime: &Path) -> Result<()> {
    let path = runtime.join("engine.json");
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => {
            let mut body = Vec::new();
            file.take(16385).read_to_end(&mut body)?;
            if body.len() > 16384 {
                bail!("Invalid engine recovery journal")
            }
            let journal: Value =
                serde_json::from_slice(&body).context("Invalid engine recovery journal")?;
            let pid = journal["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 1)
                .context("Invalid engine PID")?;
            let expected = journal_commands(&journal)?;
            let config = runtime.join("config.json");
            if journal["config"].as_str() != config.to_str() {
                bail!("Invalid engine recovery path")
            }
            if expected.contains(&process_command(pid)?.as_str()) {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline
                    && expected.contains(&process_command(pid)?.as_str())
                {
                    thread::sleep(Duration::from_millis(50));
                }
                if expected.contains(&process_command(pid)?.as_str()) {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => bail!("Cannot safely open engine recovery journal"),
    }
    Ok(())
}
fn journal_commands(journal: &Value) -> Result<Vec<&str>> {
    let commands = if let Some(commands) = journal.get("commands") {
        let values = commands.as_array().context("Invalid engine identities")?;
        if values.is_empty() || values.len() > 2 {
            bail!("Invalid engine identities")
        }
        values
            .iter()
            .map(|value| value.as_str().context("Invalid engine identity"))
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![
            journal["command"]
                .as_str()
                .context("Missing engine identity")?,
        ]
    };
    if commands
        .iter()
        .any(|value| value.is_empty() || value.len() > 8192)
    {
        bail!("Invalid engine identity")
    }
    Ok(commands)
}
pub(crate) fn recover(runtime: &Path, _lease: &crate::service::TunLease) -> Result<()> {
    recover_engine(runtime)?;
    // A worker killed during preflight can leave a separate, non-TUN probe child.
    // Probe directories are under the same verified root-only runtime directory.
    for entry in fs::read_dir(runtime)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("probe-") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("Unsafe probe recovery directory")
        }
        recover_engine(&entry.path())?;
        fs::remove_dir_all(entry.path())?;
    }
    crate::dns::restore(
        &mut crate::dns::MacSystem,
        &mut crate::dns::FileJournal::new(runtime),
    )
}
pub(crate) fn recovery_needed(runtime: &Path) -> Result<bool> {
    if runtime.join("engine.json").try_exists()? || runtime.join("dns-restore.json").try_exists()? {
        return Ok(true);
    }
    for entry in fs::read_dir(runtime)? {
        if entry?.file_name().to_string_lossy().starts_with("probe-") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_nodes(state: &State, mut resolve: impl FnMut(&str) -> Result<String>) -> Result<State> {
    let mut resolved = state.clone();
    let selected = &state.selected;
    let mut usable = false;
    for subscription in resolved.subscriptions.values_mut() {
        subscription.nodes.retain_mut(|node| {
            let Some(host) = node.outbound["server"].as_str().map(str::to_owned) else {
                return false;
            };
            let result = if host.parse::<IpAddr>().is_ok() {
                Ok(host.clone())
            } else {
                resolve(&host)
            };
            match result {
                Ok(address) => {
                    // Keep the original HTTP authority when a domain endpoint is
                    // pinned to an IP for loop-free TUN routing. Identity/profile
                    // data are untouched; this only changes the runtime clone.
                    if host.parse::<IpAddr>().is_err() {
                        match node.outbound["transport"]["type"].as_str() {
                            Some("ws")
                                if node.outbound["transport"]["headers"].get("Host").is_none() =>
                            {
                                node.outbound["transport"]["headers"]["Host"] =
                                    Value::String(host.clone());
                            }
                            Some("httpupgrade")
                                if node.outbound["transport"]["host"]
                                    .as_str()
                                    .is_none_or(str::is_empty) =>
                            {
                                node.outbound["transport"]["host"] = Value::String(host.clone());
                            }
                            _ => (),
                        }
                    }
                    node.outbound["server"] = Value::String(address);
                    usable |= selected == "auto" || node.id == *selected;
                    true
                }
                Err(_) => false,
            }
        });
    }
    if !usable {
        bail!("The selected server hostname could not be resolved")
    }
    Ok(resolved)
}
fn resolve_candidate(state: &State) -> Result<State> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut cache = std::collections::HashMap::<String, String>::new();
    let mut resolve = |host: &str| {
        if let Some(value) = cache.get(host) {
            return Ok(value.clone());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("Server resolution deadline reached")
        }
        let result = command_output(
            Command::new("/usr/bin/dscacheutil").args(["-q", "host", "-a", "name", host]),
            remaining.min(Duration::from_secs(3)),
            16384,
        )?;
        let text = String::from_utf8_lossy(&result.stdout);
        let address = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| matches!(*key, "ip_address" | "ipv6_address"))
            .filter_map(|(_, value)| value.trim().parse::<IpAddr>().ok())
            .min_by_key(|ip| usize::from(ip.is_ipv6()))
            .context("Server lookup failed")?
            .to_string();
        cache.insert(host.into(), address.clone());
        Ok(address)
    };
    // Resolve an explicitly selected server before unrelated failed DNS entries
    // consume the overall lookup budget. The normal pass then uses its cache.
    if state.selected != "auto"
        && let Some(node) = state
            .nodes()
            .into_iter()
            .find(|node| node.id == state.selected)
        && let Some(host) = node.outbound["server"]
            .as_str()
            .filter(|host| host.parse::<IpAddr>().is_err())
    {
        resolve(host)?;
    }
    resolve_nodes(state, resolve)
}

fn candidate(core: &Path, profile: &Path, runtime: &Path, state: &State) -> Result<(State, Value)> {
    crate::config::validate_state(state)?;
    let resolved = resolve_candidate(state)?;
    let assets = runtime.join("geodata");
    copy_assets(profile, state, &assets)?;
    let mut config = crate::config::generate(&resolved, "tun", 2180)?;
    config["api"] =
        json!({"tag":"whale-api","listen":runtime.join("api.sock"),"services":["RoutingService"]});
    test_config(core, &config, runtime, &assets)?;
    Ok((resolved, config))
}

fn preflight(core: &Path, runtime: &Path, state: &State, cancel: Arc<AtomicBool>) -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("probe-")
        .tempdir_in(runtime)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    if port == u16::MAX {
        bail!("Could not reserve a probe port")
    }
    let mut probe_state = state.clone();
    probe_state.rules.clear();
    probe_state.presets.clear();
    probe_state.default_route = "proxy".into();
    let mut config = crate::config::generate(&probe_state, "proxy", port)?;
    if let Some(inbounds) = config["inbounds"].as_array_mut() {
        inbounds.truncate(1);
    }
    let route = command_output(
        Command::new("/sbin/route").args(["-n", "get", "default"]),
        Duration::from_secs(3),
        8192,
    )?;
    let route = String::from_utf8_lossy(&route.stdout);
    let interface = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|name| {
            !name.starts_with("utun")
                && !name.starts_with("lo")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .context("Physical network interface unavailable")?;
    if let Some(outbounds) = config["outbounds"].as_array_mut() {
        for outbound in outbounds.iter_mut().filter(|outbound| {
            outbound["tag"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("node-"))
        }) {
            outbound["streamSettings"]["sockopt"] = json!({"interface":interface});
        }
    }
    let mut engine = Xray::new(
        core,
        directory.path(),
        &runtime.join("geodata"),
        port,
        &state.test_url,
        cancel,
        false,
    );
    engine.start(&config)?;
    let result = engine.ready();
    let stop = engine.stop();
    result.and(stop)
}

fn actual_selection(core: &Path, runtime: &Path, state: &State, config: &Value) -> Option<Value> {
    let mut selected = state.selected.clone();
    let mut fallback = false;
    if selected == "auto" {
        let result = command_output(
            Command::new(core)
                .args(["api", "bi"])
                .arg(format!(
                    "--server=unix://{}",
                    runtime.join("api.sock").display()
                ))
                .args(["--timeout=1", "--json", "auto"]),
            Duration::from_secs(2),
            65536,
        )
        .ok()?;
        if !result.success {
            return None;
        }
        let body: Value = serde_json::from_slice(&result.stdout).ok()?;
        let balancer = &body["balancer"];
        let target = balancer["override"]["target"]
            .as_str()
            .or_else(|| balancer["principleTarget"]["tag"][0].as_str())
            .or_else(|| balancer["principle_target"]["tag"][0].as_str());
        let tag = if let Some(tag) = target.filter(|tag| !tag.is_empty()) {
            tag
        } else {
            fallback = true;
            config["routing"]["balancers"][0]["fallbackTag"].as_str()?
        };
        selected = tag.strip_prefix("node-")?.into();
    }
    let node = state.nodes().into_iter().find(|node| node.id == selected)?;
    Some(
        json!({"id":node.id,"name":node.name.chars().filter(|c| !c.is_control()).take(120).collect::<String>(),"automatic":state.selected == "auto","fallback":fallback}),
    )
}

fn fingerprint(state: &State) -> Result<Vec<u8>> {
    let mut state = state.clone();
    state.extra.clear();
    for subscription in state.subscriptions.values_mut() {
        subscription.updated = 0.0;
        subscription.extra.clear();
    }
    for preset in state.presets.values_mut() {
        preset.updated = 0.0;
        preset.extra.clear();
    }
    for asset in state.geodata.values_mut() {
        asset.updated = 0.0;
        asset.extra.clear();
    }
    Ok(serde_json::to_vec(&state)?)
}

fn reconnect_request(runtime: &Path) -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(runtime.join("reconnect.json"))
        .ok()?;
    let mut body = Vec::new();
    file.take(257).read_to_end(&mut body).ok()?;
    if body.len() > 256 {
        return None;
    }
    let value: Value = serde_json::from_slice(&body).ok()?;
    value["id"]
        .as_str()
        .filter(|id| {
            id.len() <= 80
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
        .map(str::to_owned)
}

/// Internal foreground worker. Only the installed root controller starts this.
pub fn serve(profile: &Path, core: &Path, runtime: &Path, uid: u32) -> Result<()> {
    crate::service::check_runtime(profile, runtime, uid)?;
    let parent = unsafe { libc::getppid() };
    let expected_parent = std::env::var("WHALE_CONTROLLER_PID")
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    if expected_parent != Some(parent) || parent <= 1 {
        bail!("Runtime must be started by the installed controller")
    }
    let _lock = crate::service::RuntimeLock::acquire(runtime.join("runtime.lock"))?;
    let system_connection = crate::service::exclusive_tun()?;
    crate::service::recover_stale_runtimes(&system_connection, runtime)?;
    recover(runtime, &system_connection)?;
    let _ = fs::remove_file(runtime.join("reconnect.json"));
    let cancel = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGTERM, Arc::clone(&cancel))?;
    signal_hook::flag::register(libc::SIGINT, Arc::clone(&cancel))?;
    let store = Store {
        home: profile.into(),
    };
    let mut status = Status::new(ConnectionState::Starting);
    status.save(runtime)?;
    let mut engine = Xray::new(
        core,
        runtime,
        &runtime.join("geodata"),
        2180,
        "https://www.gstatic.com/generate_204",
        Arc::clone(&cancel),
        true,
    );
    let mut refresh: Option<OwnedChild> = None;
    let result = (|| -> Result<()> {
        let initial = store.read()?;
        engine.test_url = initial.test_url.clone();
        let (mut applied_state, mut applied_config) = candidate(core, profile, runtime, &initial)?;
        preflight(core, runtime, &applied_state, Arc::clone(&cancel))?;
        engine.start(&applied_config)?;
        engine.ready()?;
        crate::dns::acquire(
            &mut crate::dns::MacSystem,
            &mut crate::dns::FileJournal::new(runtime),
        )?;
        status.connection_state = ConnectionState::Connected;
        status.applied_selected = Some(initial.selected.clone());
        status.core_pid = engine.child.as_ref().map(OwnedChild::id);
        status.save(runtime)?;
        let mut applied = fingerprint(&initial)?;
        let mut rejected: Option<Vec<u8>> = None;
        let mut retry_at = Instant::now();
        let mut refresh_at = Instant::now();
        let mut selection_at = Instant::now();
        while !cancel.load(Ordering::Relaxed) && unsafe { libc::getppid() } == parent {
            if engine
                .child
                .as_mut()
                .is_none_or(|child| child.exited().unwrap_or(true))
            {
                bail!("The network engine exited unexpectedly")
            }
            if refresh
                .as_mut()
                .is_some_and(|child| child.exited().unwrap_or(true))
            {
                refresh = None;
            }
            if refresh.is_none() && Instant::now() >= refresh_at {
                refresh_at = Instant::now() + Duration::from_secs(60);
                let helper = std::env::current_exe()?;
                refresh = OwnedChild::spawn(
                    Command::new(helper)
                        .arg("--home")
                        .arg(profile)
                        .args(["_refresh", "--owner", &uid.to_string()])
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
                )
                .ok();
            }
            if Instant::now() >= selection_at {
                status.server = actual_selection(core, runtime, &applied_state, &applied_config);
                status.save(runtime)?;
                selection_at = Instant::now() + Duration::from_secs(3);
            }
            let operation = reconnect_request(runtime)
                .filter(|id| status.completed_operation.as_ref() != Some(id));
            match store
                .read()
                .and_then(|state| fingerprint(&state).map(|revision| (state, revision)))
            {
                Ok((current, revision))
                    if operation.is_some()
                        || revision != applied
                            && (rejected.as_ref() != Some(&revision)
                                || Instant::now() >= retry_at) =>
                {
                    status.connection_state = ConnectionState::Starting;
                    status.save(runtime)?;
                    let update =
                        candidate(core, profile, runtime, &current).and_then(|(state, config)| {
                            if config != applied_config || operation.is_some() {
                                preflight(core, runtime, &state, Arc::clone(&cancel))?;
                            }
                            Ok((state, config))
                        });
                    match update {
                        Ok((state, config)) => {
                            if config != applied_config || operation.is_some() {
                                status.connection_state = ConnectionState::Starting;
                                status.save(runtime)?;
                            }
                            let previous_url = engine.test_url.clone();
                            engine.test_url = current.test_url.clone();
                            engine.probe_urls = vec![
                                (applied_config.clone(), previous_url.clone()),
                                (config.clone(), current.test_url.clone()),
                            ];
                            match replace(
                                &mut engine,
                                &config,
                                Some(&applied_config),
                                operation.is_some(),
                            )? {
                                Replacement::Applied => {
                                    applied_state = state;
                                    applied_config = config;
                                    applied = revision;
                                    rejected = None;
                                    status.error = None;
                                    status.applied_selected = Some(current.selected);
                                }
                                Replacement::Restored => {
                                    engine.test_url = previous_url;
                                    rejected = Some(revision);
                                    status.error=Some("New configuration failed; previous connection was restored".into());
                                    retry_at = Instant::now() + Duration::from_secs(60);
                                }
                                Replacement::Failed => bail!(
                                    "New configuration and recovery both failed; VPN was stopped"
                                ),
                            }
                            if let Some(operation) = operation.clone() {
                                status.completed_operation = Some(operation);
                                status.operation_error = status.error.clone();
                            }
                            status.connection_state = ConnectionState::Connected;
                            status.core_pid = engine.child.as_ref().map(OwnedChild::id);
                            status.save(runtime)?;
                        }
                        Err(_) => {
                            status.connection_state = ConnectionState::Connected;
                            rejected = Some(revision);
                            retry_at = Instant::now() + Duration::from_secs(60);
                            status.error = Some(
                                "Could not apply settings; the previous connection remains active"
                                    .into(),
                            );
                            if let Some(operation) = operation.clone() {
                                status.completed_operation = Some(operation);
                                status.operation_error = status.error.clone();
                            }
                            status.save(runtime)?;
                        }
                    }
                }
                Err(_) => {
                    status.error = Some(
                        "Cannot read saved settings; the previous connection remains active".into(),
                    );
                    if let Some(operation) = operation.clone() {
                        status.completed_operation = Some(operation);
                        status.operation_error = status.error.clone();
                    }
                    status.save(runtime)?;
                }
                _ => (),
            }
            for _ in 0..10 {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        Ok(())
    })();
    status.connection_state = ConnectionState::Stopping;
    let _ = status.save(runtime);
    drop(refresh);
    let stop = engine.stop();
    let restore = crate::dns::restore(
        &mut crate::dns::MacSystem,
        &mut crate::dns::FileJournal::new(runtime),
    );
    let cleanup_failed = stop.is_err() || restore.is_err();
    let result = result.and(stop).and(restore);
    status.core_pid = None;
    status.server = None;
    status.connection_state = terminal_state(
        result.is_err(),
        cleanup_failed,
        cancel.load(Ordering::Relaxed),
    );
    status.error = result
        .as_ref()
        .err()
        .filter(|_| cleanup_failed || !cancel.load(Ordering::Relaxed))
        .map(|_| {
            "Connection failed or DNS recovery is incomplete; use Recover DNS before reconnecting"
                .into()
        });
    let _ = status.save(runtime);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[derive(Default)]
    struct FakeEngine {
        current: Option<Value>,
        reject: Vec<Value>,
        reject_ready: Vec<Value>,
        stopped: usize,
    }
    impl Engine for FakeEngine {
        fn start(&mut self, c: &Value) -> Result<()> {
            if self.reject.contains(c) {
                bail!("spawn failed")
            }
            self.current = Some(c.clone());
            Ok(())
        }
        fn stop(&mut self) -> Result<()> {
            self.current = None;
            self.stopped += 1;
            Ok(())
        }
        fn ready(&mut self) -> Result<()> {
            if self.reject_ready.contains(self.current.as_ref().unwrap()) {
                bail!("proxy request failed")
            }
            Ok(())
        }
    }
    #[test]
    fn readiness_failure_restores_previous_configuration() {
        let old = json!({"revision":1});
        let next = json!({"revision":2});
        let mut e = FakeEngine {
            current: Some(old.clone()),
            reject_ready: vec![next.clone()],
            ..Default::default()
        };
        assert_eq!(
            replace(&mut e, &next, Some(&old), false).unwrap(),
            Replacement::Restored
        );
        assert_eq!(e.current, Some(old));
    }
    #[test]
    fn rollback_spawn_failure_is_a_failed_state_not_a_panic() {
        let old = json!({"revision":1});
        let next = json!({"revision":2});
        let mut e = FakeEngine {
            current: Some(old.clone()),
            reject: vec![old.clone(), next.clone()],
            ..Default::default()
        };
        assert_eq!(
            replace(&mut e, &next, Some(&old), false).unwrap(),
            Replacement::Failed
        );
        assert!(e.current.is_none());
    }
    #[test]
    fn successful_replace_is_applied_only_after_readiness() {
        let next = json!({"revision":2});
        let mut e = FakeEngine::default();
        assert_eq!(
            replace(&mut e, &next, None, false).unwrap(),
            Replacement::Applied
        );
        assert_eq!(e.current, Some(next));
    }
    #[test]
    fn unusable_unselected_hostname_does_not_block_selected_server() {
        let mut state = State {
            selected: "working".into(),
            ..Default::default()
        };
        let nodes = vec![
            crate::model::Node {
                id: "broken".into(),
                name: "Broken".into(),
                outbound: json!({"server":"missing.invalid"}),
            },
            crate::model::Node {
                id: "working".into(),
                name: "Working".into(),
                outbound: json!({"server":"203.0.113.2"}),
            },
        ];
        state.subscriptions.insert(
            "example".into(),
            crate::model::Subscription {
                nodes,
                ..Default::default()
            },
        );
        let resolved = resolve_nodes(&state, |_| bail!("lookup failed")).unwrap();
        assert_eq!(resolved.nodes().len(), 1);
        assert_eq!(resolved.nodes()[0].id, "working");
    }
    #[test]
    fn pinning_dns_preserves_implicit_transport_authority_without_mutating_profile() {
        let mut state = State::default();
        let nodes = vec![
            crate::model::Node {
                id: "ws".into(),
                name: "Websocket".into(),
                outbound: json!({"server":"vpn.example.org","transport":{"type":"ws","path":"/"}}),
            },
            crate::model::Node {
                id: "upgrade".into(),
                name: "Upgrade".into(),
                outbound: json!({"server":"vpn.example.org","transport":{"type":"httpupgrade","path":"/"}}),
            },
        ];
        state.subscriptions.insert(
            "example".into(),
            crate::model::Subscription {
                nodes,
                ..Default::default()
            },
        );
        let resolved = resolve_nodes(&state, |_| Ok("203.0.113.1".into())).unwrap();
        assert_eq!(
            resolved.nodes()[0].outbound["transport"]["headers"]["Host"],
            "vpn.example.org"
        );
        assert_eq!(
            resolved.nodes()[1].outbound["transport"]["host"],
            "vpn.example.org"
        );
        assert!(
            state.nodes()[0].outbound["transport"]
                .get("headers")
                .is_none()
        );
    }
    #[test]
    fn startup_is_not_reported_as_connected() {
        assert_eq!(
            Status::new(ConnectionState::Starting).native(true)["state"],
            "starting"
        );
        assert_eq!(
            Status::new(ConnectionState::Connected).native(true)["state"],
            "on"
        );
        assert_eq!(
            Status::new(ConnectionState::Failed).native(true)["state"],
            "unknown"
        );
    }
    #[test]
    fn subprocess_timeout_kills_and_reaps_its_own_group() {
        let started = Instant::now();
        let result = command_output(
            Command::new("/bin/sh").args(["-c", "printf secret; sleep 30"]),
            Duration::from_millis(50),
            100,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!result.err().unwrap().to_string().contains("secret"));
    }
    #[test]
    fn subprocess_signal_probe() {
        if std::env::var("WHALE_TEST_SIGNAL_PROBE").as_deref() != Ok("1") {
            return;
        }
        let output = command_output(
            Command::new("/bin/sh").args(["-c", "sleep 0.05; printf child-ready"]),
            Duration::from_secs(1),
            100,
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"child-ready");
        let mut child = OwnedChild::spawn(Command::new("/bin/sleep").arg("30")).unwrap();
        let pid = child.id();
        child.stop_timeout(Duration::from_millis(100)).unwrap();
        assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0);
    }
    fn run_signal_probe(mode: &'static str) {
        let mut probe = Command::new(std::env::current_exe().unwrap());
        probe
            .args([
                "--exact",
                "runtime::tests::subprocess_signal_probe",
                "--nocapture",
            ])
            .env("WHALE_TEST_SIGNAL_PROBE", "1");
        // Change signal state only in this isolated test subprocess before exec.
        unsafe {
            probe.pre_exec(move || {
                if mode == "blocked" {
                    let mut mask = std::mem::zeroed();
                    libc::sigemptyset(&mut mask);
                    libc::sigaddset(&mut mask, libc::SIGCHLD);
                    let error = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
                    if error != 0 {
                        return Err(std::io::Error::from_raw_os_error(error));
                    }
                } else {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = if mode == "ignored" {
                        libc::SIG_IGN
                    } else {
                        libc::SIG_DFL
                    };
                    action.sa_flags = if mode == "no-cldwait" {
                        libc::SA_NOCLDWAIT
                    } else {
                        0
                    };
                    if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let output = probe.output().unwrap();
        assert!(
            output.status.success(),
            "signal mode {mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn inherited_blocked_sigchld_does_not_time_out_completed_commands() {
        run_signal_probe("blocked");
    }
    #[test]
    fn inherited_ignored_sigchld_remains_waitable() {
        run_signal_probe("ignored");
    }
    #[test]
    fn inherited_no_cldwait_remains_waitable() {
        run_signal_probe("no-cldwait");
    }
    #[test]
    fn owned_process_is_stopped_and_reaped_on_drop() {
        let mut child = OwnedChild::spawn(Command::new("/bin/sleep").arg("30")).unwrap();
        let pid = child.id();
        child.stop().unwrap();
        assert!(child.exited().unwrap());
        assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0);
    }
    #[test]
    fn cancellation_never_hides_failed_dns_recovery() {
        assert_eq!(terminal_state(true, true, true), ConnectionState::Failed);
        assert_eq!(terminal_state(true, false, true), ConnectionState::Stopped);
        assert_eq!(terminal_state(true, false, false), ConnectionState::Failed);
    }
    #[test]
    fn unchanged_engine_config_does_not_reconnect_unless_requested() {
        let config = json!({"revision":1});
        let mut engine = FakeEngine {
            current: Some(config.clone()),
            ..Default::default()
        };
        assert_eq!(
            replace(&mut engine, &config, Some(&config), false).unwrap(),
            Replacement::Applied
        );
        assert_eq!(engine.stopped, 0);
        assert_eq!(
            replace(&mut engine, &config, Some(&config), true).unwrap(),
            Replacement::Applied
        );
        assert_eq!(engine.stopped, 1);
    }
    #[test]
    fn geodata_fifo_is_rejected_without_blocking() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::create_dir(directory.path().join("geodata")).unwrap();
        let digest = "0".repeat(64);
        let path = directory
            .path()
            .join("geodata")
            .join(format!("{digest}.dat"));
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let mut state = State::default();
        state.geodata.insert(
            "geosite".into(),
            crate::model::Asset {
                sha256: digest,
                ..Default::default()
            },
        );
        let start = Instant::now();
        assert!(copy_assets(directory.path(), &state, &directory.path().join("copy")).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn geodata_hard_links_are_rejected() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::create_dir(directory.path().join("geodata")).unwrap();
        let digest = hex::encode(Sha256::digest(b"fixture"));
        let path = directory
            .path()
            .join("geodata")
            .join(format!("{digest}.dat"));
        fs::write(&path, b"fixture").unwrap();
        fs::hard_link(path, directory.path().join("alias")).unwrap();
        let mut state = State::default();
        state.geodata.insert(
            "geosite".into(),
            crate::model::Asset {
                sha256: digest,
                ..Default::default()
            },
        );
        assert!(copy_assets(directory.path(), &state, &directory.path().join("copy")).is_err());
    }
    fn wrapper_fixture() -> (tempfile::TempDir, OwnedChild, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let core = directory.path().join("fake-engine");
        let marker = directory.path().join("engine-started");
        fs::write(
            &core,
            b"#!/bin/sh\nprintf '%s' \"$$\" > \"$WHALE_TEST_ENGINE_MARKER\"\nexec /bin/sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&core, fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "runtime::tests::engine_wrapper_process",
                "--nocapture",
            ])
            .env("WHALE_TEST_ENGINE_WRAPPER", "1")
            .env("WHALE_TEST_ENGINE_CORE", &core)
            .env("WHALE_TEST_ENGINE_DIRECTORY", directory.path())
            .env("WHALE_TEST_ENGINE_MARKER", &marker);
        let child = OwnedChild::spawn_with_input(&mut command, Stdio::piped()).unwrap();
        (directory, child, marker)
    }
    #[test]
    fn engine_wrapper_process() {
        if std::env::var("WHALE_TEST_ENGINE_WRAPPER").as_deref() != Ok("1") {
            return;
        }
        let core = PathBuf::from(std::env::var_os("WHALE_TEST_ENGINE_CORE").unwrap());
        let directory = PathBuf::from(std::env::var_os("WHALE_TEST_ENGINE_DIRECTORY").unwrap());
        let result = engine_entry(&core, &directory.join("config.json"), &directory);
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    #[test]
    fn engine_wrapper_eof_before_authorization_never_starts_engine() {
        let (_directory, mut child, marker) = wrapper_fixture();
        drop(child.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(3);
        while !child.exited().unwrap() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(child.exited().unwrap());
        assert!(!marker.exists());
    }
    #[test]
    fn authorized_engine_reuses_wrapper_pid_and_is_reaped() {
        let (_directory, mut child, marker) = wrapper_fixture();
        let pid = child.id();
        child
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(b"whale-engine-start-v1\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fs::read_to_string(&marker).is_ok_and(|text| text.parse::<u32>() == Ok(pid))
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists());
        assert_eq!(
            fs::read_to_string(&marker).unwrap().parse::<u32>().unwrap(),
            pid
        );
        assert_eq!(child.id(), pid);
        assert!(!child.exited().unwrap());
        child.stop().unwrap();
        assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0);
    }
    #[test]
    fn recovery_accepts_journaled_wrapper_and_exec_identity_only() {
        let journal = json!({"commands":["/root/helper _engine --config /root/config.json","/root/xray run -c /root/config.json"]});
        let commands = journal_commands(&journal).unwrap();
        assert!(commands.contains(&"/root/helper _engine --config /root/config.json"));
        assert!(commands.contains(&"/root/xray run -c /root/config.json"));
        assert!(!commands.contains(&"/root/xray run -c /different/config.json"));
        assert!(journal_commands(&json!({"commands":[""]})).is_err());
    }
}
