//! Versioned, peer-authenticated privileged controller.
use crate::runtime::{self, ConnectionState, OwnedChild, Status, command_output};
use crate::store::{Store, atomic_write, canonical};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SERVICE_ROOT: &str = "/Library/Application Support/vctl";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u32,
    version: String,
    action: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    protocol: u32,
    version: String,
    result: Option<Value>,
    error: Option<String>,
}

fn decode_request(body: &[u8]) -> Result<Request> {
    if body.len() > 4096 {
        bail!("Control request exceeds limit")
    }
    let request: Request = serde_json::from_slice(body).context("Unsupported control request")?;
    if request.protocol != crate::PROTOCOL_VERSION || request.version != crate::VERSION {
        bail!("System helper upgrade required")
    }
    if !matches!(
        request.action.as_str(),
        "up" | "down" | "restart" | "status" | "install" | "recover" | "uninstall"
    ) {
        bail!("Unsupported control action")
    }
    Ok(request)
}
fn label(profile: &Path, uid: u32) -> String {
    let digest = Sha256::digest(profile.as_os_str().as_encoded_bytes());
    format!(
        "io.github.nagraver.vctl.{uid}.{}",
        &hex::encode(digest)[..12]
    )
}
fn runtime_path(profile: &Path, uid: u32) -> PathBuf {
    PathBuf::from(SERVICE_ROOT).join("runtime").join(format!(
        "{uid}-{}",
        &hex::encode(Sha256::digest(profile.as_os_str().as_encoded_bytes()))[..12]
    ))
}

fn controller_label(profile: &Path, uid: u32) -> String {
    format!("{}.control", label(profile, uid))
}
fn controller_socket(profile: &Path, uid: u32) -> PathBuf {
    PathBuf::from(SERVICE_ROOT).join("sockets").join(format!(
        "{uid}-{}.sock",
        &hex::encode(Sha256::digest(profile.as_os_str().as_encoded_bytes()))[..12]
    ))
}
fn controller_plist(profile: &Path, uid: u32) -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons")
        .join(format!("{}.plist", controller_label(profile, uid)))
}
fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Administrator approval is required")
    }
    Ok(())
}

/// Walk from / with openat; no user-controlled ancestor or symlink can be accepted.
pub(crate) fn ensure_root_directory(path: &Path, final_mode: u32) -> Result<()> {
    require_root()?;
    if !path.is_absolute() {
        bail!("Root runtime path must be absolute")
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::RootDir => None,
            std::path::Component::Normal(name) => Some(Ok(name)),
            _ => Some(Err(anyhow::anyhow!("Invalid root directory component"))),
        })
        .collect::<Result<_>>()?;
    for (index, name) in components.iter().enumerate() {
        let name = CString::new(name.as_encoded_bytes())?;
        let mut fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                bail!("Unsafe root service directory")
            }
            let mode = if index + 1 == components.len() {
                final_mode
            } else {
                0o755
            };
            if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                bail!("Cannot safely open root service directory")
            }
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("Service directories must be root-owned and not writable by other users")
        }
        if index + 1 == components.len()
            && unsafe { libc::fchmod(directory.as_raw_fd(), final_mode as libc::mode_t) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        current = directory;
    }
    Ok(())
}

pub(crate) fn profile_owner(profile: &Path, expected: Option<u32>) -> Result<(u32, u32)> {
    let file =
        crate::store::open_directory(profile).context("Cannot safely open profile directory")?;
    let metadata = file.metadata()?;
    if metadata.uid() == 0 || expected.is_some_and(|uid| uid != metadata.uid()) {
        bail!("Profile owner mismatch")
    }
    Ok((metadata.uid(), metadata.gid()))
}
pub(crate) fn check_runtime(profile: &Path, runtime: &Path, uid: u32) -> Result<()> {
    require_root()?;
    profile_owner(profile, Some(uid))?;
    if runtime != runtime_path(profile, uid) {
        bail!("Unexpected runtime directory")
    }
    ensure_root_directory(runtime, 0o700)
}
pub(crate) struct TunLease {
    _lock: RuntimeLock,
}
pub(crate) fn exclusive_tun() -> Result<TunLease> {
    ensure_root_directory(Path::new(SERVICE_ROOT), 0o755)?;
    Ok(TunLease {
        _lock: RuntimeLock::acquire(PathBuf::from(SERVICE_ROOT).join("connection.lock"))?,
    })
}
fn recover_stopped(runtime: &Path) -> Result<()> {
    let _runtime = RuntimeLock::acquire(runtime.join("runtime.lock"))?;
    if !runtime::recovery_needed(runtime)? {
        return Ok(());
    }
    let system = exclusive_tun()?;
    runtime::recover(runtime, &system)
}
/// The system lease is required before interpreting any profile's shared DNS value.
/// Recover stale children/journals before a different profile acquires that value.
pub(crate) fn recover_stale_runtimes(lease: &TunLease, current: &Path) -> Result<()> {
    let root = PathBuf::from(SERVICE_ROOT).join("runtime");
    ensure_root_directory(&root, 0o755)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path == current {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("Invalid root runtime directory")
        };
        let Some((uid, digest)) = name.split_once('-') else {
            bail!("Invalid root runtime directory")
        };
        if uid.parse::<u32>().is_err()
            || digest.len() != 12
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("Invalid root runtime directory")
        }
        ensure_root_directory(&path, 0o700)?;
        let runtime_lock = RuntimeLock::acquire(path.join("runtime.lock"));
        if runtime_lock.is_err() && runtime::recovery_needed(&path)? {
            bail!("Another VPN profile is still completing recovery")
        }
        let Ok(_runtime) = runtime_lock else {
            continue;
        };
        if runtime::recovery_needed(&path)? {
            runtime::recover(&path, lease)?;
        }
    }
    Ok(())
}

pub(crate) struct RuntimeLock(File);
impl RuntimeLock {
    pub(crate) fn acquire(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            bail!("Unsafe runtime lock")
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("Service operation is already running")
        }
        Ok(Self(file))
    }
}
impl Drop for RuntimeLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            bail!("Peer identity unavailable")
        }
        Ok(uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        bail!("Whale system control requires macOS")
    }
}
fn frame(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut byte = [0_u8; 1];
    while body.len() <= maximum {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            return Ok(body);
        }
        body.push(byte[0]);
    }
    bail!("Incomplete or oversized control response")
}
fn exchange(profile: &Path, uid: u32, action: &str) -> Result<Value> {
    let mut stream = UnixStream::connect(controller_socket(profile, uid))
        .context("System helper is not available; install it in Whale")?;
    if peer_uid(&stream)? != 0 {
        bail!("System helper identity check failed")
    }
    stream.set_read_timeout(Some(Duration::from_secs(if action == "status" {
        3
    } else {
        150
    })))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let request = Request {
        protocol: crate::PROTOCOL_VERSION,
        version: crate::VERSION.into(),
        action: action.into(),
    };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    let bytes = frame(&mut stream, 1_048_576)?;
    let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!("System helper upgrade required; approve installation in Whale")
    })?;
    if reply.protocol != crate::PROTOCOL_VERSION || reply.version != crate::VERSION {
        bail!("System helper upgrade required; approve installation in Whale")
    }
    if let Some(error) = reply.error {
        bail!(error)
    }
    reply.result.context("System helper returned no result")
}
pub fn controller_call(profile: &Path, action: &str) -> Result<Value> {
    // Validate locally, too: unsupported actions must never start installation or a connection.
    decode_request(&serde_json::to_vec(&Request {
        protocol: crate::PROTOCOL_VERSION,
        version: crate::VERSION.into(),
        action: action.into(),
    })?)?;
    let profile = canonical(profile)?;
    let uid = unsafe { libc::getuid() };
    let owner = if uid == 0 {
        profile_owner(&profile, None)?.0
    } else {
        uid
    };
    if action != "status" {
        exchange(&profile, owner, "status")?;
    }
    exchange(&profile, owner, action)
}

pub fn snapshot(profile: &Path) -> Result<Value> {
    let profile = canonical(profile)?;
    let uid = unsafe { libc::getuid() };
    let installed = controller_plist(&profile, uid).exists();
    if !controller_socket(&profile, uid).exists() {
        let mut status = Status::new(ConnectionState::Stopped);
        if installed {
            status.connection_state = ConnectionState::Failed;
            status.error = Some("System helper is unavailable; reinstall it in Whale".into());
        }
        return Ok(status.native(installed));
    }
    match exchange(&profile, uid, "status") {
        Ok(value) => value
            .get("tun")
            .cloned()
            .context("System helper returned no connection state"),
        Err(error) => {
            let mut status = Status::new(ConnectionState::Failed);
            status.error = Some(error.to_string());
            Ok(status.native(installed))
        }
    }
}

pub fn core_path(override_path: Option<&Path>) -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .context("Executable directory unavailable")?;
    let mut candidates = Vec::new();
    if let Some(path) = override_path {
        candidates.push(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("WHALE_CORE").or_else(|| std::env::var_os("VCTL_CORE")) {
        candidates.push(PathBuf::from(path));
    }
    candidates.extend([
        directory.join("xray"),
        directory.join(".tools/xray"),
        directory.join("../libexec/xray"),
        directory.join("../.tools/xray"),
    ]);
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|directory| directory.join("xray")));
    }
    for (index, path) in candidates.iter().enumerate() {
        if !path.exists() {
            if index == 0 && override_path.is_some() {
                bail!("Selected Xray executable is missing")
            };
            continue;
        }
        let path = canonical(path)?;
        let output = command_output(
            Command::new(&path).arg("version"),
            Duration::from_secs(5),
            65536,
        )?;
        let version = String::from_utf8_lossy(&output.stdout);
        if !output.success || !version.starts_with("Xray 26.9.9 ") {
            bail!("Whale requires the bundled Xray 26.9.9 engine")
        }
        return Ok(path);
    }
    bail!("Bundled Xray engine is missing; reinstall Whale")
}

fn launchctl(arguments: &[&str], timeout: u64) -> Result<()> {
    let result = command_output(
        Command::new("/bin/launchctl").args(arguments),
        Duration::from_secs(timeout),
        65536,
    )?;
    if !result.success {
        bail!(
            "macOS service manager operation failed (exit status {:?})",
            result.exit_code
        )
    }
    Ok(())
}
fn loaded_status(exit_code: Option<i32>) -> Result<bool> {
    match exit_code {
        Some(0) => Ok(true),
        // launchctl's service-not-found status, distinct from permission/tool failures.
        Some(113) => Ok(false),
        other => bail!("Could not inspect macOS service (exit status {other:?})"),
    }
}
fn is_loaded(target: &str) -> Result<bool> {
    let result = command_output(
        Command::new("/bin/launchctl").args(["print", target]),
        Duration::from_secs(5),
        65536,
    )?;
    loaded_status(result.exit_code)
}

trait StoppingJob {
    fn loaded(&mut self) -> Result<bool>;
    fn bootout(&mut self) -> Result<()>;
}
fn stop_job(job: &mut impl StoppingJob, timeout: Duration) -> Result<()> {
    if !job.loaded()? {
        return Ok(());
    }
    job.bootout()?;
    // bootout acknowledges removal before a running job has actually exited.
    // launchd retains its label while SIGTERM/DNS cleanup is still in progress.
    let started = Instant::now();
    while job.loaded()? {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("Previous system helper did not finish shutting down")
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    Ok(())
}
struct LaunchdJob<'a>(&'a str);
impl StoppingJob for LaunchdJob<'_> {
    fn loaded(&mut self) -> Result<bool> {
        is_loaded(self.0)
    }
    fn bootout(&mut self) -> Result<()> {
        launchctl(&["bootout", self.0], 60)
    }
}
fn stop_launchd(target: &str) -> Result<()> {
    // The controller plist grants 120 seconds for orderly child/DNS shutdown.
    // Only launchd may enforce its exit timeout; installation never force-kills it.
    stop_job(&mut LaunchdJob(target), Duration::from_secs(130))
}

fn read_executable(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 256_000_000 || metadata.mode() & 0o111 == 0 {
        bail!("Invalid application executable")
    }
    let mut body = Vec::new();
    file.take(256_000_001).read_to_end(&mut body)?;
    if body.len() > 256_000_000 {
        bail!("Executable exceeds size limit")
    }
    Ok(body)
}
fn install_snapshot(directory: &Path, core: &Path) -> Result<PathBuf> {
    ensure_root_directory(directory, 0o755)?;
    let helper = read_executable(&canonical(&std::env::current_exe()?)?)?;
    let xray = read_executable(&canonical(core)?)?;
    let mut hash = Sha256::new();
    hash.update(&helper);
    hash.update(&xray);
    let release = directory.join(hex::encode(hash.finalize()));
    if release.exists() {
        ensure_root_directory(&release, 0o755)?;
        // A matching directory name is insufficient proof of immutable contents.
        if read_executable(&release.join("whale-helper"))? != helper
            || read_executable(&release.join("xray"))? != xray
        {
            bail!("Installed executable snapshot failed integrity verification")
        }
        return Ok(release);
    }
    let temporary = tempfile::Builder::new()
        .prefix(".install-")
        .tempdir_in(directory)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))?;
    atomic_write(&temporary.path().join("whale-helper"), &helper, 0o755)?;
    atomic_write(&temporary.path().join("xray"), &xray, 0o755)?;
    fs::rename(temporary.path(), &release)?;
    File::open(directory)?.sync_all()?;
    Ok(release)
}

trait Deployment {
    fn write(&mut self, body: &[u8]) -> Result<()>;
    fn remove(&mut self) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn ready(&mut self) -> Result<()>;
}
fn activate_deployment(
    target: &mut impl Deployment,
    body: &[u8],
    previous: Option<&[u8]>,
    was_loaded: bool,
) -> Result<()> {
    let install = target
        .write(body)
        .context("writing helper definition")
        .and_then(|()| target.start().context("starting helper"))
        .and_then(|()| target.ready().context("verifying helper handshake"));
    let Err(install_error) = install else {
        return Ok(());
    };
    let cleanup_error = target
        .stop()
        .err()
        .map(|error| format!("; stopping failed helper also failed: {error:#}"))
        .unwrap_or_default();
    let rollback = if let Some(previous) = previous {
        target
            .write(previous)
            .context("restoring previous helper definition")
            .and_then(|()| {
                if was_loaded && cleanup_error.is_empty() {
                    target.start().context("restarting previous helper")
                } else {
                    Ok(())
                }
            })
    } else {
        target
            .remove()
            .context("removing incomplete helper definition")
    };
    if let Err(rollback_error) = rollback {
        bail!(
            "Helper installation failed while {install_error:#}{cleanup_error}; rollback failed while {rollback_error:#}"
        )
    }
    if !cleanup_error.is_empty() {
        bail!(
            "Helper installation failed while {install_error:#}{cleanup_error}; the installation definition was rolled back, but helper shutdown could not be verified"
        )
    }
    let restored = if previous.is_some() {
        "the previous installation was restored"
    } else {
        "the incomplete installation was removed"
    };
    // These causes are platform errors already redacted at the command boundary;
    // retain their stages without exposing raw child stderr or profile contents.
    bail!("Helper installation failed while {install_error:#}{cleanup_error}; {restored}")
}
struct LaunchdDeployment<'a> {
    profile: &'a Path,
    uid: u32,
    plist: &'a Path,
    target: &'a str,
}
impl Deployment for LaunchdDeployment<'_> {
    fn write(&mut self, body: &[u8]) -> Result<()> {
        atomic_write(self.plist, body, 0o644)
    }
    fn remove(&mut self) -> Result<()> {
        match fs::remove_file(self.plist) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn start(&mut self) -> Result<()> {
        launchctl(
            &[
                "bootstrap",
                "system",
                self.plist.to_str().context("Unsupported service path")?,
            ],
            30,
        )
    }
    fn stop(&mut self) -> Result<()> {
        stop_launchd(self.target)
    }
    fn ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if exchange(self.profile, self.uid, "status").is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("The new system helper did not complete its version handshake")
    }
}

pub fn install_controller(profile: &Path, core: &Path) -> Result<()> {
    require_root()?;
    let profile = canonical(profile)?;
    let (uid, _) = profile_owner(&profile, None)?;
    if let Ok(sudo_uid) = std::env::var("SUDO_UID")
        && sudo_uid.parse::<u32>().ok() != Some(uid)
    {
        bail!("Profile must belong to the administrator request's user")
    }
    let name = controller_label(&profile, uid);
    let target = format!("system/{name}");
    let directory = PathBuf::from(SERVICE_ROOT).join(&name);
    let release = install_snapshot(&directory, core)?;
    let runtime = runtime_path(&profile, uid);
    ensure_root_directory(&runtime, 0o700)?;
    let plist = controller_plist(&profile, uid);
    let previous = fs::read(&plist).ok();
    let was_loaded = is_loaded(&target)?;
    // The legacy controller and separate VPN service must not silently coexist
    // with the Rust controller. launchd sends their orderly termination signal.
    let legacy_name = label(&profile, uid);
    let legacy_target = format!("system/{legacy_name}");
    let legacy_marker = PathBuf::from("/var/run").join(format!("{legacy_name}.enabled"));
    if legacy_marker.exists() {
        fs::remove_file(&legacy_marker)?;
    }
    stop_launchd(&legacy_target)?;
    if was_loaded {
        stop_launchd(&target)?;
    }
    let definition = json!({
        "Label":name,"ProgramArguments":[release.join("whale-helper"),"--home",profile,"--core",release.join("xray"),"_controller","--owner",uid.to_string()],
        "WorkingDirectory":release,"RunAtLoad":true,"KeepAlive":true,"ThrottleInterval":5,"ExitTimeOut":120,"Umask":63,
        "EnvironmentVariables":{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","WHALE_CONTROLLER_LABEL":name},
        "StandardOutPath":directory.join("controller.log"),"StandardErrorPath":directory.join("controller.log")
    });
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, &definition)?;
    let mut deployment = LaunchdDeployment {
        profile: &profile,
        uid,
        plist: &plist,
        target: &target,
    };
    activate_deployment(&mut deployment, &body, previous.as_deref(), was_loaded)?;
    let legacy_plist = PathBuf::from("/Library/LaunchDaemons").join(format!("{legacy_name}.plist"));
    if legacy_plist.exists() {
        fs::remove_file(legacy_plist)?;
    }
    Ok(())
}

pub fn refresh_as_user(profile: &Path, uid: u32) -> Result<()> {
    let (_, gid) = profile_owner(profile, Some(uid))?;
    if unsafe { libc::geteuid() } == 0 {
        // Drop supplementary groups first; UID is dropped last and cannot be regained.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setgid(gid) } != 0
            || unsafe { libc::setuid(uid) } != 0
        {
            bail!("Could not drop system privileges")
        }
    }
    if unsafe { libc::geteuid() } != uid || unsafe { libc::getuid() } != uid {
        bail!("Refresh must run as the profile owner")
    }
    crate::sources::refresh(&Store::new(profile)?)
}

struct Controller {
    profile: PathBuf,
    core: PathBuf,
    runtime: PathBuf,
    uid: u32,
    child: Mutex<Option<OwnedChild>>,
    reconnect: Mutex<()>,
    admission: Admission,
}
struct Admission {
    generation: AtomicU64,
    stopping: AtomicBool,
    closing: AtomicBool,
    shutdown: Arc<AtomicBool>,
}
impl Admission {
    fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self {
            generation: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            shutdown,
        }
    }
    fn ticket(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    fn check(&self, ticket: u64) -> Result<()> {
        if self.closing.load(Ordering::SeqCst) || self.shutdown.load(Ordering::SeqCst) {
            bail!("System helper is shutting down")
        }
        if self.stopping.load(Ordering::SeqCst) || self.ticket() != ticket {
            bail!("Connection request was cancelled by a later stop")
        }
        Ok(())
    }
    fn admitted<T, R>(
        &self,
        ticket: u64,
        mutex: &Mutex<T>,
        action: impl FnOnce(&mut T) -> Result<R>,
    ) -> Result<R> {
        let mut state = mutex
            .lock()
            .map_err(|_| anyhow::anyhow!("Controller state unavailable"))?;
        self.check(ticket)?;
        action(&mut state)
    }
    fn stop(&self) -> Result<Stopping<'_>> {
        if self.stopping.swap(true, Ordering::SeqCst) {
            bail!("VPN is already stopping")
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(Stopping(self))
    }
    fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
    fn begin_close(&self) -> Result<Closing<'_>> {
        if self.shutdown.load(Ordering::SeqCst)
            || self
                .closing
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            bail!("System helper is already shutting down")
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(Closing(self))
    }
}
struct Closing<'a>(&'a Admission);
impl Closing<'_> {
    fn commit(self) {
        self.0.shutdown.store(true, Ordering::SeqCst);
    }
}
impl Drop for Closing<'_> {
    fn drop(&mut self) {
        // Cancel requests accepted during the unsuccessful uninstall as well.
        // A committed uninstall or a concurrent signal must never reopen admission.
        self.0.generation.fetch_add(1, Ordering::SeqCst);
        if !self.0.shutdown.load(Ordering::SeqCst) {
            self.0.closing.store(false, Ordering::SeqCst);
        }
    }
}
struct Stopping<'a>(&'a Admission);
impl Drop for Stopping<'_> {
    fn drop(&mut self) {
        self.0.generation.fetch_add(1, Ordering::SeqCst);
        self.0.stopping.store(false, Ordering::SeqCst);
    }
}
fn fresh_status(mut status: Status, now: f64) -> Status {
    // Validation, proxy preflight and orderly DNS recovery are bounded operations
    // that may take longer than the steady-state three-second selection poll.
    let maximum_age = match status.connection_state {
        ConnectionState::Starting | ConnectionState::Stopping => 120.0,
        _ => 30.0,
    };
    if !matches!(
        status.connection_state,
        ConnectionState::Stopped | ConnectionState::Failed
    ) && (now - status.updated > maximum_age || status.updated > now + 5.0)
    {
        status.connection_state = ConnectionState::Failed;
        status.server = None;
        status.error =
            Some("VPN status is stale; the current connection could not be verified".into());
    }
    status
}
impl Controller {
    fn status(&self) -> Value {
        let status = runtime::read_status(&self.runtime)
            .unwrap_or_else(|_| Status::new(ConnectionState::Stopped));
        fresh_status(status, crate::model::now()).native(true)
    }
    fn up(&self, ticket: u64) -> Result<Value> {
        profile_owner(&self.profile, Some(self.uid))?;
        self.admission.check(ticket)?;
        let pid = self.admission.admitted(ticket, &self.child, |child| {
            if child
                .as_mut()
                .is_some_and(|child| !child.exited().unwrap_or(false))
            {
                bail!("VPN is already running")
            }
            *child = None;
            recover_stopped(&self.runtime)?;
            let mut status = Status::new(ConnectionState::Starting);
            status.save(&self.runtime)?;
            let executable = std::env::current_exe()?;
            let mut command = Command::new(executable);
            command
                .arg("--home")
                .arg(&self.profile)
                .arg("--core")
                .arg(&self.core)
                .args(["_runtime", "--owner", &self.uid.to_string(), "--runtime"])
                .arg(&self.runtime)
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("WHALE_CONTROLLER_PID", std::process::id().to_string());
            self.admission.check(ticket)?;
            match OwnedChild::spawn(&mut command) {
                Ok(process) => {
                    let pid = process.id();
                    *child = Some(process);
                    Ok(pid)
                }
                Err(error) => {
                    status.connection_state = ConnectionState::Failed;
                    status.error = Some("The VPN worker could not be started".into());
                    status.save(&self.runtime)?;
                    Err(error)
                }
            }
        })?;
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            self.current_connection(ticket, pid)?;
            if let Ok(status) = runtime::read_status(&self.runtime) {
                match status.connection_state {
                    ConnectionState::Connected => return Ok(status.native(true)),
                    ConnectionState::Failed => bail!(
                        "VPN could not connect; the previous system DNS was restored when possible"
                    ),
                    ConnectionState::Stopped | ConnectionState::Stopping => {
                        bail!("Connection was cancelled")
                    }
                    ConnectionState::Starting => (),
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("Controller state unavailable"))?;
        self.admission.check(ticket)?;
        if child.as_ref().map(OwnedChild::id) != Some(pid) {
            bail!("Connection request was superseded")
        }
        let _stopping = self.admission.stop()?;
        self.stop_locked(&mut child)?;
        bail!("Connection timed out and was stopped")
    }
    fn current_connection(&self, ticket: u64, pid: u32) -> Result<()> {
        self.admission.admitted(ticket, &self.child, |child| {
            if child.as_ref().map(OwnedChild::id) != Some(pid) {
                bail!("Connection request was superseded")
            }
            Ok(())
        })
    }
    fn down(&self) -> Result<Value> {
        let _stopping = self.admission.stop()?;
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("Controller state unavailable"))?;
        self.stop_locked(&mut child)
    }
    fn stop_locked(&self, child: &mut Option<OwnedChild>) -> Result<Value> {
        let mut status = runtime::read_status(&self.runtime)
            .unwrap_or_else(|_| Status::new(ConnectionState::Stopping));
        status.connection_state = ConnectionState::Stopping;
        status.save(&self.runtime)?;
        if let Some(mut process) = child.take() {
            process.stop_timeout(Duration::from_secs(60))?;
        }
        recover_stopped(&self.runtime)?;
        let mut status = Status::new(ConnectionState::Stopped);
        status.save(&self.runtime)?;
        Ok(status.native(true))
    }
    fn restart(&self, ticket: u64) -> Result<Value> {
        let _operation = self
            .reconnect
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Reconnect is already in progress"))?;
        let id = format!(
            "{:x}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let running = self.admission.admitted(ticket, &self.child, |child| {
            if child.is_none() {
                return Ok(false);
            }
            atomic_write(
                &self.runtime.join("reconnect.json"),
                &serde_json::to_vec(&json!({"id":id}))?,
                0o600,
            )?;
            Ok(true)
        })?;
        if !running {
            return self.up(ticket);
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            self.admission.check(ticket)?;
            if let Ok(status) = runtime::read_status(&self.runtime) {
                if status.completed_operation.as_deref() == Some(&id) {
                    if let Some(error) = status.operation_error {
                        bail!(error)
                    }
                    return Ok(status.native(true));
                }
                if matches!(
                    status.connection_state,
                    ConnectionState::Stopped | ConnectionState::Stopping | ConnectionState::Failed
                ) {
                    bail!("Reconnect was cancelled or the VPN stopped")
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("Reconnect has not completed; inspect connection status")
    }
    fn action(&self, action: &str) -> Result<Value> {
        let ticket = self.admission.ticket();
        match action {
            "status" => Ok(
                json!({"ready":true,"protocol":crate::PROTOCOL_VERSION,"version":crate::VERSION,"tun":self.status()}),
            ),
            "up" => self.up(ticket),
            "down" => self.down(),
            "restart" => self.restart(ticket),
            "recover" => {
                let child = self
                    .child
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Controller state unavailable"))?;
                if child.is_some() {
                    bail!("Disconnect the VPN before recovery")
                };
                drop(child);
                self.down()
            }
            "install" => Ok(self.status()),
            "uninstall" => {
                let closing = self.admission.begin_close()?;
                let status = self.down()?;
                fs::remove_file(controller_plist(&self.profile, self.uid))?;
                closing.commit();
                Ok(status)
            }
            _ => bail!("Unsupported control action"),
        }
    }
    fn reap(&self) {
        let Ok(mut child) = self.child.try_lock() else {
            return;
        };
        if !child
            .as_mut()
            .is_some_and(|child| child.exited().unwrap_or(true))
        {
            return;
        }
        *child = None;
        let mut status = runtime::read_status(&self.runtime)
            .unwrap_or_else(|_| Status::new(ConnectionState::Failed));
        if !matches!(status.connection_state, ConnectionState::Stopped) {
            status.connection_state = ConnectionState::Failed;
            status.error = Some("VPN worker exited; recovering system DNS".into());
            status.core_pid = None;
            status.server = None;
            let _ = status.save(&self.runtime);
            let recovered = recover_stopped(&self.runtime);
            status.error = Some(
                if recovered.is_ok() {
                    "VPN worker exited; system DNS was restored"
                } else {
                    "VPN worker exited; DNS recovery is incomplete"
                }
                .into(),
            );
            let _ = status.save(&self.runtime);
        } else {
            let _ = recover_stopped(&self.runtime);
        }
    }
}

pub fn serve_controller(profile: &Path, core: &Path, uid: u32) -> Result<()> {
    require_root()?;
    let profile = canonical(profile)?;
    profile_owner(&profile, Some(uid))?;
    let name = controller_label(&profile, uid);
    if std::env::var("WHALE_CONTROLLER_LABEL").ok().as_deref() != Some(&name) {
        bail!("Controller must be started by the installed macOS service")
    }
    let runtime = runtime_path(&profile, uid);
    check_runtime(&profile, &runtime, uid)?;
    let _controller_lock = RuntimeLock::acquire(runtime.join("controller.lock"))?;
    // A surviving worker observes its parent change and exits. Never recover while it holds the runtime lock.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut recovery_failed = false;
    loop {
        if let Ok(_lock) = RuntimeLock::acquire(runtime.join("runtime.lock")) {
            if runtime::recovery_needed(&runtime)? {
                recovery_failed = exclusive_tun()
                    .and_then(|system| runtime::recover(&runtime, &system))
                    .is_err();
            }
            break;
        }
        if Instant::now() >= deadline {
            bail!("Previous VPN worker is still stopping")
        }
        thread::sleep(Duration::from_millis(100));
    }
    let mut status = Status::new(ConnectionState::Stopped);
    if recovery_failed {
        status.connection_state = ConnectionState::Failed;
        status.error = Some(
            "DNS recovery is pending; disconnect any other Whale profile and use Recover DNS"
                .into(),
        );
    }
    status.save(&runtime)?;
    let socket = controller_socket(&profile, uid);
    ensure_root_directory(socket.parent().context("Missing socket directory")?, 0o755)?;
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let socket_c = CString::new(socket.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(socket_c.as_ptr(), uid, u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(libc::SIGINT, Arc::clone(&shutdown))?;
    let controller = Arc::new(Controller {
        profile,
        core: core.into(),
        runtime,
        uid,
        child: Mutex::new(None),
        reconnect: Mutex::new(()),
        admission: Admission::new(Arc::clone(&shutdown)),
    });
    let connections = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Relaxed) {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let _ = workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        controller.reap();
        match listener.accept() {
            Ok((mut stream, _)) => {
                if !peer_uid(&stream).is_ok_and(|peer| peer == uid || peer == 0)
                    || connections.load(Ordering::Relaxed) >= 16
                {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let controller = Arc::clone(&controller);
                let connections = Arc::clone(&connections);
                connections.fetch_add(1, Ordering::Relaxed);
                workers.push(thread::spawn(move || {
                    let result = frame(&mut stream, 4096)
                        .and_then(|body| decode_request(&body))
                        .and_then(|request| controller.action(&request.action));
                    let (result, error) = match result {
                        Ok(value) => (Some(value), None),
                        Err(error) => (None, Some(error.to_string())),
                    };
                    let reply = Reply {
                        protocol: crate::PROTOCOL_VERSION,
                        version: crate::VERSION.into(),
                        result,
                        error,
                    };
                    let _ = serde_json::to_writer(&mut stream, &reply);
                    let _ = stream.write_all(b"\n");
                    connections.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error.into()),
        }
    }
    // Close admission first, then join every accepted request. In particular a
    // down/uninstall thread must finish before any runtime directory is removed.
    controller.admission.close();
    drop(listener);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = controller.down();
    let _ = fs::remove_file(socket);
    if !controller_plist(&controller.profile, uid).exists() {
        ensure_root_directory(&controller.runtime, 0o700)?;
        fs::remove_dir_all(&controller.runtime)?;
        let release_directory = PathBuf::from(SERVICE_ROOT).join(&name);
        ensure_root_directory(&release_directory, 0o755)?;
        fs::remove_dir_all(release_directory)?;
        // launchd must forget KeepAlive before process exit; the plist has already been removed.
        let _ = launchctl(&["bootout", &format!("system/{name}")], 10);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_rejects_legacy_unknown_fields_and_arbitrary_actions() {
        assert!(decode_request(br#"{"action":"up"}"#).is_err());
        for action in [
            "up",
            "down",
            "restart",
            "status",
            "install",
            "recover",
            "uninstall",
        ] {
            let body = serde_json::to_vec(
                &serde_json::json!({"protocol":2,"version":crate::VERSION,"action":action}),
            )
            .unwrap();
            assert_eq!(decode_request(&body).unwrap().action, action);
        }
        for value in [
            serde_json::json!({"protocol":2,"version":crate::VERSION,"action":"run"}),
            serde_json::json!({"protocol":2,"version":crate::VERSION,"action":"up","core":"/tmp/evil"}),
            serde_json::json!({"protocol":1,"version":crate::VERSION,"action":"up"}),
            serde_json::json!({"protocol":2,"version":"old","action":"up"}),
        ] {
            assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn identities_preserve_legacy_label_and_runtime_is_outside_profile() {
        let p = Path::new("/private/tmp/profile");
        assert_eq!(label(p, 501), "io.github.nagraver.vctl.501.6dd1f9f3641a");
        let runtime = runtime_path(p, 501);
        assert!(runtime.starts_with("/Library/Application Support/vctl"));
        assert!(!runtime.starts_with(p));
        assert_ne!(runtime, runtime_path(p, 502));
    }
    #[test]
    fn runtime_lock_refuses_symlink_without_changing_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        let before = fs::metadata(&target).unwrap();
        let lock = directory.path().join("runtime.lock");
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        assert!(RuntimeLock::acquire(lock).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        assert_eq!(fs::metadata(target).unwrap().uid(), before.uid());
    }
    #[test]
    fn framed_protocol_rejects_oversized_input() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"12345\n").unwrap();
        assert!(frame(&mut a, 4).is_err());
    }
    #[test]
    fn peer_identity_matches_current_user() {
        let (a, _) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }
    #[derive(Default)]
    struct FakeDeployment {
        body: Vec<u8>,
        loaded: bool,
        reject_write: bool,
        reject_start: bool,
        reject_ready: bool,
        reject_restore_start: bool,
        reject_stop: bool,
        starts: usize,
    }
    impl Deployment for FakeDeployment {
        fn write(&mut self, body: &[u8]) -> Result<()> {
            if body == b"new" && self.reject_write {
                bail!("definition write failed")
            }
            self.body = body.to_vec();
            Ok(())
        }
        fn remove(&mut self) -> Result<()> {
            self.body.clear();
            Ok(())
        }
        fn start(&mut self) -> Result<()> {
            if self.body == b"new" && self.reject_start {
                bail!("bootstrap failed")
            };
            if self.body == b"old" && self.reject_restore_start {
                bail!("previous bootstrap failed")
            }
            self.loaded = true;
            self.starts += 1;
            Ok(())
        }
        fn stop(&mut self) -> Result<()> {
            if self.reject_stop {
                bail!("helper shutdown timed out")
            }
            self.loaded = false;
            Ok(())
        }
        fn ready(&mut self) -> Result<()> {
            if self.reject_ready {
                bail!("handshake failed")
            };
            Ok(())
        }
    }
    #[test]
    fn failed_helper_handshake_restores_previous_loaded_installation() {
        let mut target = FakeDeployment {
            body: b"old".to_vec(),
            reject_ready: true,
            ..Default::default()
        };
        assert!(activate_deployment(&mut target, b"new", Some(b"old"), true).is_err());
        assert_eq!(target.body, b"old");
        assert!(target.loaded);
    }
    #[test]
    fn failed_bootstrap_restores_previous_unloaded_installation() {
        let mut target = FakeDeployment {
            body: b"old".to_vec(),
            reject_start: true,
            ..Default::default()
        };
        assert!(activate_deployment(&mut target, b"new", Some(b"old"), false).is_err());
        assert_eq!(target.body, b"old");
        assert!(!target.loaded);
    }
    #[test]
    fn failed_first_install_removes_broken_service() {
        let mut target = FakeDeployment {
            reject_ready: true,
            ..Default::default()
        };
        assert!(activate_deployment(&mut target, b"new", None, false).is_err());
        assert!(target.body.is_empty());
        assert!(!target.loaded);
    }
    #[test]
    fn install_write_failure_reports_stage_cause_and_restoration() {
        let mut target = FakeDeployment {
            reject_write: true,
            ..Default::default()
        };
        let error = activate_deployment(&mut target, b"new", Some(b"old"), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("writing helper definition"), "{error}");
        assert!(error.contains("definition write failed"), "{error}");
        assert!(
            error.contains("previous installation was restored"),
            "{error}"
        );
        assert_eq!(target.body, b"old");
        assert!(target.loaded);
    }
    #[test]
    fn install_start_failure_reports_stage_cause_and_restoration() {
        let mut target = FakeDeployment {
            reject_start: true,
            ..Default::default()
        };
        let error = activate_deployment(&mut target, b"new", Some(b"old"), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("starting helper"), "{error}");
        assert!(error.contains("bootstrap failed"), "{error}");
        assert!(
            error.contains("previous installation was restored"),
            "{error}"
        );
        assert_eq!(target.body, b"old");
        assert!(target.loaded);
    }
    #[test]
    fn rollback_failure_preserves_both_failure_stages_and_causes() {
        let mut target = FakeDeployment {
            reject_ready: true,
            reject_restore_start: true,
            ..Default::default()
        };
        let error = activate_deployment(&mut target, b"new", Some(b"old"), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("verifying helper handshake"), "{error}");
        assert!(error.contains("handshake failed"), "{error}");
        assert!(error.contains("restarting previous helper"), "{error}");
        assert!(error.contains("previous bootstrap failed"), "{error}");
    }
    #[test]
    fn incomplete_shutdown_does_not_bootstrap_previous_helper() {
        let mut target = FakeDeployment {
            reject_ready: true,
            reject_stop: true,
            ..Default::default()
        };
        let error = activate_deployment(&mut target, b"new", Some(b"old"), true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            target.starts, 1,
            "must not restart before the new job is gone"
        );
        assert_eq!(target.body, b"old");
        assert!(error.contains("shutdown could not be verified"), "{error}");
    }
    struct SlowStoppingJob {
        states: std::collections::VecDeque<bool>,
        visible: bool,
        bootouts: usize,
    }
    impl StoppingJob for SlowStoppingJob {
        fn loaded(&mut self) -> Result<bool> {
            self.visible = self.states.pop_front().unwrap_or(self.visible);
            Ok(self.visible)
        }
        fn bootout(&mut self) -> Result<()> {
            self.bootouts += 1;
            Ok(())
        }
    }
    #[test]
    fn bootout_waits_until_terminating_job_is_removed() {
        let mut job = SlowStoppingJob {
            states: [true, true, false].into(),
            visible: true,
            bootouts: 0,
        };
        stop_job(&mut job, Duration::from_secs(1)).unwrap();
        assert!(
            !job.visible,
            "bootout may return while launchd still owns the terminating job"
        );
        assert_eq!(job.bootouts, 1);
    }
    #[test]
    fn bootout_deadline_does_not_report_a_live_job_stopped() {
        let mut job = SlowStoppingJob {
            states: [true].into(),
            visible: true,
            bootouts: 0,
        };
        assert!(stop_job(&mut job, Duration::ZERO).is_err());
        assert!(job.visible);
    }
    #[test]
    fn service_query_failure_is_not_treated_as_a_removed_job() {
        assert!(loaded_status(Some(0)).unwrap());
        assert!(!loaded_status(Some(113)).unwrap());
        assert!(loaded_status(Some(1)).is_err());
        assert!(loaded_status(None).is_err());
    }
    #[test]
    fn stalled_runtime_is_not_reported_connected() {
        let mut status = Status::new(ConnectionState::Connected);
        status.updated = 100.0;
        assert_eq!(
            fresh_status(status.clone(), 130.0).connection_state,
            ConnectionState::Connected
        );
        assert_eq!(
            fresh_status(status, 131.0).connection_state,
            ConnectionState::Failed
        );
        let mut starting = Status::new(ConnectionState::Starting);
        starting.updated = 100.0;
        assert_eq!(
            fresh_status(starting.clone(), 160.0).connection_state,
            ConnectionState::Starting
        );
        assert_eq!(
            fresh_status(starting, 221.0).connection_state,
            ConnectionState::Failed
        );
    }
    #[test]
    fn socket_paths_fit_even_the_largest_uid() {
        let profile = Path::new("/private/tmp/profile");
        assert!(controller_socket(profile, u32::MAX).as_os_str().len() < 104);
        assert!(
            runtime_path(profile, u32::MAX)
                .join("api.sock")
                .as_os_str()
                .len()
                < 104
        );
    }
    #[test]
    fn system_lease_excludes_other_profile_until_recovery_finishes() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let path = directory.path().join("system.lock");
        let lease = TunLease {
            _lock: RuntimeLock::acquire(path.clone()).unwrap(),
        };
        // runtime::recover requires &TunLease, so an actor without this lock
        // cannot interpret another profile's shared fake DNS setting.
        assert!(RuntimeLock::acquire(path.clone()).is_err());
        drop(lease);
        assert!(RuntimeLock::acquire(path).is_ok());
    }
    #[test]
    fn queued_connect_cannot_restart_after_a_completed_stop() {
        let admission = Arc::new(Admission::new(Arc::new(AtomicBool::new(false))));
        let child = Arc::new(Mutex::new(false));
        let ticket = admission.ticket();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stop_admission = Arc::clone(&admission);
        let stop_child = Arc::clone(&child);
        let stop = thread::spawn(move || {
            let _stopping = stop_admission.stop().unwrap();
            let mut running = stop_child.lock().unwrap();
            *running = false;
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx.recv().unwrap();
        let start_admission = Arc::clone(&admission);
        let start_child = Arc::clone(&child);
        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let start = thread::spawn(move || {
            queued_tx.send(()).unwrap();
            start_admission.admitted(ticket, &start_child, |running| {
                *running = true;
                Ok(())
            })
        });
        queued_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        stop.join().unwrap();
        assert!(start.join().unwrap().is_err());
        assert!(!*child.lock().unwrap());
        // A genuinely new request after stop is allowed to connect again.
        admission
            .admitted(admission.ticket(), &child, |running| {
                *running = true;
                Ok(())
            })
            .unwrap();
    }
    #[test]
    fn uninstall_gate_permanently_rejects_old_and_new_connect_requests() {
        let admission = Arc::new(Admission::new(Arc::new(AtomicBool::new(false))));
        let child = Arc::new(Mutex::new(false));
        let ticket = admission.ticket();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();
        let pending_admission = Arc::clone(&admission);
        let pending_child = Arc::clone(&child);
        let pending = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            pending_admission.admitted(ticket, &pending_child, |running| {
                *running = true;
                Ok(())
            })
        });
        ready_rx.recv().unwrap();
        admission.close();
        {
            let _stop = admission.stop().unwrap();
            *child.lock().unwrap() = false;
        }
        go_tx.send(()).unwrap();
        assert!(pending.join().unwrap().is_err());
        assert!(
            admission
                .admitted(admission.ticket(), &child, |running| {
                    *running = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!*child.lock().unwrap());
    }
    #[test]
    fn failed_uninstall_during_stop_allows_a_fresh_connection_request() {
        let controller = Controller {
            profile: "/unused/profile".into(),
            core: "/unused/core".into(),
            runtime: "/unused/runtime".into(),
            uid: 501,
            child: Mutex::new(None),
            reconnect: Mutex::new(()),
            admission: Admission::new(Arc::new(AtomicBool::new(false))),
        };
        let stopping = controller.admission.stop().unwrap();
        assert!(controller.action("uninstall").is_err());
        drop(stopping);
        assert!(
            controller
                .admission
                .check(controller.admission.ticket())
                .is_ok()
        );
    }
    #[test]
    fn failed_uninstall_invalidates_queued_requests_and_has_one_owner() {
        let admission = Admission::new(Arc::new(AtomicBool::new(false)));
        let before = admission.ticket();
        let closing = admission.begin_close().unwrap();
        let during = admission.ticket();
        assert!(admission.begin_close().is_err());
        assert!(admission.check(during).is_err());
        drop(closing);
        assert!(admission.check(before).is_err());
        assert!(admission.check(during).is_err());
        assert!(admission.check(admission.ticket()).is_ok());
    }
    #[test]
    fn failed_uninstall_cannot_reopen_admission_after_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let admission = Admission::new(Arc::clone(&shutdown));
        let closing = admission.begin_close().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        admission.close();
        drop(closing);
        assert!(admission.closing.load(Ordering::SeqCst));
        assert!(admission.check(admission.ticket()).is_err());
        assert!(admission.begin_close().is_err());
    }
    #[test]
    fn completed_uninstall_keeps_admission_closed() {
        let admission = Admission::new(Arc::new(AtomicBool::new(false)));
        admission.begin_close().unwrap().commit();
        assert!(admission.closing.load(Ordering::SeqCst));
        assert!(admission.shutdown.load(Ordering::SeqCst));
        assert!(admission.check(admission.ticket()).is_err());
    }
}
