//! Profile transactions anchored to directory descriptors, never ownership repair.
use crate::model::State;
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const MAX_PROFILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Store {
    pub home: PathBuf,
}

impl Store {
    /// Resolves a profile identity without creating files. Status stays read-only.
    pub fn new(home: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            home: canonical(home.as_ref())?,
        })
    }

    pub fn read(&self) -> Result<State> {
        match open_directory(&self.home) {
            Ok(dir) => read_at(&dir),
            Err(error) if is_not_found(&error) => Ok(State::default()),
            Err(error) => Err(error.context("cannot open profile directory")),
        }
    }

    pub fn write(&self, state: &State) -> Result<()> {
        self.update(|current| {
            *current = state.clone();
            Ok(())
        })
    }

    pub fn update(&self, change: impl FnOnce(&mut State) -> Result<()>) -> Result<()> {
        // Privileged runtime state uses atomic_write in a root-owned directory.
        // Profile editing and source downloads must be performed after dropping UID.
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "profile changes must run as the profile owner, not root"
        );
        fs::create_dir_all(&self.home).context("cannot create profile directory")?;
        let dir = open_directory(&self.home)?;
        let owner = dir.metadata()?.uid();
        ensure!(
            owner == unsafe { libc::geteuid() },
            "profile belongs to another user"
        );
        chmod(&dir, 0o700)?;
        // Darwin's openat(O_CREAT) create-or-open fallback can spuriously return
        // ENOENT when several writers first create a lock. Avoid that kernel path:
        // create exclusively, or open the winner's existing file without O_CREAT.
        // Both operations retain descriptor-relative access and O_NOFOLLOW.
        let lock = match open_at(
            &dir,
            OsStr::new("state.lock"),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(lock) => lock,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                open_at(&dir, OsStr::new("state.lock"), libc::O_RDWR, 0)?
            }
            Err(error) => return Err(error.context("cannot create profile lock")),
        };
        check_regular(&lock, owner)?;
        chmod(&lock, 0o600)?;
        loop {
            // SAFETY: lock owns an open regular-file descriptor for the whole transaction.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        // Dropping lock releases flock on every exit, including validation errors.
        let mut state = read_at(&dir)?;
        change(&mut state)?;
        ensure!(state.version == 1, "unsupported profile version");
        let bytes = serde_json::to_vec_pretty(&state)?;
        ensure!(
            bytes.len() as u64 <= MAX_PROFILE_BYTES,
            "profile exceeds 16 MB"
        );
        write_at(&dir, OsStr::new("state.json"), &bytes, 0o600)
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

fn read_at(dir: &File) -> Result<State> {
    let file = match open_at(dir, OsStr::new("state.json"), libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if is_not_found(&error) => return Ok(State::default()),
        Err(error) => return Err(error.context("cannot safely read state.json")),
    };
    read_snapshot(file, dir.metadata()?.uid())
}

fn read_snapshot(file: File, owner: u32) -> Result<State> {
    let metadata = file.metadata()?;
    // A concurrent atomic replacement unlinks the old inode, but this open
    // descriptor still holds a coherent snapshot. Multiple links remain unsafe.
    ensure!(
        metadata.is_file() && metadata.nlink() <= 1,
        "expected a regular file without hard links"
    );
    ensure!(
        metadata.uid() == owner,
        "file owner does not match its directory"
    );
    ensure!(metadata.len() <= MAX_PROFILE_BYTES, "profile exceeds 16 MB");
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_PROFILE_BYTES,
        "profile exceeds 16 MB"
    );
    // Do not print serde's value-bearing errors: profiles contain credentials.
    let state: State = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid profile JSON or field type"))?;
    ensure!(state.version == 1, "unsupported profile version");
    Ok(state)
}

fn check_regular(file: &File, owner: u32) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "expected a regular file without hard links"
    );
    ensure!(
        metadata.uid() == owner,
        "file owner does not match its directory"
    );
    Ok(())
}

fn chmod(file: &File, mode: u32) -> Result<()> {
    // SAFETY: the descriptor is owned and mode contains permission bits only.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name.as_bytes())?;
    // NONBLOCK prevents hostile FIFOs from hanging before fstat rejects them.
    // SAFETY: both the directory descriptor and NUL-terminated name remain valid.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openat returns a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn open_directory(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "directory path must be absolute");
    let mut dir = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            }
            _ => bail!("directory path must be normalized"),
        }
    }
    Ok(dir)
}

/// Resolve existing ancestors once to a stable absolute profile identity. Later
/// accesses reject symlinks in every component, including after directory swaps.
pub fn canonical(path: &Path) -> Result<PathBuf> {
    let expanded = if path == Path::new("~") || path.starts_with("~/") {
        let home = std::env::var_os("HOME").context("home directory unavailable")?;
        PathBuf::from(home).join(path.strip_prefix("~")?)
    } else {
        path.to_path_buf()
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()?.join(expanded)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    let mut ancestor = normalized.as_path();
    let mut tail = Vec::new();
    loop {
        match fs::canonicalize(ancestor) {
            Ok(mut resolved) => {
                for name in tail.into_iter().rev() {
                    resolved.push(name);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tail.push(
                    ancestor
                        .file_name()
                        .context("invalid profile path")?
                        .to_os_string(),
                );
                ancestor = ancestor.parent().context("invalid profile path")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Durable replacement in an existing directory. Never follows destination
/// symlinks, guesses ownership, or changes ownership of an existing file.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("file has no parent directory")?;
    let dir = open_directory(parent)?;
    ensure!(
        dir.metadata()?.uid() == unsafe { libc::geteuid() },
        "destination directory belongs to another user"
    );
    write_at(
        &dir,
        path.file_name().context("file has no name")?,
        bytes,
        mode,
    )
}

fn write_at(dir: &File, name: &OsStr, bytes: &[u8], mode: u32) -> Result<()> {
    ensure!(mode & !0o777 == 0, "invalid file permissions");
    match open_at(dir, name, libc::O_RDONLY, 0) {
        Ok(existing) => check_regular(&existing, dir.metadata()?.uid())?,
        Err(error) if is_not_found(&error) => {}
        Err(error) => return Err(error.context("unsafe destination file")),
    }
    let mut random = [0_u8; 16];
    // SAFETY: buffer has the given length, well below getentropy's 256-byte limit.
    if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let temporary = CString::new(format!(".pending-{}", hex::encode(random)))?;
    let destination = CString::new(name.as_bytes())?;
    let mut file = open_at(
        dir,
        OsStr::from_bytes(temporary.as_bytes()),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let result = (|| {
        chmod(&file, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // SAFETY: rename occurs between entries in the same held directory.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                dir.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        dir.sync_all()?;
        Ok(())
    })();
    // SAFETY: remove only our exclusive temporary entry; after rename it is absent.
    unsafe {
        libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opened_snapshot_remains_readable_after_atomic_replacement() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let path = directory.path().join("state.json");
        fs::write(&path, br#"{"version":1,"selected":"old"}"#).unwrap();
        let snapshot = File::open(&path).unwrap();
        atomic_write(&path, br#"{"version":1,"selected":"new"}"#, 0o600).unwrap();
        assert_eq!(snapshot.metadata().unwrap().nlink(), 0);
        assert!(check_regular(&snapshot, unsafe { libc::geteuid() }).is_err());
        assert_eq!(
            read_snapshot(snapshot, unsafe { libc::geteuid() })
                .unwrap()
                .selected,
            "old"
        );
        assert_eq!(
            Store::new(directory.path())
                .unwrap()
                .read()
                .unwrap()
                .selected,
            "new"
        );
    }

    #[test]
    fn snapshots_still_reject_hard_links_and_wrong_owner() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let path = directory.path().join("state.json");
        fs::write(&path, br#"{"version":1}"#).unwrap();
        let owner = unsafe { libc::geteuid() };
        assert!(read_snapshot(File::open(&path).unwrap(), owner.wrapping_add(1)).is_err());
        fs::hard_link(&path, directory.path().join("alias")).unwrap();
        assert!(read_snapshot(File::open(path).unwrap(), owner).is_err());
    }
}
