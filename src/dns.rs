//! System DNS is changed only after a durable ownership journal is written.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const TUN_DNS: &str = "198.19.255.53";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Journal {
    pub previous: BTreeMap<String, Vec<String>>,
    pub applied: Vec<String>,
}

pub trait System {
    fn active_services(&mut self) -> Result<Vec<String>>;
    fn get(&mut self, name: &str) -> Result<Vec<String>>;
    fn set(&mut self, name: &str, values: &[String]) -> Result<()>;
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

pub trait JournalStore {
    fn load(&mut self) -> Result<Option<Journal>>;
    fn save(&mut self, journal: &Journal) -> Result<()>;
    fn clear(&mut self) -> Result<()>;
}

pub fn acquire(system: &mut impl System, store: &mut impl JournalStore) -> Result<()> {
    restore(system, store)?;
    let mut journal = Journal {
        applied: vec![TUN_DNS.into()],
        ..Default::default()
    };
    let services = system.active_services()?;
    if services.is_empty() {
        bail!("No active network service is available")
    }
    for name in services {
        let previous = match system.get(&name) {
            Ok(values) => values,
            Err(error) => {
                let _ = restore(system, store);
                return Err(error);
            }
        };
        // An unjournaled old tunnel DNS must not become the restoration target.
        if previous == journal.applied {
            let _ = restore(system, store);
            bail!(
                "An earlier VPN still owns system DNS; disconnect or recover it before connecting"
            )
        }
        journal.previous.insert(name.clone(), previous);
        // Persist before every mutation. A crash between save and set is safe:
        // recovery restores only a service whose current value equals applied.
        if let Err(error) = store.save(&journal) {
            let _ = restore(system, store);
            return Err(error);
        }
        if let Err(error) = system.set(&name, &journal.applied) {
            let _ = restore(system, store);
            return Err(error);
        }
    }
    let _ = system.flush();
    Ok(())
}
pub fn restore(system: &mut impl System, store: &mut impl JournalStore) -> Result<()> {
    let Some(mut journal) = store.load()? else {
        return Ok(());
    };
    if journal.applied != [TUN_DNS] || journal.previous.len() > 128 {
        bail!("Invalid DNS recovery journal")
    }
    let names: Vec<_> = journal.previous.keys().cloned().collect();
    let mut incomplete = false;
    for name in names {
        let previous = &journal.previous[&name];
        if previous
            .iter()
            .any(|address| address.parse::<IpAddr>().is_err())
        {
            incomplete = true;
            continue;
        }
        match system.get(&name) {
            Ok(current) => {
                if current == journal.applied && system.set(&name, previous).is_err() {
                    incomplete = true;
                    continue;
                }
                // A different current value belongs to another actor and is left alone.
                journal.previous.remove(&name);
                if journal.previous.is_empty() {
                    store.clear()?;
                } else {
                    store.save(&journal)?;
                }
            }
            Err(_) => incomplete = true,
        }
    }
    if journal.previous.is_empty() {
        store.clear()?;
    }
    let _ = system.flush();
    if incomplete {
        bail!("DNS restoration is incomplete; recovery data was retained")
    }
    Ok(())
}

/// Callers supply a verified root-owned runtime directory, never a profile path.
pub struct FileJournal {
    path: PathBuf,
}
impl FileJournal {
    pub fn new(runtime: &Path) -> Self {
        Self {
            path: runtime.join("dns-restore.json"),
        }
    }
}
impl JournalStore for FileJournal {
    fn load(&mut self) -> Result<Option<Journal>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => bail!("Cannot safely open DNS recovery journal"),
        };
        if !file.metadata()?.is_file() {
            bail!("Invalid DNS recovery journal")
        }
        let mut body = Vec::new();
        file.take(65537).read_to_end(&mut body)?;
        if body.len() > 65536 {
            bail!("DNS recovery journal exceeds limit")
        }
        Ok(Some(
            serde_json::from_slice(&body).context("Invalid DNS recovery journal")?,
        ))
    }
    fn save(&mut self, journal: &Journal) -> Result<()> {
        crate::store::atomic_write(&self.path, &serde_json::to_vec(journal)?, 0o600)
    }
    fn clear(&mut self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => fs::File::open(self.path.parent().context("Missing journal directory")?)?
                .sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

pub struct MacSystem;
impl MacSystem {
    fn networksetup(arguments: &[&str]) -> Result<String> {
        let mut command = Command::new("/usr/sbin/networksetup");
        command.args(arguments).env("LC_ALL", "C");
        let output = crate::runtime::command_output(&mut command, Duration::from_secs(15), 65536)?;
        if !output.success {
            bail!("macOS DNS operation failed")
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}
impl System for MacSystem {
    fn active_services(&mut self) -> Result<Vec<String>> {
        let output = Self::networksetup(&["-listallnetworkservices"])?;
        let mut names = Vec::new();
        for name in output
            .lines()
            .skip(1)
            .filter(|line| !line.is_empty() && !line.starts_with('*'))
        {
            let info = Self::networksetup(&["-getinfo", name])?;
            let active = info.lines().any(|line| {
                ["IP address:", "IPv6 IP address:"].iter().any(|prefix| {
                    line.strip_prefix(prefix).is_some_and(|address| {
                        address
                            .trim()
                            .parse::<IpAddr>()
                            .is_ok_and(|ip| !ip.is_unspecified())
                    })
                })
            });
            if active {
                names.push(name.into());
            }
        }
        if names.len() > 128 {
            bail!("Too many network services")
        }
        Ok(names)
    }
    fn get(&mut self, name: &str) -> Result<Vec<String>> {
        let output = Self::networksetup(&["-getdnsservers", name])?;
        if output.starts_with("There aren't any DNS Servers") {
            return Ok(Vec::new());
        }
        let values: Vec<String> = output.lines().map(|line| line.trim().to_owned()).collect();
        if values.is_empty() || values.iter().any(|value| value.parse::<IpAddr>().is_err()) {
            bail!("Invalid macOS DNS response")
        }
        Ok(values)
    }
    fn set(&mut self, name: &str, values: &[String]) -> Result<()> {
        let mut arguments = vec!["-setdnsservers", name];
        if values.is_empty() {
            arguments.push("Empty");
        } else {
            arguments.extend(values.iter().map(String::as_str));
        }
        Self::networksetup(&arguments).map(|_| ())
    }
    fn flush(&mut self) -> Result<()> {
        crate::runtime::command_output(
            Command::new("/usr/bin/dscacheutil").arg("-flushcache"),
            Duration::from_secs(5),
            4096,
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Memory {
        journal: Option<Journal>,
        fail_save: bool,
        events: Rc<RefCell<Vec<String>>>,
    }
    impl JournalStore for Memory {
        fn load(&mut self) -> Result<Option<Journal>> {
            Ok(self.journal.clone())
        }
        fn save(&mut self, j: &Journal) -> Result<()> {
            if self.fail_save {
                bail!("disk unavailable")
            }
            self.events.borrow_mut().push("journal".into());
            self.journal = Some(j.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<()> {
            self.journal = None;
            Ok(())
        }
    }
    #[derive(Default)]
    struct FakeSystem {
        values: BTreeMap<String, Vec<String>>,
        fail: Option<String>,
        events: Rc<RefCell<Vec<String>>>,
    }
    impl System for FakeSystem {
        fn active_services(&mut self) -> Result<Vec<String>> {
            Ok(self.values.keys().cloned().collect())
        }
        fn get(&mut self, n: &str) -> Result<Vec<String>> {
            self.values
                .get(n)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("service missing"))
        }
        fn set(&mut self, n: &str, values: &[String]) -> Result<()> {
            self.events.borrow_mut().push(format!("set:{n}"));
            if self.fail.as_deref() == Some(n) {
                bail!("write failed")
            }
            self.values.insert(n.into(), values.to_vec());
            Ok(())
        }
    }
    fn setup() -> (FakeSystem, Memory) {
        let events = Rc::default();
        (
            FakeSystem {
                values: [("Wi-Fi".into(), vec!["9.9.9.9".into()])].into(),
                events: Rc::clone(&events),
                ..Default::default()
            },
            Memory {
                events,
                ..Default::default()
            },
        )
    }
    #[test]
    fn journal_precedes_dns_change_and_round_trip_restores() {
        let (mut system, mut store) = setup();
        acquire(&mut system, &mut store).unwrap();
        assert_eq!(system.values["Wi-Fi"], [TUN_DNS]);
        assert_eq!(&*store.events.borrow(), &["journal", "set:Wi-Fi"]);
        restore(&mut system, &mut store).unwrap();
        assert_eq!(system.values["Wi-Fi"], ["9.9.9.9"]);
        assert!(store.journal.is_none());
    }
    #[test]
    fn failed_journal_never_changes_system() {
        let (mut system, mut store) = setup();
        store.fail_save = true;
        assert!(acquire(&mut system, &mut store).is_err());
        assert_eq!(system.values["Wi-Fi"], ["9.9.9.9"]);
        assert!(store.events.borrow().is_empty());
    }
    #[test]
    fn recovery_preserves_external_dns_changes() {
        let (mut system, mut store) = setup();
        acquire(&mut system, &mut store).unwrap();
        system.values.insert("Wi-Fi".into(), vec!["8.8.8.8".into()]);
        restore(&mut system, &mut store).unwrap();
        assert_eq!(system.values["Wi-Fi"], ["8.8.8.8"]);
        assert!(store.journal.is_none());
    }
    #[test]
    fn failed_restore_keeps_retryable_journal() {
        let (mut system, mut store) = setup();
        acquire(&mut system, &mut store).unwrap();
        system.fail = Some("Wi-Fi".into());
        assert!(restore(&mut system, &mut store).is_err());
        assert!(
            store
                .journal
                .as_ref()
                .unwrap()
                .previous
                .contains_key("Wi-Fi")
        );
        system.fail = None;
        restore(&mut system, &mut store).unwrap();
        assert!(store.journal.is_none());
    }
}
