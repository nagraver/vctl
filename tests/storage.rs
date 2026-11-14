use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use whale::{
    model::{Rule, State},
    store::Store,
};

#[test]
fn read_only_does_not_create_profile() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("missing");
    assert_eq!(Store::new(&home).unwrap().read().unwrap().selected, "auto");
    assert!(!home.exists());
}

#[test]
fn preserves_legacy_extensions_and_insertion_order() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), br#"{"version":1,"subscriptions":{"z":{"nodes":[]},"a":{"nodes":[]}},"ui":{"language":"ru"},"future":{"flag":true}}"#).unwrap();
    let store = Store::new(dir.path()).unwrap();
    store
        .update(|s| {
            s.selected = "auto".into();
            Ok(())
        })
        .unwrap();
    let state = store.read().unwrap();
    assert_eq!(
        state
            .subscriptions
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["z", "a"]
    );
    assert_eq!(state.extra["ui"]["language"], "ru");
    assert_eq!(state.extra["future"]["flag"], true);
    let meta = std::fs::metadata(dir.path().join("state.json")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
}

#[test]
fn rejects_corrupt_and_future_profile_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path()).unwrap();
    for data in ["{", "{\"version\":99}", "{\"version\":1} trailing"] {
        std::fs::write(dir.path().join("state.json"), data).unwrap();
        assert!(store.update(|_| Ok(())).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("state.json")).unwrap(),
            data
        );
    }
}

#[test]
fn rejects_symlink_state_and_lock_without_changing_target() {
    for name in ["state.json", "state.lock"] {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"important").unwrap();
        symlink(&victim, dir.path().join(name)).unwrap();
        let store = Store::new(dir.path()).unwrap();
        assert!(store.update(|_| Ok(())).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"important");
    }
}

#[test]
fn failed_transaction_keeps_previous_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path()).unwrap();
    store.write(&State::default()).unwrap();
    assert!(
        store
            .update(|s| {
                s.selected = "changed".into();
                anyhow::bail!("validation failed")
            })
            .is_err()
    );
    assert_eq!(store.read().unwrap().selected, "auto");
}

#[test]
fn concurrent_updates_do_not_lose_rules() {
    // Race the first lock-file creation as well as subsequent state replacement.
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path()).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let threads = (0..12)
            .map(|i| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.update(|s| {
                        s.rules.push(Rule {
                            kind: "domain".into(),
                            value: format!("{i}.example.org"),
                            action: "direct".into(),
                        });
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        // Join every writer before reporting errors or dropping its directory.
        let results = threads
            .into_iter()
            .map(|thread| thread.join())
            .collect::<Vec<_>>();
        for result in results {
            result.unwrap().unwrap();
        }
        let rules = store.read().unwrap().rules;
        assert_eq!(rules.len(), 12);
        assert_eq!(
            rules
                .iter()
                .map(|rule| &rule.value)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            12
        );
    }
}

#[test]
fn refuses_oversized_profile_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let f = std::fs::File::create(dir.path().join("state.json")).unwrap();
    f.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(Store::new(dir.path()).unwrap().read().is_err());
}

#[test]
fn rejects_parent_directory_swap_after_profile_identity_is_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let other = dir.path().join("other");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&other).unwrap();
    let store = Store::new(&home).unwrap();
    std::fs::rename(&home, dir.path().join("old-home")).unwrap();
    symlink(&other, &home).unwrap();
    assert!(store.write(&State::default()).is_err());
    assert!(!other.join("state.json").exists());
}

#[test]
fn rejects_hardlinked_profile_and_fifo_lock_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"{}").unwrap();
    std::fs::hard_link(&victim, dir.path().join("state.json")).unwrap();
    let store = Store::new(dir.path()).unwrap();
    assert!(store.read().is_err());
    std::fs::remove_file(dir.path().join("state.json")).unwrap();
    let lock = std::ffi::CString::new(dir.path().join("state.lock").as_os_str().as_encoded_bytes())
        .unwrap();
    assert_eq!(unsafe { libc::mkfifo(lock.as_ptr(), 0o600) }, 0);
    assert!(store.update(|_| Ok(())).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"{}");
}
