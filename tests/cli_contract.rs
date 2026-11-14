use std::process::Command;

#[test]
fn public_status_is_read_only_and_only_supported_commands_are_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("missing-profile");
    let status = Command::new(env!("CARGO_BIN_EXE_whale"))
        .arg("--home")
        .arg(&home)
        .arg("status")
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("VPN: off"));
    assert!(!home.exists());
    for command in ["sub", "completion", "tun", "start"] {
        let output = Command::new(env!("CARGO_BIN_EXE_whale"))
            .arg("--home")
            .arg(&home)
            .arg(command)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    assert!(!home.exists());
}

#[test]
fn helper_snapshot_redacts_populated_profile_and_deduplicates_nodes() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("state.json"),
        include_bytes!("fixtures/native-state.json"),
    )
    .unwrap();
    let snapshot = Command::new(env!("CARGO_BIN_EXE_whale-helper"))
        .arg("--home")
        .arg(directory.path())
        .arg("snapshot")
        .output()
        .unwrap();
    assert!(snapshot.status.success());
    let text = String::from_utf8(snapshot.stdout).unwrap();
    for secret in [
        "fixture-private",
        "subscription-private-token",
        "password",
        "outbound",
    ] {
        assert!(!text.contains(secret), "secret leaked into snapshot");
    }
    let data: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(data["protocol"], 2);
    assert_eq!(data["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(data["subscriptions"][0]["count"], 1);
    assert_eq!(data["geodata"]["geoip"]["interval"], 172800);
    assert_eq!(data["geodata"]["geoip"]["redacted"], true);
}
