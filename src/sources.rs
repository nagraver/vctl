//! Source I/O runs as the profile owner, before taking the profile transaction lock.
use crate::{
    config,
    model::{self, Asset, Preset, Rule, State, Subscription},
    store::{self, Store},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const SOURCE_LIMIT: u64 = 2_000_000;
const ASSET_LIMIT: u64 = 64_000_000;
const LAN: [&str; 8] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

fn require_user() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Source operations must run as the profile owner, not root"
    );
    Ok(())
}
fn interval_valid(interval: u64) -> Result<()> {
    ensure!(interval >= 60, "Minimum interval is 60 seconds");
    Ok(())
}
fn source_url(raw: &str) -> Result<url::Url> {
    ensure!(
        raw.len() <= 16_384 && !raw.chars().any(char::is_control),
        "Invalid source URL"
    );
    let url = url::Url::parse(raw).map_err(|_| anyhow::anyhow!("Source URL must use HTTPS"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Source URL must use HTTPS without userinfo or fragments"
    );
    Ok(url)
}
fn limited_read(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut body)
        .map_err(|_| anyhow::anyhow!("Source could not be read completely; cache preserved"))?;
    ensure!(
        !body.is_empty() && body.len() as u64 <= limit,
        "Source is empty or exceeds its size limit; cache preserved"
    );
    Ok(body)
}
fn download(raw: &str, limit: u64) -> Result<(Vec<u8>, HeaderMap)> {
    require_user()?;
    let url = source_url(raw)?;
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(format!("whale/{}", crate::VERSION))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 10 && source_url(attempt.url().as_str()).is_ok() {
                attempt.follow()
            } else {
                attempt.error("Source redirect refused")
            }
        }))
        .build()
        .map_err(|_| anyhow::anyhow!("Could not initialize source download"))?;
    let response = client
        .get(url)
        .send()
        .map_err(|_| anyhow::anyhow!("Download failed; cache preserved"))?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Download returned HTTP {}; cache preserved",
        response.status().as_u16()
    );
    ensure!(
        response.content_length().is_none_or(|size| size <= limit),
        "Source exceeds its size limit; cache preserved"
    );
    let headers = response.headers().clone();
    Ok((limited_read(response, limit)?, headers))
}
fn title(header: &str, address: &str) -> String {
    let value = if header
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("base64:"))
    {
        let encoded: String = header[7..].chars().filter(|c| !c.is_whitespace()).collect();
        [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ]
        .iter()
        .find_map(|engine| engine.decode(&encoded).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
    } else {
        header.to_owned()
    };
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    if cleaned.is_empty() {
        source_url(address)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| "Subscription".into())
    } else {
        cleaned
    }
}
pub fn fetch_subscription(address: &str, interval: u64) -> Result<Subscription> {
    require_user()?;
    interval_valid(interval)?;
    let (body, headers) = download(address, SOURCE_LIMIT)?;
    let (nodes, skipped) = crate::profiles::parse_subscription(&body)?;
    Ok(Subscription {
        url: address.into(),
        interval,
        updated: model::now(),
        title: title(
            headers
                .get("profile-title")
                .and_then(|header| header.to_str().ok())
                .unwrap_or(""),
            address,
        ),
        nodes,
        skipped,
        ..Default::default()
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresetDocument {
    version: u32,
    rules: Vec<PresetRule>,
    #[serde(default, rename = "description")]
    _description: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresetRule {
    kind: String,
    value: String,
    action: String,
}

pub fn load_preset(source: &str, interval: u64) -> Result<Preset> {
    require_user()?;
    interval_valid(interval)?;
    let mut preset = Preset {
        source: source.into(),
        interval,
        updated: model::now(),
        ..Default::default()
    };
    if source.starts_with("builtin:") {
        preset.rules = match source {
            "builtin:lan" => LAN
                .iter()
                .map(|value| Rule {
                    kind: "cidr".into(),
                    value: (*value).into(),
                    action: "direct".into(),
                })
                .collect(),
            "builtin:ads" => vec![Rule {
                kind: "geosite".into(),
                value: "category-ads-all".into(),
                action: "block".into(),
            }],
            _ => bail!("Unknown built-in preset"),
        };
        return Ok(preset);
    }
    let body = if source.contains("://") {
        download(source, SOURCE_LIMIT)?.0
    } else {
        let path = store::canonical(Path::new(source))
            .map_err(|_| anyhow::anyhow!("Cannot open preset source"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| anyhow::anyhow!("Cannot open preset source"))?;
        ensure!(
            file.metadata()?.is_file(),
            "Preset source must be a regular file"
        );
        preset.source = path.to_string_lossy().into_owned();
        limited_read(file, SOURCE_LIMIT)?
    };
    let document: PresetDocument = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("Preset requires version 1 and valid routing rules"))?;
    ensure!(
        document.version == 1 && !document.rules.is_empty() && document.rules.len() <= 5000,
        "Preset requires version 1 and 1..5000 rules"
    );
    for rule in document.rules {
        preset.rules.push(
            config::make_rule(&rule.kind, &rule.value, &rule.action)
                .map_err(|_| anyhow::anyhow!("Preset contains an invalid routing rule"))?,
        );
    }
    Ok(preset)
}

fn varint(body: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *body.get(*offset).context("Invalid geodata protobuf")?;
        *offset += 1;
        ensure!(shift < 63 || byte <= 1, "Invalid geodata protobuf");
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    bail!("Invalid geodata protobuf")
}
fn messages(body: &[u8], wanted: u64) -> Result<Vec<&[u8]>> {
    let mut found = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let tag = varint(body, &mut offset)?;
        ensure!(tag >> 3 != 0, "Invalid geodata protobuf");
        let length = match tag & 7 {
            0 => {
                varint(body, &mut offset)?;
                continue;
            }
            1 => 8,
            2 => usize::try_from(varint(body, &mut offset)?).context("Invalid geodata protobuf")?,
            5 => 4,
            _ => bail!("Invalid geodata protobuf"),
        };
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= body.len())
            .context("Invalid geodata protobuf")?;
        if tag & 7 == 2 && tag >> 3 == wanted {
            ensure!(found.len() < 100_000, "Too many geodata entries");
            found.push(&body[offset..end]);
        }
        offset = end;
    }
    Ok(found)
}
fn first_category(body: &[u8]) -> Result<String> {
    for entry in messages(body, 1)? {
        if let Some(value) = messages(entry, 1)?.into_iter().next() {
            let category = std::str::from_utf8(value)
                .map_err(|_| anyhow::anyhow!("Invalid geodata category"))?
                .to_ascii_lowercase();
            ensure!(
                !category.is_empty()
                    && category.len() <= 120
                    && category
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"!@_-".contains(&byte)),
                "Invalid geodata category"
            );
            return Ok(category);
        }
    }
    bail!("Geodata contains no categories")
}
fn asset_directory(home: &Path) -> Result<PathBuf> {
    let home = store::canonical(home)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&home)
        .context("Cannot create profile directory")?;
    let profile = store::open_directory(&home)?;
    let owner = unsafe { libc::geteuid() };
    ensure!(
        profile.metadata()?.uid() == owner,
        "Profile belongs to another user"
    );
    let name = c"geodata";
    if unsafe { libc::mkdirat(profile.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
    {
        bail!("Cannot create geodata directory");
    }
    let fd = unsafe {
        libc::openat(
            profile.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "Cannot safely open geodata directory");
    let directory = unsafe { File::from_raw_fd(fd) };
    ensure!(
        directory.metadata()?.uid() == owner && directory.metadata()?.mode() & 0o077 == 0,
        "Geodata directory must be private and owned by the profile owner"
    );
    Ok(home.join("geodata"))
}
fn validate_asset_with_engine(
    directory: &Path,
    kind: &str,
    digest: &str,
    category: &str,
    core: Option<&Path>,
) -> Result<()> {
    let core = crate::service::core_path(core)
        .context("Xray is required to validate downloaded geodata")?;
    let temp = tempfile::Builder::new()
        .prefix("whale-geodata-check-")
        .tempdir_in("/private/tmp")?;
    let mut rule = json!({"type":"field","outboundTag":"direct"});
    rule[if kind == "geoip" { "ip" } else { "domain" }] =
        json!([format!("ext:{digest}.dat:{category}")]);
    let config =
        json!({"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[rule]}});
    let path = temp.path().join("config.json");
    store::atomic_write(&path, &serde_json::to_vec(&config)?, 0o600)?;
    let output = crate::runtime::command_output(
        Command::new(core)
            .args(["run", "-test", "-c"])
            .arg(path)
            .env("XRAY_LOCATION_ASSET", directory),
        Duration::from_secs(20),
        65536,
    )?;
    ensure!(
        output.success,
        "Geodata was rejected by Xray; previous database preserved"
    );
    Ok(())
}
pub fn fetch_asset(home: &Path, kind: &str, address: &str, interval: u64) -> Result<Asset> {
    fetch_asset_with_core(home, kind, address, interval, None)
}
pub fn fetch_asset_with_core(
    home: &Path,
    kind: &str,
    address: &str,
    interval: u64,
    core: Option<&Path>,
) -> Result<Asset> {
    require_user()?;
    interval_valid(interval)?;
    ensure!(matches!(kind, "geoip" | "geosite"), "Unknown geodata kind");
    let (body, _) = download(address, ASSET_LIMIT)?;
    let category = first_category(&body)?;
    let digest = hex::encode(Sha256::digest(&body));
    let directory = asset_directory(home)?;
    store::atomic_write(&directory.join(format!("{digest}.dat")), &body, 0o600)?;
    validate_asset_with_engine(&directory, kind, &digest, &category, core)?;
    Ok(Asset {
        url: address.into(),
        sha256: digest,
        updated: model::now(),
        interval,
        ..Default::default()
    })
}

enum Change {
    Subscription(String, Subscription, Subscription),
    Preset(String, Preset, Preset),
    Asset(String, Asset, Asset),
}
impl Change {
    fn apply(&self, state: &mut State) -> Result<bool> {
        match self {
            Self::Subscription(name, old, new) => {
                let Some(current) = state.subscriptions.get(name) else {
                    return Ok(false);
                };
                if current.url != old.url
                    || current.interval != old.interval
                    || current.updated != old.updated
                    || current.nodes != old.nodes
                {
                    return Ok(false);
                }
                let mut new = new.clone();
                new.extra = current.extra.clone();
                state.subscriptions.insert(name.clone(), new);
            }
            Self::Preset(name, old, new) => {
                let Some(current) = state.presets.get(name) else {
                    return Ok(false);
                };
                if current.source != old.source
                    || current.interval != old.interval
                    || current.updated != old.updated
                    || current.rules != old.rules
                {
                    return Ok(false);
                }
                let mut new = new.clone();
                new.extra = current.extra.clone();
                new.enabled = current.enabled;
                state.presets.insert(name.clone(), new);
            }
            Self::Asset(name, old, new) => {
                let Some(current) = state.geodata.get(name) else {
                    return Ok(false);
                };
                if current.url != old.url
                    || current.interval != old.interval
                    || current.updated != old.updated
                    || current.sha256 != old.sha256
                {
                    return Ok(false);
                }
                let mut new = new.clone();
                new.extra = current.extra.clone();
                state.geodata.insert(name.clone(), new);
            }
        }
        ensure!(
            state.selected == "auto" || state.nodes().iter().any(|node| node.id == state.selected),
            "The selected server disappeared; previous subscription cache preserved"
        );
        Ok(true)
    }
}
fn apply_refresh(store: &Store, change: Change, core: Option<&Path>) -> Result<()> {
    apply_refresh_with(store, change, |candidate| {
        config::validate_state(candidate)?;
        if let Some(core) = core {
            crate::runtime::validate_config(core, &store.home, candidate, "proxy", 2080)?;
        }
        Ok(())
    })
}
fn apply_refresh_with(
    store: &Store,
    change: Change,
    mut validate: impl FnMut(&State) -> Result<()>,
) -> Result<()> {
    for _ in 0..3 {
        let before = store.read()?;
        let revision = serde_json::to_vec(&before)?;
        let mut candidate = before.clone();
        if !change.apply(&mut candidate)? {
            return Ok(());
        }
        validate(&candidate)?;
        let mut conflict = false;
        let result = store.update(|current| {
            if serde_json::to_vec(current)? != revision {
                conflict = true;
                bail!("Profile changed while validating source update");
            }
            *current = candidate;
            Ok(())
        });
        if !conflict {
            return result;
        }
    }
    bail!("Profile kept changing; source update will be retried later")
}
fn refresh_using(
    store: &Store,
    mut subscription: impl FnMut(&str, u64) -> Result<Subscription>,
    mut preset: impl FnMut(&str, u64) -> Result<Preset>,
    mut asset: impl FnMut(&Path, &str, &str, u64) -> Result<Asset>,
    core: Option<&Path>,
) -> Result<()> {
    let state = store.read()?;
    let now = model::now();
    let mut failures = 0;
    for (name, old) in &state.subscriptions {
        if now - old.updated >= old.interval as f64
            && subscription(&old.url, old.interval)
                .and_then(|new| {
                    apply_refresh(
                        store,
                        Change::Subscription(name.clone(), old.clone(), new),
                        core,
                    )
                })
                .is_err()
        {
            failures += 1;
        }
    }
    for (name, old) in &state.presets {
        if old.enabled
            && old.source.starts_with("https://")
            && now - old.updated >= old.interval as f64
            && preset(&old.source, old.interval)
                .and_then(|new| {
                    apply_refresh(store, Change::Preset(name.clone(), old.clone(), new), core)
                })
                .is_err()
        {
            failures += 1;
        }
    }
    for (name, old) in &state.geodata {
        if now - old.updated >= old.interval as f64
            && asset(&store.home, name, &old.url, old.interval)
                .and_then(|new| {
                    apply_refresh(store, Change::Asset(name.clone(), old.clone(), new), core)
                })
                .is_err()
        {
            failures += 1;
        }
    }
    ensure!(
        failures == 0,
        "Some sources could not be refreshed; their previous cached data was preserved"
    );
    Ok(())
}
pub fn refresh(store: &Store) -> Result<()> {
    require_user()?;
    let core = crate::service::core_path(None)?;
    refresh_using(
        store,
        fetch_subscription,
        load_preset,
        fetch_asset,
        Some(&core),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn domain_builtin_and_local_presets_keep_order_and_validate_rules() {
        let lan = load_preset("builtin:lan", 60).unwrap();
        assert_eq!(lan.rules[0].value, "10.0.0.0/8");
        assert_eq!(lan.rules.len(), 8);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rules.json");
        fs::write(
            &file,
            r#"{"version":1,"rules":[{"kind":"suffix","value":"Example.ORG","action":"direct"}]}"#,
        )
        .unwrap();
        assert_eq!(
            load_preset(file.to_str().unwrap(), 60).unwrap().rules[0].value,
            "example.org"
        );
        fs::write(&file, r#"{"version":1,"rules":[],"extra":true}"#).unwrap();
        assert!(load_preset(file.to_str().unwrap(), 60).is_err());
    }

    #[test]
    fn domain_source_errors_do_not_include_secret_urls() {
        let error = fetch_subscription("http://example.org/secret-token", 60)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret-token"));
        assert!(load_preset("builtin:lan", 59).is_err());
        assert!(
            fetch_asset(
                Path::new("/unused"),
                "unexpected",
                "https://example.org",
                60
            )
            .is_err()
        );
    }

    #[test]
    fn titles_decode_base64_and_strip_terminal_controls() {
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode("  Мои серверы\u{1b}  ");
        assert_eq!(
            title(&format!("base64:{encoded}"), "https://example.org/secret"),
            "Мои серверы"
        );
        assert_eq!(title("", "https://example.org/secret"), "example.org");
    }

    #[test]
    fn source_reads_are_bounded_and_geodata_must_be_protobuf() {
        assert!(limited_read(&b"12345"[..], 4).is_err());
        assert!(limited_read(&b""[..], 4).is_err());
        assert!(first_category(b"<html>error</html>").is_err());
        assert_eq!(
            first_category(b"\x0a\x09\x0a\x07PRIVATE").unwrap(),
            "private"
        );
        assert!(first_category(b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").is_err());
    }

    #[test]
    fn local_fifo_and_symlink_asset_directory_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(load_preset(fifo.to_str().unwrap(), 60).is_err());
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("geodata")).unwrap();
        assert!(asset_directory(directory.path()).is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    fn test_subscription(address: &str) -> Subscription {
        let node =
            crate::profiles::parse_uri("trojan://test-secret@127.0.0.1:443?security=tls#Old")
                .unwrap();
        Subscription {
            url: address.into(),
            interval: 60,
            nodes: vec![node],
            ..Default::default()
        }
    }

    #[test]
    fn failed_refresh_does_not_block_later_source_or_overwrite_unrelated_edits() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path()).unwrap();
        let mut state = State::default();
        state.subscriptions.insert(
            "broken".into(),
            test_subscription("https://broken.invalid/sub"),
        );
        state
            .subscriptions
            .insert("good".into(), test_subscription("https://good.invalid/sub"));
        store.write(&state).unwrap();
        let result = refresh_using(
            &store,
            |address, interval| {
                if address.contains("broken") {
                    bail!("Expected source failure");
                }
                store
                    .update(|state| {
                        state.default_route = "direct".into();
                        Ok(())
                    })
                    .unwrap();
                let mut new = test_subscription(address);
                new.interval = interval;
                new.updated = model::now();
                new.nodes[0].name = "Updated".into();
                Ok(new)
            },
            |_, _| unreachable!(),
            |_, _, _, _| unreachable!(),
            None,
        );
        assert!(result.is_err());
        let result = store.read().unwrap();
        assert_eq!(result.subscriptions["broken"].nodes[0].name, "Old");
        assert_eq!(result.subscriptions["good"].nodes[0].name, "Updated");
        assert_eq!(result.default_route, "direct");
    }

    #[test]
    fn preset_refresh_preserves_concurrent_disable_and_unknown_fields() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path()).unwrap();
        let preset = Preset {
            source: "https://example.org/preset".into(),
            interval: 60,
            rules: vec![Rule {
                kind: "suffix".into(),
                value: "old.example".into(),
                action: "direct".into(),
            }],
            ..Default::default()
        };
        let mut state = State::default();
        state.presets.insert("Rules".into(), preset.clone());
        store.write(&state).unwrap();
        refresh_using(
            &store,
            |_, _| unreachable!(),
            |_, _| {
                store
                    .update(|state| {
                        let current = state.presets.get_mut("Rules").unwrap();
                        current.enabled = false;
                        current.extra.insert("future".into(), json!(true));
                        Ok(())
                    })
                    .unwrap();
                let mut new = preset.clone();
                new.updated = model::now();
                new.rules[0].value = "new.example".into();
                Ok(new)
            },
            |_, _, _, _| unreachable!(),
            None,
        )
        .unwrap();
        let state = store.read().unwrap();
        let current = &state.presets["Rules"];
        assert!(!current.enabled);
        assert_eq!(current.extra["future"], true);
        assert_eq!(current.rules[0].value, "new.example");
    }

    #[test]
    fn changed_source_is_not_replaced_by_an_inflight_refresh() {
        let mut state = State::default();
        let old = test_subscription("https://old.invalid/sub");
        state.subscriptions.insert("Main".into(), old.clone());
        let new = test_subscription("https://old.invalid/sub");
        state.subscriptions.get_mut("Main").unwrap().url = "https://new.invalid/sub".into();
        assert!(
            !Change::Subscription("Main".into(), old, new)
                .apply(&mut state)
                .unwrap()
        );
        assert_eq!(state.subscriptions["Main"].url, "https://new.invalid/sub");
    }

    #[test]
    fn engine_rejects_invalid_geodata_even_when_profile_has_no_geo_rules() {
        let core = Path::new(env!("CARGO_MANIFEST_DIR")).join(".tools/xray");
        if !core.is_file() {
            eprintln!("Bundled Xray unavailable; checked in integration instead");
            return;
        }
        let directory = tempfile::Builder::new()
            .prefix("whale-geodata-test-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let body = b"<html>not a geodata database</html>";
        let digest = hex::encode(Sha256::digest(body));
        fs::write(directory.path().join(format!("{digest}.dat")), body).unwrap();
        assert!(
            validate_asset_with_engine(directory.path(), "geoip", &digest, "private", Some(&core))
                .is_err()
        );
    }

    #[test]
    fn refresh_preserves_cache_when_explicit_server_disappears() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path()).unwrap();
        let old = test_subscription("https://example.org/sub");
        let mut state = State {
            selected: old.nodes[0].id.clone(),
            ..Default::default()
        };
        state.subscriptions.insert("Main".into(), old.clone());
        store.write(&state).unwrap();
        let mut new = old.clone();
        new.nodes[0] = crate::profiles::parse_uri(
            "trojan://test-secret@127.0.0.1:444?security=tls#Replacement",
        )
        .unwrap();
        new.updated = model::now();
        assert!(
            apply_refresh(&store, Change::Subscription("Main".into(), old, new), None).is_err()
        );
        assert_eq!(store.read().unwrap(), state);
    }

    #[test]
    fn refresh_revalidates_combined_state_after_a_concurrent_edit() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path()).unwrap();
        let old = test_subscription("https://example.org/sub");
        let mut state = State::default();
        state.subscriptions.insert("Main".into(), old.clone());
        store.write(&state).unwrap();
        let mut new = old.clone();
        new.nodes[0].name = "Updated".into();
        new.updated = model::now();
        let mut validations = 0;
        let result = apply_refresh_with(
            &store,
            Change::Subscription("Main".into(), old.clone(), new),
            |candidate| {
                validations += 1;
                if validations == 1 {
                    store
                        .update(|current| {
                            current.default_route = "direct".into();
                            Ok(())
                        })
                        .unwrap();
                }
                ensure!(
                    candidate.default_route != "direct",
                    "New combination rejected by validator"
                );
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(validations, 2);
        let current = store.read().unwrap();
        assert_eq!(current.default_route, "direct");
        assert_eq!(current.subscriptions["Main"], old);
    }

    #[test]
    fn refresh_revalidates_and_preserves_concurrent_subscription_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path()).unwrap();
        let old = test_subscription("https://example.org/sub");
        let mut state = State::default();
        state.subscriptions.insert("Main".into(), old.clone());
        state
            .subscriptions
            .insert("Other".into(), test_subscription("https://other.org/sub"));
        store.write(&state).unwrap();
        let mut new = old.clone();
        new.updated = model::now();
        let mut validations = 0;
        apply_refresh_with(
            &store,
            Change::Subscription("Main".into(), old, new),
            |_| {
                validations += 1;
                if validations == 1 {
                    store
                        .update(|current| {
                            current.subscriptions.move_index(0, 1);
                            Ok(())
                        })
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(validations, 2);
        assert_eq!(
            store.read().unwrap().subscriptions.keys().next().unwrap(),
            "Other"
        );
    }
}
