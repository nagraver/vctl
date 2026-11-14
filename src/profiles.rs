//! Strict import boundary and stable identities for the legacy profile format.
use crate::model::Node;
use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use url::Url;

pub const SUBSCRIPTION_LIMIT: usize = 2_000_000;

pub fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

fn percent_decode(value: &str, query: bool) -> Result<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let raw = value.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                ensure!(i + 2 < raw.len(), "invalid URI encoding");
                let hi = (raw[i + 1] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow!("invalid URI encoding"))?;
                let lo = (raw[i + 2] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow!("invalid URI encoding"))?;
                bytes.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'+' if query => {
                bytes.push(b' ');
                i += 1;
            }
            byte => {
                bytes.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("invalid URI encoding"))
}

fn text_ok(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(char::is_control)
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && text_ok(host, 253)
        && (host.parse::<IpAddr>().is_ok()
            || (!host.contains(['/', '\\', ':', '@', '%', '?', '#', ' '])
                && url::Host::parse(host).is_ok()))
}

fn uuid(value: &str) -> Result<String> {
    let compact = value.replace('-', "").to_ascii_lowercase();
    ensure!(
        compact.len() == 32 && compact.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid VLESS UUID"
    );
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &compact[..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..]
    ))
}

/// Python's historical `json.dumps(sort_keys=True)` representation, not compact JSON.
/// Changing whitespace or Unicode escaping here would orphan saved selections.
fn legacy_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| format!("{}: {}", legacy_json(&json!(k)), legacy_json(&object[k])))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(legacy_json)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).expect("string JSON serialization");
            let mut output = String::new();
            for ch in encoded.chars() {
                if ch.is_ascii() {
                    output.push(ch);
                } else {
                    let mut units = [0; 2];
                    for unit in ch.encode_utf16(&mut units) {
                        output.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
            output
        }
        _ => value.to_string(),
    }
}

pub fn parse_uri(raw: &str) -> Result<Node> {
    ensure!(
        raw.len() <= 65_536 && !raw.chars().any(char::is_control),
        "invalid server URI"
    );
    ensure!(
        raw.starts_with("vless://") || raw.starts_with("trojan://"),
        "supported protocols: vless, trojan"
    );
    let uri = Url::parse(raw).map_err(|_| anyhow!("invalid server URI"))?;
    let protocol = uri.scheme();
    let server = uri
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = uri
        .port()
        .filter(|p| *p > 0)
        .ok_or_else(|| anyhow!("missing server, port or credentials"))?;
    ensure!(
        host_ok(server) && !uri.username().is_empty(),
        "missing server, port or credentials"
    );
    ensure!(uri.password().is_none(), "invalid credentials");
    let credential = percent_decode(uri.username(), false)?;
    ensure!(
        !credential.is_empty() && text_ok(&credential, 8192),
        "invalid credentials"
    );
    let allowed = [
        "type",
        "security",
        "encryption",
        "flow",
        "fp",
        "pbk",
        "sid",
        "sni",
        "spx",
        "alpn",
        "allowInsecure",
        "insecure",
        "path",
        "host",
        "serviceName",
        "headerType",
        "fm",
    ];
    let mut query = BTreeMap::new();
    if let Some(raw_query) = uri.query() {
        ensure!(!raw_query.contains(';'), "invalid query");
        for item in raw_query.split('&').filter(|part| !part.is_empty()) {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            let key = percent_decode(key, true)?;
            let value = percent_decode(value, true)?;
            ensure!(
                allowed.contains(&key.as_str()),
                "unsupported connection parameter"
            );
            ensure!(text_ok(&value, 32768), "invalid connection parameter");
            ensure!(
                query.insert(key, value).is_none(),
                "duplicate connection parameter"
            );
        }
    }
    let get = |key: &str, default: &str| {
        query
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    };
    let transport = get("type", "tcp");
    ensure!(
        ["tcp", "raw", "ws", "grpc", "httpupgrade"].contains(&transport.as_str()),
        "unsupported transport"
    );
    ensure!(
        get("encryption", "none") == "none" && get("headerType", "none") == "none",
        "unsupported encryption or TCP header"
    );
    let mut outbound = json!({"type":protocol,"server":server,"server_port":port});
    let flow = get("flow", "");
    if protocol == "vless" {
        outbound["uuid"] = json!(uuid(&credential)?);
        if !flow.is_empty() {
            ensure!(
                flow == "xtls-rprx-vision" && matches!(transport.as_str(), "tcp" | "raw"),
                "unsupported VLESS flow"
            );
            outbound["flow"] = json!(flow);
        }
    } else {
        ensure!(flow.is_empty(), "unsupported Trojan flow");
        outbound["password"] = json!(credential);
    }
    let security = get(
        "security",
        if protocol == "trojan" { "tls" } else { "none" },
    );
    ensure!(
        matches!(security.as_str(), "none" | "tls" | "reality"),
        "unsupported security"
    );
    let insecure = get("allowInsecure", &get("insecure", "0"));
    ensure!(
        matches!(insecure.as_str(), "0" | "false" | ""),
        "insecure TLS is not accepted"
    );
    if security != "none" {
        let mut tls = json!({"enabled":true,"server_name":get("sni", server)});
        let alpn = get("alpn", "");
        if !alpn.is_empty() {
            tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
        if !get("fp", "").is_empty() || security == "reality" {
            tls["utls"] = json!({"enabled":true,"fingerprint":get("fp", "chrome")});
        }
        if security == "reality" {
            ensure!(!get("pbk", "").is_empty(), "Reality key required");
            tls["reality"] =
                json!({"enabled":true,"public_key":get("pbk", ""),"short_id":get("sid", "")});
        }
        outbound["tls"] = tls;
    } else {
        ensure!(flow.is_empty(), "Vision requires TLS/Reality");
    }
    if let Some(mask) = query.get("fm") {
        let mask: Value = serde_json::from_str(mask).map_err(|_| anyhow!("invalid fm JSON"))?;
        validate_mask(&mask)?;
        outbound["finalmask"] = mask;
    }
    if !matches!(transport.as_str(), "tcp" | "raw") {
        let mut settings = json!({"type":transport});
        if transport == "grpc" {
            settings["service_name"] = json!(get("serviceName", ""));
        } else {
            settings["path"] = json!(get("path", "/"));
            let host = get("host", "");
            if !host.is_empty() {
                if transport == "ws" {
                    settings["headers"] = json!({"Host":host});
                } else {
                    settings["host"] = json!(host);
                }
            }
        }
        outbound["transport"] = settings;
    }
    validate_outbound(&outbound)?;
    let id = hex::encode(Sha256::digest(legacy_json(&outbound).as_bytes()))[..16].to_owned();
    let name = percent_decode(uri.fragment().unwrap_or_default(), false)?;
    Ok(Node {
        id,
        name: if name.is_empty() {
            protocol.to_uppercase()
        } else {
            name
        },
        outbound,
    })
}

fn object_keys<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("invalid stored connection settings"))?;
    ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "unsupported stored connection settings"
    );
    Ok(object)
}

fn string<'a>(value: &'a Value, key: &str, empty: bool) -> Result<&'a str> {
    let text = value[key]
        .as_str()
        .ok_or_else(|| anyhow!("invalid stored connection settings"))?;
    ensure!(
        text_ok(text, 8192) && (empty || !text.is_empty()),
        "invalid stored connection settings"
    );
    Ok(text)
}

/// Validate the entire engine-bound schema before a privileged caller compiles it.
pub fn validate_outbound(outbound: &Value) -> Result<()> {
    object_keys(
        outbound,
        &[
            "type",
            "server",
            "server_port",
            "uuid",
            "password",
            "flow",
            "tls",
            "transport",
            "finalmask",
        ],
    )?;
    let protocol = string(outbound, "type", false)?;
    ensure!(
        matches!(protocol, "vless" | "trojan"),
        "unsupported outbound protocol"
    );
    ensure!(
        host_ok(string(outbound, "server", false)?),
        "invalid stored server"
    );
    ensure!(
        outbound["server_port"]
            .as_u64()
            .is_some_and(|p| (1..=65535).contains(&p)),
        "invalid stored server port"
    );
    if protocol == "vless" {
        uuid(string(outbound, "uuid", false)?)?;
        ensure!(
            outbound.get("password").is_none(),
            "invalid stored connection settings"
        );
    } else {
        string(outbound, "password", false)?;
        ensure!(
            outbound.get("uuid").is_none() && outbound.get("flow").is_none(),
            "invalid stored connection settings"
        );
    }
    if let Some(tls) = outbound.get("tls") {
        object_keys(tls, &["enabled", "server_name", "alpn", "utls", "reality"])?;
        ensure!(tls["enabled"] == true, "invalid stored TLS settings");
        let server_name = string(tls, "server_name", true)?;
        ensure!(
            server_name.is_empty() || host_ok(server_name),
            "invalid stored TLS name"
        );
        if let Some(alpn) = tls.get("alpn") {
            let alpn = alpn
                .as_array()
                .ok_or_else(|| anyhow!("invalid ALPN settings"))?;
            ensure!(
                alpn.len() <= 32
                    && alpn
                        .iter()
                        .all(|v| v.as_str().is_some_and(|s| !s.is_empty() && text_ok(s, 255))),
                "invalid ALPN settings"
            );
        }
        if let Some(utls) = tls.get("utls") {
            object_keys(utls, &["enabled", "fingerprint"])?;
            ensure!(utls["enabled"] == true, "invalid fingerprint settings");
            string(utls, "fingerprint", true)?;
        }
        if let Some(reality) = tls.get("reality") {
            object_keys(reality, &["enabled", "public_key", "short_id"])?;
            ensure!(reality["enabled"] == true, "invalid Reality settings");
            string(reality, "public_key", false)?;
            let short_id = string(reality, "short_id", true)?;
            ensure!(
                short_id.len() <= 16
                    && short_id.len().is_multiple_of(2)
                    && short_id.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid Reality short ID"
            );
        }
    }
    if let Some(flow) = outbound.get("flow") {
        ensure!(
            flow == "xtls-rprx-vision"
                && outbound.get("tls").is_some()
                && outbound.get("transport").is_none(),
            "unsupported VLESS flow"
        );
    }
    if let Some(transport) = outbound.get("transport") {
        let kind = string(transport, "type", false)?;
        match kind {
            "ws" => {
                object_keys(transport, &["type", "path", "headers"])?;
                string(transport, "path", true)?;
                if let Some(headers) = transport.get("headers") {
                    object_keys(headers, &["Host"])?;
                    if headers.get("Host").is_some() {
                        string(headers, "Host", false)?;
                    }
                }
            }
            "grpc" => {
                object_keys(transport, &["type", "service_name"])?;
                string(transport, "service_name", true)?;
            }
            "httpupgrade" => {
                object_keys(transport, &["type", "path", "host"])?;
                string(transport, "path", true)?;
                if transport.get("host").is_some() {
                    string(transport, "host", true)?;
                }
            }
            _ => bail!("stored transport unsupported"),
        }
    }
    if let Some(mask) = outbound.get("finalmask") {
        validate_mask(mask)?;
    }
    Ok(())
}

fn validate_mask(mask: &Value) -> Result<()> {
    let invalid = || anyhow!("unsupported or invalid fm fragmentation settings");
    let object = mask.as_object().ok_or_else(invalid)?;
    ensure!(
        object.len() == 1,
        "unsupported or invalid fm fragmentation settings"
    );
    let tcp = mask["tcp"].as_array().ok_or_else(invalid)?;
    ensure!(
        tcp.len() == 1
            && tcp[0].as_object().is_some_and(|m| m.len() == 2)
            && tcp[0]["type"] == "fragment",
        "unsupported or invalid fm fragmentation settings"
    );
    let settings = &tcp[0]["settings"];
    ensure!(
        settings.as_object().is_some_and(|m| m.len() == 3) && settings["packets"] == "tlshello",
        "unsupported or invalid fm fragmentation settings"
    );
    for (key, min, max) in [("length", 1u32, 65535u32), ("delay", 0, 60000)] {
        let value = settings[key].as_str().ok_or_else(invalid)?;
        let parts: Vec<_> = value.split('-').collect();
        ensure!(
            (1..=2).contains(&parts.len())
                && parts.iter().all(|s| !s.is_empty()
                    && s.len() <= 5
                    && s.bytes().all(|b| b.is_ascii_digit())),
            "unsupported or invalid fm fragmentation settings"
        );
        let lo: u32 = parts[0].parse().map_err(|_| invalid())?;
        let hi: u32 = parts[parts.len() - 1].parse().map_err(|_| invalid())?;
        ensure!(
            min <= lo && lo <= hi && hi <= max,
            "unsupported or invalid fm fragmentation settings"
        );
    }
    Ok(())
}

pub fn decode64(value: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(value) = engine.decode(&compact) {
            return Ok(value);
        }
    }
    bail!("expected plain or Base64 URI subscription")
}

fn uri_prefix(value: &str) -> bool {
    value.split_once("://").is_some_and(|(prefix, _)| {
        prefix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && prefix
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    })
}

pub fn parse_subscription(body: &[u8]) -> Result<(Vec<Node>, usize)> {
    ensure!(
        body.len() <= SUBSCRIPTION_LIMIT,
        "subscription exceeds 2 MB"
    );
    let text = std::str::from_utf8(body)
        .map_err(|_| anyhow!("invalid subscription encoding; cache preserved"))?
        .trim_start_matches('\u{feff}')
        .trim();
    let decoded;
    let text = if uri_prefix(text) {
        text
    } else {
        decoded = decode64(text)?;
        std::str::from_utf8(&decoded)
            .map_err(|_| anyhow!("invalid subscription encoding; cache preserved"))?
    };
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    let mut skipped = 0;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if uri_prefix(line) && !line.starts_with("vless://") && !line.starts_with("trojan://") {
            skipped += 1;
            continue;
        }
        let node = parse_uri(line).map_err(|err| {
            anyhow!(
                "subscription entry #{}: {}; cache preserved",
                index + 1,
                err
            )
        })?;
        if seen.insert(node.id.clone()) {
            output.push(node);
        }
    }
    ensure!(
        !output.is_empty(),
        "subscription has no supported VLESS or Trojan servers; cache preserved"
    );
    Ok((output, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../internal/whale/testdata/legacy.json")).unwrap()
    }

    #[test]
    fn domain_legacy_nodes_keep_ids_and_transport_options() {
        let f = fixture();
        for (i, uri) in f["uris"].as_array().unwrap().iter().enumerate() {
            let node = parse_uri(uri.as_str().unwrap()).unwrap();
            assert_eq!(serde_json::to_value(node).unwrap(), f["nodes"][i]);
        }
    }

    #[test]
    fn domain_mixed_subscription_deduplicates_and_counts_unsupported() {
        let body = "ss://unsupported\ntrojan://secret@example.org:443#Working\ntrojan://secret@example.org:443#Duplicate\nvmess://unsupported";
        for data in [body.to_owned(), STANDARD.encode(body)] {
            let (nodes, skipped) = parse_subscription(data.as_bytes()).unwrap();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].name, "Working");
            assert_eq!(skipped, 2);
        }
    }

    #[test]
    fn domain_invalid_parameters_never_expose_credentials() {
        for uri in [
            "vless://secret@example.org:443",
            "trojan://secret@example.org:443?security=tls&allowInsecure=1",
            "trojan://secret@example.org:443?type=ws&type=tcp",
            "trojan://secret@example.org:443?secret=token",
            "trojan://secret:password@example.org:443",
            "trojan://secret@example.org:443?path=%zz",
        ] {
            let err = parse_uri(uri).unwrap_err().to_string();
            assert!(!err.contains("secret") && !err.contains("token") && !err.contains("password"));
        }
        assert!(
            parse_subscription(b"ss://unsupported\nvless://invalid")
                .unwrap_err()
                .to_string()
                .contains("cache preserved")
        );
    }

    #[test]
    fn domain_escaped_credentials_and_unicode_identity_are_stable() {
        let node = parse_uri(
            "trojan://p%40ss%2B%E9%9B%AA@[2001:db8::1]:443?type=httpupgrade&path=%2Fh#%E9%9B%AA",
        )
        .unwrap();
        assert_eq!(node.outbound["password"], "p@ss+雪");
        assert_eq!(node.outbound["server"], "2001:db8::1");
        assert_eq!(node.name, "雪");
        assert_eq!(node.id, "be8284f8bd40b5d3");
        assert_eq!(
            node.outbound["transport"],
            serde_json::json!({"type":"httpupgrade","path":"/h"})
        );
    }
}
