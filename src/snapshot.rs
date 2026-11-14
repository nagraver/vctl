use crate::{model::State, service, store::Store};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;

pub fn build(home: &Path) -> Result<Value> {
    let store = Store::new(home)?;
    let state = store.read()?;
    let tun = service::snapshot(&store.home)?;
    Ok(from_state(&store.home, &state, tun))
}

/// Source locations are editable, but query tokens and userinfo never cross into UI state.
pub fn display_source(source: &str) -> String {
    if let Ok(mut url) = url::Url::parse(source)
        && matches!(url.scheme(), "https" | "http")
    {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        return url.to_string();
    }
    source.to_owned()
}

pub fn from_state(home: &Path, state: &State, mut tun: Value) -> Value {
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut subscriptions = Vec::new();
    let mut desired = "Automatic".to_owned();
    for (name, sub) in &state.subscriptions {
        let mut local = HashSet::new();
        let mut sub_nodes = Vec::new();
        for node in &sub.nodes {
            let public = json!({"id":node.id,"name":crate::profiles::clean(&node.name),"subscription":crate::profiles::clean(name),"protocol":node.outbound.get("type").and_then(Value::as_str).unwrap_or("")});
            if local.insert(&node.id) {
                sub_nodes.push(public.clone());
            }
            if seen.insert(&node.id) {
                nodes.push(public);
            }
            if node.id == state.selected {
                desired = crate::profiles::clean(&node.name);
            }
        }
        subscriptions.push(json!({"key":name,"name":crate::profiles::clean(name),"count":sub_nodes.len(),"skipped":sub.skipped,"nodes":sub_nodes,"interval":sub.interval,"updated":sub.updated}));
    }
    let presets: Vec<_> = state.presets.iter().map(|(name, preset)|json!({"key":name,"name":crate::profiles::clean(name),"source":display_source(&preset.source),"enabled":preset.enabled,"count":preset.rules.len(),"interval":preset.interval})).collect();
    let geodata: serde_json::Map<_, _> = state.geodata.iter().map(|(kind, asset)|{
        let source = display_source(&asset.url);
        (kind.clone(), json!({"url":source,"redacted":source != asset.url,"sha256":asset.sha256,"updated":asset.updated,"interval":asset.interval}))
    }).collect();
    let mut dns = json!({"direct":"https://1.1.1.1/dns-query","proxy":"https://1.1.1.1/dns-query","strategy":"UseIP"});
    let mut dns_redacted = false;
    for (key, value) in &state.dns {
        if matches!(key.as_str(), "direct" | "proxy") {
            let public = display_source(value);
            dns_redacted |= public != *value;
            dns[key] = json!(public);
        } else if key == "strategy" {
            dns[key] = json!(crate::profiles::clean(value));
        }
    }
    if let Some(name) = tun["server"]["name"].as_str() {
        let name = crate::profiles::clean(name);
        tun["server"]["name"] = json!(name);
    }
    let actual_name = tun
        .get("server")
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let connected = tun.get("state").and_then(Value::as_str) == Some("on");
    let server_name = match actual_name {
        Some(name) if tun["server"]["automatic"] == true => format!("Automatic — {name}"),
        Some(name) => name.to_owned(),
        None if connected => "Connected server unavailable".into(),
        None => desired.clone(),
    };
    json!({"protocol":crate::PROTOCOL_VERSION,"version":crate::VERSION,"home":home,"selected":state.selected,"serverName":server_name,"desiredServerName":desired,"defaultRoute":state.default_route,"nodes":nodes,"subscriptions":subscriptions,"rules":state.rules,"presets":presets,"dns":dns,"dnsRedacted":dns_redacted,"geodata":geodata,"tun":tun})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Node, Subscription};

    #[test]
    fn snapshot_redacts_secrets_and_reports_applied_server() {
        let mut state = State {
            selected: "new".into(),
            ..Default::default()
        };
        let old = Node {
            id: "old".into(),
            name: "Old".into(),
            outbound: json!({"type":"trojan", "password":"secret-password"}),
        };
        let new = Node {
            id: "new".into(),
            name: "New".into(),
            outbound: json!({"type":"vless", "uuid":"secret-uuid"}),
        };
        state.subscriptions.insert(
            "Main".into(),
            Subscription {
                url: "https://example.org/secret-token".into(),
                nodes: vec![old.clone(), new],
                ..Default::default()
            },
        );
        state.subscriptions.insert(
            "Duplicate".into(),
            Subscription {
                nodes: vec![old],
                ..Default::default()
            },
        );
        let snapshot = from_state(
            Path::new("/profile"),
            &state,
            json!({"state":"on","server":{"id":"old","name":"Old"},"error":"Update failed"}),
        );
        let text = snapshot.to_string();
        for secret in ["secret-password", "secret-uuid", "secret-token", "outbound"] {
            assert!(!text.contains(secret));
        }
        assert_eq!(snapshot["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(snapshot["selected"], "new");
        assert_eq!(snapshot["serverName"], "Old");
        assert_eq!(snapshot["desiredServerName"], "New");
        assert_eq!(snapshot["protocol"], 2);
    }

    #[test]
    fn empty_snapshot_has_decodable_collections() {
        let snapshot = from_state(
            Path::new("/missing"),
            &State::default(),
            json!({"state":"off","installed":false}),
        );
        for key in ["nodes", "subscriptions", "presets", "rules"] {
            assert!(snapshot[key].is_array(), "{key}");
        }
        assert_eq!(snapshot["dns"]["strategy"], "UseIP");
    }
    #[test]
    fn reading_status_does_not_create_a_profile() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("missing");
        let snapshot = build(&home).unwrap();
        assert_eq!(snapshot["tun"]["state"], "off");
        assert!(!home.exists());
    }
    #[test]
    fn source_display_hides_query_password_and_fragment() {
        let display = display_source("https://user:password@example.org/data?token=secret#private");
        assert_eq!(display, "https://example.org/data");
        assert_eq!(display_source("/tmp/preset.json"), "/tmp/preset.json");
    }
    #[test]
    fn display_labels_are_clean_and_dns_credentials_are_not_exposed() {
        let mut state = State::default();
        state.subscriptions.insert(
            "Main\n".into(),
            Subscription {
                nodes: vec![Node {
                    id: "id".into(),
                    name: "Server\u{1b}\n".into(),
                    outbound: json!({"type":"trojan"}),
                }],
                ..Default::default()
            },
        );
        state.dns.insert(
            "direct".into(),
            "https://user:password@1.1.1.1/dns-query?token=private".into(),
        );
        state.dns.insert("unknown".into(), "hidden-secret".into());
        let snapshot = from_state(
            Path::new("/profile"),
            &state,
            json!({"state":"on","server":{"name":"Server\u{1b}\n"}}),
        );
        assert_eq!(snapshot["nodes"][0]["name"], "Server");
        assert_eq!(snapshot["serverName"], "Server");
        assert_eq!(snapshot["subscriptions"][0]["name"], "Main");
        assert_eq!(snapshot["subscriptions"][0]["key"], "Main\n");
        assert_eq!(snapshot["dns"]["direct"], "https://1.1.1.1/dns-query");
        assert_eq!(snapshot["dnsRedacted"], true);
        for secret in ["password", "token=private", "hidden-secret"] {
            assert!(!snapshot.to_string().contains(secret));
        }
    }
}
