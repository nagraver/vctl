//! Validated domain rules compiled into the pinned Xray JSON dialect.
use crate::model::{Node, Rule, State};
use crate::profiles::validate_outbound;
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use url::{Host, Url};

pub const PRIVATE_IPS: [&str; 8] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

pub fn make_rule(kind: &str, value: &str, action: &str) -> Result<Rule> {
    ensure!(
        matches!(action, "direct" | "proxy" | "block")
            && !value.is_empty()
            && value.len() <= 8192
            && !value.chars().any(char::is_control),
        "invalid routing rule"
    );
    let value = match kind {
        "cidr" => {
            let net = if value.contains('/') {
                value
                    .parse::<ipnet::IpNet>()
                    .map_err(|_| anyhow!("invalid CIDR"))?
            } else {
                ipnet::IpNet::from(
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| anyhow!("invalid CIDR"))?,
                )
            };
            net.trunc().to_string()
        }
        "domain" | "suffix" => {
            let normalized = value.trim_end_matches('.').to_lowercase();
            // Keep ASCII spelling stable: URL host parsing would expand short numeric hostnames.
            let ascii = if normalized.is_ascii() {
                normalized
            } else {
                Host::parse(&normalized)
                    .map_err(|_| anyhow!("invalid hostname"))?
                    .to_string()
            };
            ensure!(
                !ascii.is_empty()
                    && ascii.len() <= 253
                    && ascii.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label
                                .as_bytes()
                                .first()
                                .is_some_and(u8::is_ascii_alphanumeric)
                            && label
                                .as_bytes()
                                .last()
                                .is_some_and(u8::is_ascii_alphanumeric)
                            && label
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    }),
                "use a hostname without scheme, wildcard or path"
            );
            ascii
        }
        "geoip" | "geosite" => {
            let value = value.to_lowercase();
            let parts: Vec<_> = value.split('@').collect();
            ensure!(
                (1..=2).contains(&parts.len())
                    && parts.iter().all(|part| !part.is_empty()
                        && part.bytes().all(|c| c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || matches!(c, b'_' | b'!' | b'-'))),
                "invalid geodata category"
            );
            value
        }
        "process" => {
            ensure!(!value.contains('/'), "use path for an absolute executable");
            value.to_owned()
        }
        "path" => {
            ensure!(
                Path::new(value).is_absolute(),
                "application path must be absolute"
            );
            let directory = value.ends_with('/') || value.ends_with(".app");
            let mut path = PathBuf::new();
            for part in Path::new(value).components() {
                match part {
                    Component::ParentDir => {
                        path.pop();
                    }
                    Component::CurDir => {}
                    _ => path.push(part.as_os_str()),
                }
            }
            let mut value = path.to_string_lossy().into_owned();
            if directory && !value.ends_with('/') {
                value.push('/');
            }
            value
        }
        _ => bail!("invalid routing rule"),
    };
    Ok(Rule {
        kind: kind.into(),
        value,
        action: action.into(),
    })
}

fn https_url(value: &str) -> Result<Url> {
    ensure!(
        value.len() <= 8192 && !value.chars().any(char::is_control),
        "invalid HTTPS URL"
    );
    let url = Url::parse(value).map_err(|_| anyhow!("invalid HTTPS URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "URL must use HTTPS without user credentials or fragment"
    );
    Ok(url)
}

fn digest_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
}

/// This runs again in the privileged supervisor; user-owned state is never trusted.
pub fn validate_state(state: &State) -> Result<()> {
    ensure!(state.version == 1, "unsupported profile version");
    let rule_count = state.rules.len().saturating_add(
        state
            .presets
            .values()
            .map(|preset| preset.rules.len())
            .sum::<usize>(),
    );
    let node_count: usize = state
        .subscriptions
        .values()
        .map(|subscription| subscription.nodes.len())
        .sum();
    ensure!(
        rule_count <= 50_000 && node_count <= 20_000,
        "profile exceeds supported rule or server count"
    );
    ensure!(
        matches!(state.default_route.as_str(), "direct" | "proxy"),
        "invalid default route"
    );
    ensure!(
        !state.selected.is_empty()
            && state.selected.len() <= 128
            && !state.selected.chars().any(char::is_control),
        "invalid selected server"
    );
    https_url(&state.test_url)?;
    for (key, value) in &state.dns {
        match key.as_str() {
            "direct" | "proxy" => {
                if value.is_empty() {
                    continue;
                }
                let url = https_url(value)?;
                ensure!(
                    matches!(url.host(), Some(Host::Ipv4(_)) | Some(Host::Ipv6(_))),
                    "DNS resolver must contain an IP address"
                );
            }
            "strategy" => ensure!(
                matches!(value.as_str(), "" | "UseIP" | "UseIPv4" | "UseIPv6"),
                "invalid DNS strategy"
            ),
            _ => bail!("unsupported DNS setting"),
        }
    }
    for (kind, asset) in &state.geodata {
        ensure!(
            matches!(kind.as_str(), "geoip" | "geosite"),
            "unknown geodata kind"
        );
        ensure!(digest_ok(&asset.sha256), "invalid geodata digest");
    }
    for rule in state
        .rules
        .iter()
        .chain(state.presets.values().flat_map(|preset| &preset.rules))
    {
        make_rule(&rule.kind, &rule.value, &rule.action)?;
    }
    let mut identities = HashMap::new();
    for node in state
        .subscriptions
        .values()
        .flat_map(|subscription| &subscription.nodes)
    {
        ensure!(
            node.id.len() == 16
                && node
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f')),
            "invalid stored node ID"
        );
        validate_outbound(&node.outbound)?;
        if let Some(previous) = identities.insert(&node.id, &node.outbound) {
            ensure!(
                previous == &node.outbound,
                "conflicting stored node identities"
            );
        }
    }
    Ok(())
}

fn outbound(node: &Node) -> Result<Value> {
    validate_outbound(&node.outbound)?;
    let source = &node.outbound;
    let settings = match source["type"].as_str().unwrap_or_default() {
        "vless" => {
            let mut user = json!({"id":source["uuid"],"encryption":"none"});
            if let Some(flow) = source.get("flow") {
                user["flow"] = flow.clone();
            }
            json!({"vnext":[{"address":source["server"],"port":source["server_port"],"users":[user]}]})
        }
        "trojan" => {
            json!({"servers":[{"address":source["server"],"port":source["server_port"],"password":source["password"]}]})
        }
        _ => bail!("unsupported outbound protocol"),
    };
    let mut stream = json!({"network":"tcp","security":"none"});
    if let Some(mask) = source.get("finalmask") {
        stream["finalmask"] = mask.clone();
    }
    if let Some(tls) = source.get("tls") {
        let reality = tls.get("reality");
        let security = if reality.is_some() { "reality" } else { "tls" };
        stream["security"] = json!(security);
        let mut fields = json!({"serverName":tls["server_name"]});
        if let Some(utls) = tls.get("utls") {
            fields["fingerprint"] = utls["fingerprint"].clone();
        }
        if let Some(reality) = reality {
            fields["password"] = reality["public_key"].clone();
            fields["shortId"] = reality["short_id"].clone();
            if fields.get("fingerprint").is_none() {
                fields["fingerprint"] = json!("chrome");
            }
        } else if let Some(alpn) = tls.get("alpn") {
            fields["alpn"] = alpn.clone();
        }
        stream[format!("{security}Settings")] = fields;
    }
    if let Some(transport) = source.get("transport") {
        let kind = transport["type"].as_str().unwrap_or_default();
        stream["network"] = json!(kind);
        match kind {
            "ws" => {
                stream["wsSettings"] = json!({"path":transport["path"],"headers":transport.get("headers").cloned().unwrap_or_else(|| json!({}))});
            }
            "grpc" => {
                stream["grpcSettings"] = json!({"serviceName":transport["service_name"]});
            }
            "httpupgrade" => {
                stream["httpupgradeSettings"] = json!({"path":transport["path"],"host":transport.get("host").cloned().unwrap_or_else(|| json!(""))});
            }
            _ => bail!("stored transport unsupported"),
        }
    }
    Ok(
        json!({"protocol":source["type"],"tag":format!("node-{}",node.id),"settings":settings,"streamSettings":stream}),
    )
}

fn target(mut rule: Value, action: &str, selected: &str) -> Value {
    if action == "proxy" && selected == "auto" {
        rule["balancerTag"] = json!("auto");
    } else {
        rule["outboundTag"] = json!(if action == "proxy" {
            format!("node-{selected}")
        } else {
            action.into()
        });
    }
    rule
}

fn resolver(state: &State, action: &str, domains: Option<&str>) -> Value {
    let address = state
        .dns
        .get(action)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or("https://1.1.1.1/dns-query");
    let mut server = json!({"address":address,"tag":format!("dns-{action}")});
    if let Some(domain) = domains {
        server["domains"] = json!([domain]);
        server["skipFallback"] = json!(true);
        server["finalQuery"] = json!(true);
    }
    server
}

pub fn generate(state: &State, mode: &str, port: u16) -> Result<Value> {
    ensure!(
        matches!(mode, "proxy" | "tun") && (1..=65534).contains(&port),
        "invalid mode or port"
    );
    validate_state(state)?;
    let nodes = state.nodes();
    ensure!(!nodes.is_empty(), "add a subscription first");
    ensure!(
        state.selected == "auto" || nodes.iter().any(|node| node.id == state.selected),
        "selected server disappeared; choose a server or auto"
    );
    let tags: Vec<_> = nodes
        .iter()
        .map(|node| format!("node-{}", node.id))
        .collect();
    let mut outbounds: Vec<_> = nodes.iter().map(outbound).collect::<Result<_>>()?;
    let mut rules = vec![
        json!({"type":"field","inboundTag":["dns-direct"],"outboundTag":"direct"}),
        target(
            json!({"type":"field","inboundTag":["dns-proxy"]}),
            "proxy",
            &state.selected,
        ),
        json!({"type":"field","port":"53","outboundTag":"dns-out"}),
    ];
    let mut dns = Vec::new();
    let effective = state.rules.iter().chain(
        state
            .presets
            .values()
            .filter(|p| p.enabled)
            .flat_map(|p| &p.rules),
    );
    for rule in effective {
        let rule = make_rule(&rule.kind, &rule.value, &rule.action)?;
        let value = match rule.kind.as_str() {
            "domain" => format!("full:{}", rule.value),
            "suffix" => format!("domain:{}", rule.value),
            "geoip" | "geosite" => {
                let digest = &state
                    .geodata
                    .get(&rule.kind)
                    .ok_or_else(|| anyhow!("geodata missing; update databases"))?
                    .sha256;
                ensure!(digest_ok(digest), "invalid geodata digest");
                format!("ext:{digest}.dat:{}", rule.value)
            }
            _ => rule.value.clone(),
        };
        let field = match rule.kind.as_str() {
            "domain" | "suffix" | "geosite" => "domain",
            "cidr" | "geoip" => "ip",
            _ => "process",
        };
        let mut compiled = target(json!({"type":"field"}), &rule.action, &state.selected);
        compiled[field] = json!([value]);
        if matches!(rule.kind.as_str(), "path" | "process") {
            compiled["inboundTag"] = json!(["tun-in"]);
        }
        rules.push(compiled);
        if matches!(rule.kind.as_str(), "domain" | "suffix" | "geosite") {
            let action = if rule.action == "block" {
                &state.default_route
            } else {
                &rule.action
            };
            dns.push(resolver(state, action, Some(&value)));
        }
    }
    rules.push(json!({"type":"field","ip":PRIVATE_IPS,"outboundTag":"direct"}));
    rules.push(target(
        json!({"type":"field","network":"tcp,udp"}),
        &state.default_route,
        &state.selected,
    ));
    let sniff = json!({"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false});
    let mut inbounds = vec![
        json!({"tag":"socks-in","listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":sniff}),
        json!({"tag":"http-in","listen":"127.0.0.1","port":port + 1,"protocol":"http","settings":{},"sniffing":sniff}),
    ];
    if mode == "tun" {
        inbounds.push(json!({"tag":"tun-in","protocol":"tun","settings":{"mtu":1500,"gateway":["172.28.0.1/30"],"autoSystemRoutingTable":["0.0.0.0/0","::/0"],"autoOutboundsInterface":"auto"},"sniffing":sniff}));
    }
    dns.push(resolver(state, &state.default_route, None));
    outbounds.extend([
        json!({"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIP"}}),
        json!({"protocol":"blackhole","tag":"block","settings":{}}),
        json!({"protocol":"dns","tag":"dns-out","settings":{}}),
    ]);
    let strategy = state
        .dns
        .get("strategy")
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .unwrap_or("UseIP");
    let mut config = json!({
        "log":{"loglevel":"warning"}, "inbounds":inbounds,
        "dns":{"servers":dns,"tag":format!("dns-{}", state.default_route),"queryStrategy":strategy,"disableFallbackIfMatch":true},
        "outbounds":outbounds, "routing":{"domainStrategy":"IPOnDemand","rules":rules}
    });
    if state.selected == "auto" {
        config["routing"]["balancers"] = json!([{"tag":"auto","selector":tags,"fallbackTag":tags[0],"strategy":{"type":"leastPing"}}]);
        config["observatory"] = json!({"subjectSelector":tags,"probeURL":state.test_url,"probeInterval":"5m","enableConcurrency":true});
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Value, State) {
        let f: Value =
            serde_json::from_str(include_str!("../internal/whale/testdata/legacy.json")).unwrap();
        let s = serde_json::from_value(f["state"].clone()).unwrap();
        (f, s)
    }

    #[test]
    fn domain_compiler_preserves_complete_legacy_config_and_order() {
        let (f, s) = fixture();
        assert_eq!(generate(&s, "proxy", 2080).unwrap(), f["proxy"]);
        assert_eq!(generate(&s, "tun", 2180).unwrap(), f["tun"]);
    }

    #[test]
    fn domain_rules_normalize_and_reject_ambiguous_inputs() {
        assert_eq!(
            make_rule("suffix", "ПРИМЕР.РФ.", "direct").unwrap().value,
            "xn--e1afmkfd.xn--p1ai"
        );
        assert_eq!(
            make_rule("cidr", "192.0.2.17/24", "direct").unwrap().value,
            "192.0.2.0/24"
        );
        assert_eq!(
            make_rule("path", "/Applications/Foo.app", "proxy")
                .unwrap()
                .value,
            "/Applications/Foo.app/"
        );
        for (kind, value, action) in [
            ("suffix", "https://example.org", "direct"),
            ("path", "foo.app", "direct"),
            ("process", "/bin/curl", "proxy"),
            ("cidr", "bad", "direct"),
            ("domain", "example.org", "invalid"),
        ] {
            assert!(make_rule(kind, value, action).is_err());
        }
    }

    #[test]
    fn domain_privileged_compiler_rejects_injected_engine_fields() {
        let (_, mut s) = fixture();
        s.subscriptions["demo"].nodes[0].outbound["tls"]["certificate_path"] =
            json!("/etc/private-key");
        assert!(generate(&s, "tun", 2180).is_err());
        let (_, mut s) = fixture();
        s.dns
            .insert("proxy".into(), "https://resolver.example/dns-query".into());
        assert!(validate_state(&s).is_err());
    }

    #[test]
    fn domain_selected_node_must_exist_and_ports_must_fit() {
        let (_, mut s) = fixture();
        s.selected = "missing".into();
        assert!(generate(&s, "tun", 2180).is_err());
        s.selected = "auto".into();
        assert!(generate(&s, "tun", 65535).is_err());
        assert!(generate(&s, "tun", 0).is_err());
    }

    #[test]
    fn domain_node_ids_cannot_alias_different_connections() {
        let (_, mut s) = fixture();
        s.subscriptions["demo"].nodes[1].id = s.subscriptions["demo"].nodes[0].id.clone();
        assert!(validate_state(&s).is_err());
        let (_, mut s) = fixture();
        s.subscriptions["demo"].nodes[0].id = "arbitrary-tag".into();
        assert!(validate_state(&s).is_err());
    }

    #[test]
    fn domain_state_bounds_work_before_engine_generation() {
        let (_, mut s) = fixture();
        s.rules = vec![s.rules[0].clone(); 50_001];
        assert!(validate_state(&s).is_err());
        let (_, mut s) = fixture();
        s.subscriptions["demo"].nodes = vec![s.subscriptions["demo"].nodes[0].clone(); 20_001];
        assert!(validate_state(&s).is_err());
    }
}
