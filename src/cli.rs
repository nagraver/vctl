#[cfg(test)]
mod tests {
    use clap::Parser;
    #[test]
    fn public_contract_rejects_removed_commands() {
        for command in ["tun", "sub", "start", "stop", "completion", "nodes", "rule"] {
            assert!(super::PublicArgs::try_parse_from(["whale", command]).is_err());
        }
        for command in ["up", "down", "status"] {
            assert!(super::PublicArgs::try_parse_from(["whale", command]).is_ok());
        }
    }
    #[test]
    fn explicit_install_replaces_a_compatible_controller() {
        let args = super::HelperArgs::try_parse_from(["whale-helper", "tun", "install"]).unwrap();
        let Some(super::HelperCommand::Tun(action)) = args.command else {
            panic!("Expected tunnel action")
        };
        assert!(super::installation_required(action.action(), true));
        assert!(!super::installation_required("up", true));
        assert!(super::installation_required("down", false));
    }
    #[test]
    fn helper_accepts_gui_inventory_but_rejects_arbitrary_tunnel_commands() {
        for args in [
            vec!["snapshot"],
            vec!["sub", "add", "--interval", "43200"],
            vec!["_tun", "up"],
            vec!["rule-remove-match", "suffix", "example.org", "direct"],
            vec!["_runtime", "--owner", "501", "--runtime", "/safe/runtime"],
        ] {
            let mut all = vec!["whale-helper"];
            all.extend(args);
            assert!(super::HelperArgs::try_parse_from(all).is_ok());
        }
        assert!(super::HelperArgs::try_parse_from(["whale-helper", "_tun", "run"]).is_err());
    }
    #[test]
    fn dns_validation_rejects_credentials_and_non_ip_hosts() {
        for value in [
            "http://1.1.1.1/dns-query",
            "https://example.org/dns-query",
            "https://name:secret@1.1.1.1/dns-query",
            "https://1.1.1.1/dns-query?secret=token",
        ] {
            assert!(super::validate_dns("direct", value).is_err());
        }
        assert!(super::validate_dns("direct", "https://1.1.1.1/dns-query").is_ok());
        assert!(super::validate_dns("proxy", "https://[2606:4700:4700::1111]/dns-query").is_ok());
        assert!(super::validate_dns("strategy", "invalid").is_err());
    }
    #[test]
    fn mutation_validates_with_bundled_engine_before_saving() {
        let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".tools/xray");
        if !core.is_file() {
            eprintln!("Bundled Xray unavailable; checked in integration instead");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let store = crate::store::Store::new(directory.path().join("profile")).unwrap();
        let command = super::HelperCommand::Rule(super::RuleCommand::Add {
            kind: "suffix".into(),
            value: "example.org".into(),
            action: "direct".into(),
        });
        super::run_operation(&store, Some(&core), command).unwrap();
        assert_eq!(store.read().unwrap().rules[0].value, "example.org");
    }
}

use crate::{
    config, latency,
    model::{State, Subscription},
    runtime, service, snapshot, sources,
    store::Store,
};
use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn default_home() -> PathBuf {
    for key in ["WHALE_HOME", "VCTL_HOME"] {
        if let Some(path) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config/vctl")
}
#[derive(Parser)]
#[command(name="whale", version=crate::VERSION, about="Whale VPN — manage settings in the macOS application")]
struct PublicArgs {
    #[arg(long, global=true, default_value_os_t=default_home())]
    home: PathBuf,
    #[command(subcommand)]
    command: Option<PublicCommand>,
}
#[derive(Subcommand)]
enum PublicCommand {
    Up,
    Down,
    Status,
}
#[derive(Parser)]
#[command(name="whale-helper", version=crate::VERSION, about="Whale internal application helper")]
struct HelperArgs {
    #[arg(long, global=true, default_value_os_t=default_home())]
    home: PathBuf,
    #[arg(long, global = true)]
    core: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<HelperCommand>,
}
#[derive(Subcommand)]
enum HelperCommand {
    Snapshot,
    Nodes,
    Use {
        id: String,
    },
    Default {
        route: String,
    },
    #[command(subcommand)]
    Sub(SubscriptionCommand),
    #[command(subcommand)]
    Rule(RuleCommand),
    RuleRemoveMatch {
        kind: String,
        value: String,
        action: String,
    },
    #[command(subcommand)]
    Preset(PresetCommand),
    #[command(subcommand)]
    Dns(DnsCommand),
    #[command(subcommand)]
    Geodata(GeodataCommand),
    Latency {
        #[arg(long)]
        subscription: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    ControllerStatus,
    Control {
        action: String,
    },
    #[command(name = "tun", subcommand)]
    Tun(TunnelCommand),
    #[command(name = "_tun", hide = true, subcommand)]
    InternalTun(TunnelCommand),
    #[command(name = "_controller-install", hide = true)]
    ControllerInstall,
    #[command(name = "_controller", hide = true)]
    Controller {
        #[arg(long)]
        owner: u32,
    },
    #[command(name = "_runtime", hide = true)]
    Runtime {
        #[arg(long)]
        owner: u32,
        #[arg(long)]
        runtime: PathBuf,
    },
    #[command(name = "_refresh", hide = true)]
    Refresh {
        #[arg(long)]
        owner: u32,
    },
    #[command(name = "_engine", hide = true)]
    Engine {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        assets: PathBuf,
    },
}
#[derive(Subcommand)]
enum SubscriptionCommand {
    List,
    Add {
        name: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 43200)]
        interval: u64,
    },
    Update {
        name: Option<String>,
    },
    Remove {
        name: String,
    },
}
#[derive(Subcommand)]
enum RuleCommand {
    List,
    Add {
        kind: String,
        value: String,
        action: String,
    },
    Remove {
        index: usize,
    },
}
#[derive(Subcommand)]
enum PresetCommand {
    List,
    Add {
        name: String,
        source: String,
        #[arg(long, default_value_t = 43200)]
        interval: u64,
    },
    Show {
        name: String,
    },
    Update {
        name: Option<String>,
    },
    Remove {
        name: String,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
}
#[derive(Subcommand)]
enum DnsCommand {
    Show,
    Set(DnsOptions),
}
#[derive(Args)]
struct DnsOptions {
    #[arg(long)]
    direct: Option<String>,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    strategy: Option<String>,
}
#[derive(Subcommand)]
enum GeodataCommand {
    Status,
    Update {
        #[arg(long)]
        geoip_url: Option<String>,
        #[arg(long)]
        geosite_url: Option<String>,
        #[arg(long)]
        interval: Option<u64>,
    },
}
#[derive(Subcommand)]
enum TunnelCommand {
    Up,
    Down,
    Restart,
    Status,
    Install,
    Uninstall,
    Recover,
}
impl TunnelCommand {
    fn action(&self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Restart => "restart",
            Self::Status => "status",
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Recover => "recover",
        }
    }
}

fn output(value: &impl serde::Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, value)?;
    writeln!(writer)?;
    Ok(())
}
fn helper_path() -> Result<PathBuf> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = executable
        .parent()
        .context("Application directory unavailable")?;
    for path in [
        directory.join("whale-helper"),
        directory.join("../libexec/whale-helper"),
        directory.join("../MacOS/whale-helper"),
    ] {
        if path.is_file() {
            return Ok(path.canonicalize()?);
        }
    }
    bail!("Whale helper is missing; reinstall the application")
}
pub fn public_main() -> Result<()> {
    let args = PublicArgs::parse();
    let Some(command) = args.command else {
        PublicArgs::command().print_help()?;
        println!();
        return Ok(());
    };
    let action = match command {
        PublicCommand::Up => Some("up"),
        PublicCommand::Down => Some("down"),
        PublicCommand::Status => None,
    };
    if let Some(action) = action {
        let status = Command::new(helper_path()?)
            .arg("--home")
            .arg(&args.home)
            .args(["tun", action])
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()?;
        if !status.success() {
            bail!("Could not {action} VPN; see the message above");
        }
    }
    let snapshot = snapshot::build(&args.home)?;
    println!(
        "VPN: {}\nServer: {}",
        snapshot["tun"]["state"].as_str().unwrap_or("unknown"),
        snapshot["serverName"].as_str().unwrap_or("Unavailable")
    );
    if let Some(error) = snapshot["tun"]["error"]
        .as_str()
        .filter(|error| !error.is_empty())
    {
        println!("Details: {error}");
    }
    Ok(())
}
fn controller_action(
    home: &Path,
    core: Option<&Path>,
    action: &str,
    bootstrap: bool,
) -> Result<Value> {
    if bootstrap
        && installation_required(
            action,
            action != "install" && service::controller_call(home, "status").is_ok(),
        )
    {
        let mut command = Command::new("/usr/bin/sudo");
        command
            .arg(std::env::current_exe()?)
            .arg("--home")
            .arg(home);
        if let Some(core) = core {
            command.arg("--core").arg(core);
        }
        if !command
            .arg("_controller-install")
            .status()
            .context("Could not request system helper authorization")?
            .success()
        {
            bail!("System helper installation or upgrade was not approved");
        }
    }
    service::controller_call(
        home,
        if bootstrap && action == "install" {
            "status"
        } else {
            action
        },
    )
}
fn installation_required(action: &str, compatible: bool) -> bool {
    action == "install" || !compatible
}
fn validate_candidate(
    store: &Store,
    core: Option<&Path>,
    before: &State,
    candidate: &State,
) -> Result<()> {
    config::validate_state(candidate)?;
    if !before.nodes().is_empty()
        && candidate.nodes().is_empty()
        && service::snapshot(&store.home)?["state"].as_str() != Some("off")
    {
        bail!("Disconnect the VPN before removing the last subscription");
    }
    let mut validation = candidate.clone();
    if validation.nodes().is_empty() {
        let node =
            crate::profiles::parse_uri("trojan://validation@127.0.0.1:1?security=tls#Validation")?;
        validation.selected = node.id.clone();
        validation.subscriptions.insert(
            "validation".into(),
            Subscription {
                nodes: vec![node],
                interval: 43200,
                ..Default::default()
            },
        );
    }
    runtime::validate_config(
        &service::core_path(core)?,
        &store.home,
        &validation,
        "proxy",
        2080,
    )
}
fn commit(store: &Store, core: Option<&Path>, before: State, candidate: State) -> Result<()> {
    validate_candidate(store, core, &before, &candidate)?;
    let revision = serde_json::to_vec(&before)?;
    store.update(|current| {
        if serde_json::to_vec(current)? != revision {
            bail!("Profile changed during this operation; refresh and try again");
        }
        *current = candidate;
        Ok(())
    })?;
    println!("Saved. The running service applies changes automatically.");
    Ok(())
}
fn read_private_url() -> Result<String> {
    let mut input = String::new();
    io::stdin().lock().take(16_385).read_line(&mut input)?;
    if input.len() > 16_384 {
        bail!("Subscription URL is too long");
    }
    let input = input.trim().to_owned();
    if input.is_empty() {
        bail!("Subscription URL is required");
    }
    Ok(input)
}
fn valid_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 512 || name.chars().any(char::is_control) {
        bail!("Enter a nonempty name without control characters");
    }
    Ok(())
}
fn validate_dns(key: &str, value: &str) -> Result<()> {
    if key == "strategy" {
        if !matches!(value, "UseIP" | "UseIPv4" | "UseIPv6") {
            bail!("Invalid DNS strategy");
        }
    } else {
        let url = url::Url::parse(value)
            .map_err(|_| anyhow::anyhow!("DNS requires HTTPS with a literal IP host"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || url.host_str().is_none_or(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_err()
            })
        {
            bail!("DNS requires HTTPS with a literal IP host and no credentials");
        }
    }
    Ok(())
}
pub fn helper_main() -> Result<()> {
    let args = HelperArgs::parse();
    let core = args.core.as_deref();
    let Some(command) = args.command else {
        HelperArgs::command().print_help()?;
        println!();
        return Ok(());
    };
    match command {
        HelperCommand::Snapshot => output(&snapshot::build(&args.home)?),
        HelperCommand::ControllerStatus => output(&service::controller_call(&args.home, "status")?),
        HelperCommand::Control { action } => {
            output(&controller_action(&args.home, core, &action, false)?)
        }
        HelperCommand::Tun(action) | HelperCommand::InternalTun(action) => {
            output(&controller_action(
                &args.home,
                core,
                action.action(),
                !matches!(action, TunnelCommand::Status),
            )?)
        }
        HelperCommand::ControllerInstall => {
            service::install_controller(&args.home, &service::core_path(core)?)
        }
        HelperCommand::Controller { owner } => {
            service::serve_controller(&args.home, &service::core_path(core)?, owner)
        }
        HelperCommand::Runtime { owner, runtime } => {
            runtime::serve(&args.home, &service::core_path(core)?, &runtime, owner)
        }
        HelperCommand::Refresh { owner } => service::refresh_as_user(&args.home, owner),
        HelperCommand::Engine { config, assets } => {
            runtime::engine_entry(core.context("Engine path is required")?, &config, &assets)
        }
        other => run_operation(&Store::new(&args.home)?, core, other),
    }
}
fn run_operation(store: &Store, core: Option<&Path>, command: HelperCommand) -> Result<()> {
    let before = store.read()?;
    let mut candidate = before.clone();
    match command {
        HelperCommand::Nodes => {
            return output(
                &snapshot::from_state(&store.home, &before, json!({"state":"off"}))["nodes"],
            );
        }
        HelperCommand::Use { id } => {
            if id != "auto" && !before.nodes().iter().any(|node| node.id == id) {
                bail!("Unknown node ID");
            }
            candidate.selected = id;
        }
        HelperCommand::Default { route } => {
            if !matches!(route.as_str(), "proxy" | "direct") {
                bail!("Choose proxy or direct");
            }
            candidate.default_route = route;
        }
        HelperCommand::Sub(command) => match command {
            SubscriptionCommand::List => {
                return output(
                    &snapshot::from_state(&store.home, &before, json!({"state":"off"}))["subscriptions"],
                );
            }
            SubscriptionCommand::Add {
                name,
                url,
                interval,
            } => {
                let url = match url {
                    Some(url) => url,
                    None => read_private_url()?,
                };
                if before.subscriptions.values().any(|sub| sub.url == url) {
                    bail!("Subscription already exists");
                }
                let sub = sources::fetch_subscription(&url, interval)?;
                let name = match name {
                    Some(name) => {
                        valid_name(&name)?;
                        if before.subscriptions.contains_key(&name) {
                            bail!("Subscription name already exists");
                        }
                        name
                    }
                    None => {
                        let base = if sub.title.trim().is_empty() {
                            "Subscription"
                        } else {
                            &sub.title
                        };
                        let mut name = base.to_owned();
                        let mut i = 2;
                        while before.subscriptions.contains_key(&name) {
                            name = format!("{base} ({i})");
                            i += 1;
                        }
                        valid_name(&name)?;
                        name
                    }
                };
                candidate.subscriptions.insert(name, sub);
            }
            SubscriptionCommand::Update { name } => {
                let names: Vec<_> = name
                    .map(|name| vec![name])
                    .unwrap_or_else(|| before.subscriptions.keys().cloned().collect());
                for name in names {
                    let old = before
                        .subscriptions
                        .get(&name)
                        .context("Unknown subscription")?;
                    let mut new = sources::fetch_subscription(&old.url, old.interval)?;
                    new.extra = old.extra.clone();
                    candidate.subscriptions.insert(name, new);
                }
            }
            SubscriptionCommand::Remove { name } => {
                if candidate.subscriptions.shift_remove(&name).is_none() {
                    bail!("Unknown subscription");
                }
                if candidate.selected != "auto"
                    && !candidate
                        .nodes()
                        .iter()
                        .any(|node| node.id == candidate.selected)
                {
                    candidate.selected = "auto".into();
                }
            }
        },
        HelperCommand::Rule(command) => match command {
            RuleCommand::List => return output(&before.rules),
            RuleCommand::Add {
                kind,
                value,
                action,
            } => {
                let rule = config::make_rule(&kind, &value, &action)?;
                if !candidate.rules.contains(&rule) {
                    candidate.rules.push(rule);
                }
            }
            RuleCommand::Remove { index } => {
                if index == 0 || index > candidate.rules.len() {
                    bail!("Invalid rule index");
                }
                candidate.rules.remove(index - 1);
            }
        },
        HelperCommand::RuleRemoveMatch {
            kind,
            value,
            action,
        } => {
            let index = candidate
                .rules
                .iter()
                .position(|rule| rule.kind == kind && rule.value == value && rule.action == action)
                .context("Rule no longer exists; refresh and try again")?;
            candidate.rules.remove(index);
        }
        HelperCommand::Preset(command) => match command {
            PresetCommand::List => {
                return output(
                    &snapshot::from_state(&store.home, &before, json!({"state":"off"}))["presets"],
                );
            }
            PresetCommand::Add {
                name,
                source,
                interval,
            } => {
                valid_name(&name)?;
                if before.presets.contains_key(&name) {
                    bail!("Preset already exists");
                }
                candidate
                    .presets
                    .insert(name, sources::load_preset(&source, interval)?);
            }
            PresetCommand::Show { name } => {
                let preset = before.presets.get(&name).context("Unknown preset")?;
                return output(
                    &json!({"rules":preset.rules,"enabled":preset.enabled,"interval":preset.interval}),
                );
            }
            PresetCommand::Update { name } => {
                let names: Vec<_> = name
                    .map(|name| vec![name])
                    .unwrap_or_else(|| before.presets.keys().cloned().collect());
                for name in names {
                    let old = before.presets.get(&name).context("Unknown preset")?;
                    let mut new = sources::load_preset(&old.source, old.interval)?;
                    new.enabled = old.enabled;
                    new.extra = old.extra.clone();
                    candidate.presets.insert(name, new);
                }
            }
            PresetCommand::Remove { name } => {
                if candidate.presets.shift_remove(&name).is_none() {
                    bail!("Unknown preset");
                }
            }
            PresetCommand::Enable { name } => {
                candidate
                    .presets
                    .get_mut(&name)
                    .context("Unknown preset")?
                    .enabled = true
            }
            PresetCommand::Disable { name } => {
                candidate
                    .presets
                    .get_mut(&name)
                    .context("Unknown preset")?
                    .enabled = false
            }
        },
        HelperCommand::Dns(command) => match command {
            DnsCommand::Show => {
                return output(
                    &snapshot::from_state(&store.home, &before, json!({"state":"off"}))["dns"],
                );
            }
            DnsCommand::Set(options) => {
                for (key, value) in [
                    ("direct", options.direct),
                    ("proxy", options.proxy),
                    ("strategy", options.strategy),
                ] {
                    if let Some(value) = value.filter(|value| !value.is_empty()) {
                        validate_dns(key, &value)?;
                        candidate.dns.insert(key.into(), value);
                    }
                }
            }
        },
        HelperCommand::Geodata(command) => match command {
            GeodataCommand::Status => {
                return output(
                    &snapshot::from_state(&store.home, &before, json!({"state":"off"}))["geodata"],
                );
            }
            GeodataCommand::Update {
                geoip_url,
                geosite_url,
                interval,
            } => {
                for (kind, url) in [("geoip", geoip_url), ("geosite", geosite_url)] {
                    let old = before.geodata.get(kind);
                    let url=url.filter(|url|!url.is_empty()).or_else(||old.map(|asset|asset.url.clone())).unwrap_or_else(||format!("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{kind}.dat"));
                    let interval = interval
                        .filter(|value| *value != 0)
                        .or_else(|| old.map(|asset| asset.interval))
                        .filter(|value| *value != 0)
                        .unwrap_or(86400);
                    let mut asset =
                        sources::fetch_asset_with_core(&store.home, kind, &url, interval, core)?;
                    if let Some(old) = old {
                        asset.extra = old.extra.clone();
                    }
                    candidate.geodata.insert(kind.into(), asset);
                }
            }
        },
        HelperCommand::Latency {
            subscription,
            server,
        } => {
            return latency::run(
                &latency::nodes(&before, subscription.as_deref(), server.as_deref())?,
                &mut io::stdout().lock(),
            );
        }
        _ => unreachable!("early command dispatch"),
    }
    commit(store, core, before, candidate)
}
