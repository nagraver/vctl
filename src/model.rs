//! Persisted compatibility model. Secret-bearing fields never enter UI DTOs.
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub outbound: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Subscription {
    pub url: String,
    pub interval: u64,
    pub updated: f64,
    pub nodes: Vec<Node>,
    pub title: String,
    pub skipped: usize,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub kind: String,
    pub value: String,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Preset {
    pub source: String,
    pub interval: u64,
    pub updated: f64,
    pub enabled: bool,
    pub rules: Vec<Rule>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Preset {
    fn default() -> Self {
        Self {
            source: String::new(),
            interval: 43200,
            updated: 0.0,
            enabled: true,
            rules: Vec::new(),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
    pub updated: f64,
    pub interval: u64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    pub version: u32,
    pub subscriptions: IndexMap<String, Subscription>,
    pub rules: Vec<Rule>,
    pub selected: String,
    #[serde(rename = "default")]
    pub default_route: String,
    pub test_url: String,
    pub presets: IndexMap<String, Preset>,
    pub geodata: IndexMap<String, Asset>,
    pub dns: IndexMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            subscriptions: IndexMap::new(),
            rules: Vec::new(),
            selected: "auto".into(),
            default_route: "proxy".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            presets: IndexMap::new(),
            geodata: IndexMap::new(),
            dns: IndexMap::new(),
            extra: Map::new(),
        }
    }
}

impl State {
    pub fn nodes(&self) -> Vec<Node> {
        let mut seen = HashSet::new();
        self.subscriptions
            .values()
            .flat_map(|s| &s.nodes)
            .filter(|n| seen.insert(n.id.clone()))
            .cloned()
            .collect()
    }
}

pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
