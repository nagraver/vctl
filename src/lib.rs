pub mod cli;
pub mod config;
pub mod dns;
pub mod latency;
pub mod model;
pub mod profiles;
pub mod runtime;
pub mod service;
pub mod snapshot;
pub mod sources;
pub mod store;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: u32 = 2;
