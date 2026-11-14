# Whale Rust architecture

The requested and selected scope is Rust application logic and CLI, retaining the native macOS SwiftUI interface and the external Xray transport engine. This is a control-plane rewrite, not a new VPN protocol implementation.

## Compatibility

macOS 13+; public commands `whale up/down/status`; helper process JSON/JSONL interface; profile schema 1 at `~/.config/vctl`, `WHALE_HOME` and `VCTL_HOME`; existing subscription ordering, legacy node identities, VLESS/Trojan transports, routing, presets, DNS, geodata and TCP latency. Preserve unknown profile fields. Never expose subscription URLs, credentials or generated engine JSON in snapshots or error output. Existing Go source remains as a compatibility reference during migration and is excluded from the production build.

## Boundaries

- `model`, `store`: serde models, validated schema, bounded reads, exclusive locks and durable atomic transactions. Profile operations run as the profile owner. Root never chowns or writes user-controlled profile paths.
- `profiles`, `config`, `sources`: bounded HTTPS downloads, strict URI/rule validation, deterministic Xray compiler, legacy IDs. Fetch before taking the write lock and merge under lock. A failed source cannot block unrelated edits.
- `service`, `runtime`, `dns`: fixed-action peer-authenticated Unix IPC and a single supervisor owning Xray. Root runtime, logs and DNS journal live under a root-owned service directory, never `profile/tun`. Controller protocol/version handshake forces deliberate upgrade from legacy controllers.
- `cli`, `snapshot`, `latency`: thin command adapters, redacted versioned snapshots, bounded TCP probes and cancellation.
- SwiftUI keeps native UI and authorization. Failed saves retain the form; failed polling marks status stale; desired and applied selections are distinct.

## Connection semantics

States are stopped, starting, connected, stopping and failed; native compatibility maps these to off/starting/on/unknown. Connected requires application-level readiness through the selected proxy, not launchd process existence. Status includes applied selection and last apply error. Validate proposed configuration with the bundled Xray before replacement. On failure, retain/restart the last known working configuration and report rollback failure without panicking. Reap owned children. Capture bounded diagnostics without secrets.

## Privileges and recovery

Keep the current locally distributed launchd installation model for this rewrite. Use immutable root-owned executable snapshots and fixed IPC actions; reject extra request fields, enforce bounded frames and timeouts, verify peer UID on both sides. Preserve deterministic service identity and handle legacy helper version mismatch. Store a durable DNS recovery journal before each network change; restore only changes still owned by Whale, retaining recovery data on failure. Treat user profile content as untrusted; privileged config is rebuilt from validated models. Downloads/automatic profile refresh run with dropped user privileges.

No automatic installation, live VPN interruption, system DNS change, publishing or overwriting an installed application is part of validation. Those require a separate controlled integration session. Build a local `.app` artifact and clearly report this test limit.

## Evidence and decisions

- Mature Rust clients separate daemon, CLI and GUI: https://github.com/mullvad/mullvadvpn-app/blob/main/docs/architecture.md
- Pin behavior to Xray v26.9.9 source: https://raw.githubusercontent.com/XTLS/Xray-core/v26.9.9/proxy/tun/README.md . macOS TUN does not install system DNS; maintain a transactional platform adapter. TCP acceptance is insufficient readiness evidence.
- macOS process routing is implemented in the pinned source: https://raw.githubusercontent.com/XTLS/Xray-core/v26.9.9/common/net/find_process_darwin.go
- NetworkExtension is a separate signed/provisioned architecture change, with selective proxy constraints: https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers and https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- Future signed distribution can use SMAppService: https://developer.apple.com/documentation/servicemanagement/smappservice . Not coupled to changing language.
- Concurrent first creation of a lock uses exclusive creation followed by opening an existing file. This avoids the Darwin `openat(O_CREAT)` race reproduced by our storage test and reported upstream: https://github.com/golang/go/issues/81246 . Lock and file validation remain mandatory.

## Validation

Rust unit tests cover parser compatibility, routing precedence, legacy profile preservation, malformed input, symlink rejection, concurrent storage transactions, state transitions and fixed IPC messages. Integration checks use loopback and fake engines, plus actual bundled Xray config validation. Compile Swift snapshot fixtures and build/sign the complete bundle. Run rustfmt and clippy. Real privileged TUN, reboot, sleep/wake and DNS recovery remain explicitly identified manual tests; passing unit tests does not prove these.
