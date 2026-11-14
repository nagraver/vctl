import SwiftUI
import AppKit

private enum Page: String, CaseIterable, Identifiable {
    case connection = "Connection", servers = "Servers", routing = "Routing", presets = "Presets", dns = "DNS", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .connection: return "network"
        case .servers: return "server.rack"
        case .routing: return "arrow.triangle.branch"
        case .presets: return "square.stack.3d.up"
        case .dns: return "globe"
        case .settings: return "gearshape"
        }
    }
}
enum EditorKind: String, Identifiable {
    case subscription = "Add subscription", rule = "Add routing rule", preset = "Add preset", dns = "Edit DNS", geodata = "Geodata sources"
    var id: String { rawValue }
}
private struct PendingAction {
    let title: String
    let message: String
    let arguments: [String]
    var admin = false
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @ViewState<Page?> private var page = .connection
    @ViewState<EditorKind?> private var editor = nil
    @ViewState<PendingAction?> private var pending = nil
    @ViewState<String> private var search = ""
    @ViewState<Set<String>> private var collapsedSubscriptions = []

    var body: some View {
        HStack(spacing: 0) {
            List(Page.allCases, selection: $page) { item in
                Label(item.rawValue, systemImage: item.icon).tag(item)
            }
            .listStyle(.sidebar)
            .frame(width: 200)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                if let statusError = model.statusError {
                    HStack {
                        Label(statusError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        Spacer()
                        Button("Retry") { Task { await model.refresh(reportErrors: true) } }
                    }.font(.callout).padding(16)
                    Divider()
                }
                if let snapshot = model.snapshot {
                    detail(snapshot).padding(24)
                } else {
                    VStack(spacing: 12) { ProgressView(); Text("Loading Whale…").foregroundStyle(.secondary) }.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                if let busy = model.busy {
                    Divider()
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small)
                        Text(busy)
                        Spacer()
                    }.font(.callout).padding(.horizontal, 20).padding(.vertical, 12)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .sheet(item: $editor) { kind in EditorSheet(kind: kind, snapshot: model.snapshot).environmentObject(model) }
        .sheet(isPresented: Binding(get: { model.details != nil }, set: { if !$0 { model.details = nil } })) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Details").font(.title2.bold())
                ScrollView { Text(model.details ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                HStack { Spacer(); Button("Done") { model.details = nil }.keyboardShortcut(.defaultAction) }
            }.padding(24).frame(width: 680, height: 460)
        }
        .alert("Whale", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .confirmationDialog(pending?.title ?? "Confirm", isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }), titleVisibility: .visible) {
            if let action = pending {
                Button(action.title, role: .destructive) { model.perform(action.title, action.arguments, admin: action.admin); pending = nil }
            }
            Button("Cancel", role: .cancel) { pending = nil }
        } message: { Text(pending?.message ?? "") }
    }

    @ViewBuilder private func detail(_ s: Snapshot) -> some View {
        switch page ?? .connection {
        case .connection: connection(s)
        case .servers: servers(s)
        case .routing: routing(s)
        case .presets: presets(s)
        case .dns: dns(s)
        case .settings: settings(s)
        }
    }
    private func connection(_ s: Snapshot) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 18) {
                    Image(systemName: s.tun.state == "on" ? "checkmark.shield.fill" : "shield.lefthalf.filled").font(.system(size: 48)).foregroundStyle(s.tun.state == "on" ? Color.green : Color.accentColor)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(s.tun.title).font(.largeTitle.bold())
                        Text(s.serverName).foregroundStyle(.secondary)
                        if s.tun.active, let applied = s.tun.applied_selected, applied != s.selected {
                            Text("Selected: \(s.desiredServerName ?? s.selected) · waiting to apply").font(.caption).foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                    Button(s.tun.canDisconnect ? "Disconnect" : "Connect") { model.tunnel(s.tun.canDisconnect ? "down" : "up") }
                        .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy != nil || s.tun.connection_state == "stopping" || (!s.tun.canDisconnect && (model.statusError != nil || s.nodes.isEmpty)))
                }.padding(.vertical, 12)
                if let error = s.tun.error, !error.isEmpty {
                    Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                GroupBox("System VPN") {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Routes traffic from your Mac through the selected server. Direct rules bypass the VPN.").foregroundStyle(.secondary)
                        Picker("Server", selection: Binding(get: { s.selected }, set: { model.perform("Selecting server…", ["use", $0]) })) {
                            Text("Automatic selection").tag("auto")
                            ForEach(s.nodes) { Text($0.name).tag($0.id) }
                        }.disabled(model.busy != nil || s.nodes.isEmpty)
                        HStack {
                            Button("Reconnect") { model.tunnel("restart") }.disabled(!s.tun.active || model.busy != nil)
                            Spacer()
                            Text("Administrator approval is needed for initial setup").font(.caption).foregroundStyle(.secondary)
                        }
                    }.padding(12)
                }
                if s.nodes.isEmpty {
                    Label("Add a subscription to connect.", systemImage: "info.circle").foregroundStyle(.secondary)
                    Button("Add subscription") { editor = .subscription }
                }
                Text("Closing this window leaves the VPN running. Use Disconnect or whale down to stop it.").font(.callout).foregroundStyle(.secondary)
            }
        }
    }
    private func servers(_ s: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                TextField("Search servers", text: $search).textFieldStyle(.roundedBorder)
                Button { editor = .subscription } label: { Label("Add subscription", systemImage: "plus") }.disabled(model.busy != nil)
                Button(model.pinging ? "Stop" : "Ping all") {
                    if model.pinging { model.stopPing() } else { model.ping() }
                }.disabled(!model.pinging && (model.busy != nil || s.nodes.isEmpty))
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    if s.subscriptions.isEmpty {
                        Text("Add a subscription to see its servers.").foregroundStyle(.secondary).padding(.vertical, 24)
                    }
                    ForEach(s.subscriptions) { sub in
                        subscriptionGroup(sub, snapshot: s)
                    }
                }
            }
        }
    }
    private func subscriptionGroup(_ sub: Subscription, snapshot s: Snapshot) -> some View {
        let matches = sub.nodes.filter { search.isEmpty || sub.name.localizedCaseInsensitiveContains(search) || $0.name.localizedCaseInsensitiveContains(search) }
        let expanded = !search.isEmpty || !collapsedSubscriptions.contains(sub.commandName)
        return Group {
            if search.isEmpty || !matches.isEmpty {
                GroupBox {
                    VStack(spacing: 0) {
                        HStack(spacing: 12) {
                            Button {
                                withAnimation(.easeInOut(duration: 0.16)) {
                                    if expanded { collapsedSubscriptions.insert(sub.commandName) } else { collapsedSubscriptions.remove(sub.commandName) }
                                }
                            } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: "chevron.right")
                                        .font(.system(size: 14, weight: .semibold))
                                        .rotationEffect(.degrees(expanded ? 90 : 0))
                                        .frame(width: 30, height: 30)
                                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(sub.name).font(.headline)
                                        if let skipped = sub.skipped, skipped > 0 {
                                            Text("\(skipped) unsupported servers skipped").font(.caption).foregroundStyle(.orange)
                                        }
                                        Text("\(sub.nodes.count) servers · updated \(Date(timeIntervalSince1970: sub.updated).formatted(date: .abbreviated, time: .shortened))")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer(minLength: 0)
                                }.padding(.vertical, 8).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                            .accessibilityLabel("\(expanded ? "Collapse" : "Expand") \(sub.name)")
                            Button("Ping") { model.ping(subscription: sub.commandName) }.disabled(model.pinging || model.busy != nil || sub.nodes.isEmpty)
                            Button("Update") { model.perform("Updating subscription…", ["sub", "update", sub.commandName]) }.disabled(model.busy != nil)
                            Button(role: .destructive) {
                                pending = PendingAction(title: "Remove subscription", message: "Remove \(sub.name) and its servers?", arguments: ["sub", "remove", sub.commandName])
                            } label: { Image(systemName: "trash") }.disabled(model.busy != nil)

                        }
                        if expanded {
                        VStack(spacing: 0) {
                            ForEach(matches) { node in
                                Divider()
                                HStack(spacing: 12) {
                                    Image(systemName: s.selected == node.id ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(s.selected == node.id ? Color.green : Color.secondary)
                                    Text(node.name).frame(maxWidth: .infinity, alignment: .leading)
                                    Text(node.protocol).foregroundStyle(.secondary).frame(width: 55)
                                    Text(model.latency[node.id] ?? (model.pendingPingIDs.contains(node.id) ? "…" : "—"))
                                        .monospacedDigit().frame(width: 90, alignment: .trailing)
                                    Button("Ping") { model.ping(subscription: sub.commandName, server: node.id) }
                                        .disabled(model.pinging || model.busy != nil)
                                    Button(s.selected == node.id ? "Selected" : "Select") { model.perform("Selecting server…", ["use", node.id]) }
                                        .disabled(model.busy != nil || s.selected == node.id).frame(width: 75)
                                }.padding(.vertical, 10)
                            }
                            if matches.isEmpty { Text("No servers in this subscription.").foregroundStyle(.secondary).padding() }
                        }.padding(.top, 10)

                        }
                    }.padding(10)
                }
            }
        }
    }
    private func routing(_ s: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker("Default route", selection: Binding(get: { s.defaultRoute }, set: { model.perform("Updating default route…", ["default", $0]) })) {
                Text("All traffic through VPN").tag("proxy")
                Text("Direct unless a rule uses VPN").tag("direct")
            }.pickerStyle(.segmented).disabled(model.busy != nil)
            HStack { Button { editor = .rule } label: { Label("Add rule", systemImage: "plus") }.disabled(model.busy != nil); Spacer(); Text("First matching rule wins").foregroundStyle(.secondary) }
            Table(s.rules) {
                TableColumn("Type", value: \.kind).width(85)
                TableColumn("Value", value: \.value)
                TableColumn("Route", value: \.action).width(70)
                TableColumn("") { rule in
                    Button(role: .destructive) { pending = PendingAction(title: "Remove rule", message: "Remove \(rule.kind) \(rule.value) → \(rule.action)?", arguments: ["rule-remove-match", rule.kind, rule.value, rule.action]) } label: { Image(systemName: "trash") }.disabled(model.busy != nil)
                }.width(30)
            }
            Text("Application rules apply to the system VPN. A website may need exceptions for additional domains that host its scripts and images.").font(.callout).foregroundStyle(.secondary)
        }
    }
    private func presets(_ s: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Button { editor = .preset } label: { Label("Add preset", systemImage: "plus") }; Button("Update all") { model.perform("Updating presets…", ["preset", "update"]) }; Spacer() }.disabled(model.busy != nil)
            List(s.presets) { preset in
                HStack {
                    Toggle(isOn: Binding(get: { preset.enabled }, set: { model.perform("Updating preset…", ["preset", $0 ? "enable" : "disable", preset.commandName]) })) {
                        VStack(alignment: .leading) { Text(preset.name).font(.headline); Text("\(preset.count) rules").foregroundStyle(.secondary) }
                    }.toggleStyle(.switch)
                    Spacer()
                    Button("Rules") { model.perform("Reading preset…", ["preset", "show", preset.commandName], showOutput: true) }
                    Button("Update") { model.perform("Updating preset…", ["preset", "update", preset.commandName]) }
                    Button(role: .destructive) { pending = PendingAction(title: "Remove preset", message: "Remove \(preset.name)?", arguments: ["preset", "remove", preset.commandName]) } label: { Image(systemName: "trash") }
                }.padding(.vertical, 6).disabled(model.busy != nil)
            }
        }
    }
    private func dns(_ s: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("DNS resolvers").font(.title2.bold())
            GroupBox {
                Form {
                    LabeledContent("Direct traffic", value: s.dns["direct"] ?? "")
                    LabeledContent("VPN traffic", value: s.dns["proxy"] ?? "")
                    LabeledContent("Address strategy", value: s.dns["strategy"] ?? "UseIP")
                }.padding(12)
            }
            Text("DNS-over-HTTPS is used for both routes. The system DNS is restored when the VPN disconnects.").foregroundStyle(.secondary)
            Button("Edit DNS") { editor = .dns }.disabled(model.busy != nil)
            Spacer()
        }
    }
    private func settings(_ s: Snapshot) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox("Application") {
                    VStack(alignment: .leading, spacing: 10) {
                        LabeledContent("Version", value: s.version)
                        LabeledContent("Profile", value: s.home).textSelection(.enabled)
                        Button("Open profile folder") { NSWorkspace.shared.open(URL(fileURLWithPath: s.home)) }
                        Text("Terminal commands: whale up · whale down · whale status").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    }.padding(12)
                }
                GroupBox("GeoIP / GeoSite") {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(["geoip", "geosite"], id: \.self) { kind in
                            LabeledContent(kind.uppercased(), value: s.geodata?[kind] == nil ? "Not installed" : "Installed")
                        }
                        HStack { Button("Update databases") { model.perform("Updating geodata…", ["geodata", "update"]) }; Button("Configure sources") { editor = .geodata } }
                    }.padding(12).disabled(model.busy != nil)
                }
                GroupBox("System service") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(s.tun.installed == true ? "Installed. macOS manages the VPN independently of this app." : "Installed automatically when you connect.").foregroundStyle(.secondary)
                        HStack {
                            Button("Install") { model.perform("Installing service…", ["_tun", "install"], admin: true) }.disabled(s.tun.active)
                            Button("Recover DNS") { model.perform("Recovering network settings…", ["_tun", "recover"], admin: true) }.disabled(s.tun.active)
                            Button("Uninstall service", role: .destructive) { pending = PendingAction(title: "Uninstall service", message: "Disconnect the system VPN and remove its service? Your profile will be kept.", arguments: ["_tun", "uninstall"], admin: true) }
                        }
                    }.padding(12).disabled(model.busy != nil)
                }
            }
        }
    }
}
