import SwiftUI
import AppKit

struct EditorSheet: View {
    let kind: EditorKind
    let snapshot: Snapshot?
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @ViewState<String> private var name = ""
    @ViewState<String> private var value = ""
    @ViewState<String> private var second = ""
    @ViewState<String> private var interval = "43200"
    @ViewState<String> private var ruleType = "suffix"
    @ViewState<String> private var route = "direct"
    @ViewState<String> private var strategy = "UseIP"
    @ViewState<String?> private var saveError = nil
    @ViewState<Bool> private var saving = false
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(kind.rawValue).font(.title2.bold())
            Form {
                switch kind {
                case .subscription:
                    SecureField("Subscription URL", text: $value)
                    TextField("Name (automatic if empty)", text: $name)
                    TextField("Update interval, seconds", text: $interval)
                case .rule:
                    Picker("Match", selection: $ruleType) {
                        ForEach(["suffix", "domain", "cidr", "geoip", "geosite", "process", "path"], id: \.self) { Text($0).tag($0) }
                    }
                    TextField("Value", text: $value)
                    if ruleType == "path" { Button("Choose application…") { chooseFile() } }
                    Picker("Route", selection: $route) { ForEach(["direct", "proxy", "block"], id: \.self) { Text($0).tag($0) } }
                    Text("Suffix matches a domain and all its subdomains. Process matches an executable name; path matches an application or executable path.").font(.caption).foregroundStyle(.secondary)
                case .preset:
                    TextField("Name", text: $name)
                    TextField("Source URL, file or builtin name", text: $value)
                    Button("Choose file…") { chooseFile() }
                    TextField("Update interval, seconds", text: $interval)
                case .dns:
                    TextField("Direct DNS", text: $value)
                    TextField("VPN DNS", text: $second)
                    Picker("Address strategy", selection: $strategy) { ForEach(["UseIP", "UseIPv4", "UseIPv6"], id: \.self) { Text($0).tag($0) } }
                    Text("Use an HTTPS URL with an IP address, such as https://1.1.1.1/dns-query.").font(.caption).foregroundStyle(.secondary)
                    if snapshot?.dnsRedacted == true { Text("Saved resolver credentials are hidden. Editing an address replaces its full URL.").font(.caption).foregroundStyle(.secondary) }
                case .geodata:
                    TextField("GeoIP URL", text: $value)
                    TextField("GeoSite URL", text: $second)
                    TextField("Update interval, seconds", text: $interval)
                    Text("Saving downloads both databases.").font(.caption).foregroundStyle(.secondary)
                    if snapshot?.geodata?.values.contains(where: { $0.redacted == true }) == true {
                        Text("Source credentials are hidden. Editing a source replaces its full URL.").font(.caption).foregroundStyle(.secondary)
                    }

                }
            }.textFieldStyle(.roundedBorder).disabled(saving)
            if let saveError { Label(saveError, systemImage: "exclamationmark.triangle").foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                if saving { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(saving)
                Button("Save") { save() }.keyboardShortcut(.defaultAction).disabled(!valid || model.busy != nil || saving)
            }
        }.padding(24).frame(width: 560).interactiveDismissDisabled(saving)
        .onAppear {
            if kind == .dns { value = snapshot?.dns["direct"] ?? "https://1.1.1.1/dns-query"; second = snapshot?.dns["proxy"] ?? value; strategy = snapshot?.dns["strategy"] ?? "UseIP" }
            if kind == .geodata {
                value = snapshot?.geodata?["geoip"]?.url ?? "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
                second = snapshot?.geodata?["geosite"]?.url ?? "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
                interval = String(snapshot?.geodata?["geoip"]?.interval ?? snapshot?.geodata?["geosite"]?.interval ?? 86400)
            }
        }
    }
    private var valid: Bool {
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        if kind == .subscription || kind == .preset || kind == .geodata {
            guard let seconds = Int(interval), seconds >= 60 else { return false }
        }
        if kind == .preset && name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        if (kind == .dns || kind == .geodata) && second.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return true
    }
    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = kind == .rule
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { value = url.path }
    }
    private func save() {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        var arguments: [String]
        var input: String? = nil
        switch kind {
        case .subscription:
            arguments = ["sub", "add"]
            let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedName.isEmpty { arguments.append(trimmedName) }
            arguments += ["--interval", interval]
            input = value + "\n"
        case .rule: arguments = ["rule", "add", ruleType, value, route]
        case .preset: arguments = ["preset", "add", name.trimmingCharacters(in: .whitespacesAndNewlines), value, "--interval", interval]
        case .dns:
            arguments = ["dns", "set", "--strategy", strategy]
            if value != snapshot?.dns["direct"] { arguments += ["--direct", value] }
            let proxy = second.trimmingCharacters(in: .whitespacesAndNewlines)
            if proxy != snapshot?.dns["proxy"] { arguments += ["--proxy", proxy] }
        case .geodata:
            arguments = Backend.geodataArguments(geoip: value, geosite: second.trimmingCharacters(in: .whitespacesAndNewlines), interval: interval, original: snapshot?.geodata)
        }
        saving = true
        saveError = nil
        Task {
            defer { saving = false }
            do {
                try await model.execute("Saving…", arguments, input: input)
                dismiss()
            } catch { saveError = error.localizedDescription }
        }
    }
}
