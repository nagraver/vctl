import Foundation

struct Server: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let subscription: String
    let `protocol`: String
}
struct Subscription: Decodable, Identifiable {
    let skipped: Int?
    let key: String?
    var commandName: String { key ?? name }
    var id: String { commandName }
    let name: String
    let count: Int
    let nodes: [Server]
    let interval: Int
    let updated: Double
}
struct RouteRule: Decodable, Identifiable {
    var id: String { [kind, value, action].joined(separator: "\u{0}") }
    let kind: String
    let value: String
    let action: String
}
struct Preset: Decodable, Identifiable {
    let key: String?
    var commandName: String { key ?? name }
    var id: String { commandName }
    let name: String
    let source: String
    let enabled: Bool
    let count: Int
    let interval: Int
}
struct Connection: Decodable {
    let state: String
    let installed: Bool?
    let error: String?
    let applied_selected: String?
    let connection_state: String?
    var active: Bool { state == "on" || state == "starting" || connection_state == "stopping" }
    var canDisconnect: Bool { active || (state == "unknown" && installed == true) }
    var title: String {
        if connection_state == "stopping" { return "Disconnecting" }
        if connection_state == "failed" { return "Connection failed" }
        switch state {
        case "on": return "Connected"
        case "off": return "Disconnected"
        case "starting": return "Connecting"
        default: return "Status unavailable"
        }
    }
}
struct Asset: Decodable {
    let url: String
    let sha256: String
    let updated: Double
    let interval: Int
    let redacted: Bool?
}
struct Snapshot: Decodable {
    let `protocol`: Int
    let version: String
    let home: String
    let selected: String
    let serverName: String
    let desiredServerName: String?
    let defaultRoute: String
    let nodes: [Server]
    let subscriptions: [Subscription]
    let rules: [RouteRule]
    let presets: [Preset]
    let dns: [String: String]
    let dnsRedacted: Bool?
    let geodata: [String: Asset]?
    let tun: Connection
}

struct HelperFailure: LocalizedError {
    let text: String
    var errorDescription: String? { text }
}

enum Backend {
    static let protocolVersion = 2
    static var helper: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/whale-helper")
    }
    static var home: String {
        ["WHALE_HOME", "VCTL_HOME"].compactMap { ProcessInfo.processInfo.environment[$0] }.first { !$0.isEmpty } ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/vctl").path
    }
    static func decodeSnapshot(_ data: Data) throws -> Snapshot {
        let snapshot = try JSONDecoder().decode(Snapshot.self, from: data)
        guard snapshot.protocol == protocolVersion else { throw HelperFailure(text: "This helper version is incompatible. Rebuild or reinstall Whale.") }
        return snapshot
    }
    static func validateController(_ data: Data) throws {
        let reply = try JSONDecoder().decode(ControllerStatus.self, from: data)
        guard reply.protocol == protocolVersion, reply.ready else { throw HelperFailure(text: "The system helper needs an upgrade.") }
    }
    static func requiresControllerInstallation(action: String, compatible: Bool) -> Bool {
        action == "install" || !compatible
    }
    static func geodataArguments(geoip: String, geosite: String, interval: String, original: [String: Asset]?) -> [String] {
        var args = ["geodata", "update"]
        if geoip != original?["geoip"]?.url { args += ["--geoip-url", geoip] }
        if geosite != original?["geosite"]?.url { args += ["--geosite-url", geosite] }
        let previousInterval = original?["geoip"]?.interval ?? original?["geosite"]?.interval ?? 86400
        if interval != String(previousInterval) { args += ["--interval", interval] }
        return args
    }
    // Quote each argument independently. No user data is evaluated as shell code.
    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    static func appleQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r") + "\""
    }
    static func run(_ arguments: [String], input: String? = nil, administrator: Bool = false) async throws -> Data {
        if administrator, arguments.first == "_tun", arguments.count == 2 {
            let action = arguments[1]
            var compatible = false
            if action != "install" {
                do { try validateController(try await rawRun(["controller-status"])); compatible = true }
                catch { compatible = false }
            }
            if requiresControllerInstallation(action: action, compatible: compatible) {
                _ = try await rawRun(["_controller-install"], administrator: true)
            }
            if action == "install" { return try await rawRun(["controller-status"]) }
            return try await rawRun(["control", arguments[1]])
        }
        return try await rawRun(arguments, input: input, administrator: administrator)
    }
    private static func rawRun(_ arguments: [String], input: String? = nil, administrator: Bool = false) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            let process = Process()
            let args = ["--home", home] + arguments
            if administrator {
                let command = ([helper.path] + args).map(shellQuote).joined(separator: " ")
                process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                process.arguments = ["-e", "do shell script " + appleQuote(command) + " with administrator privileges"]
            } else {
                process.executableURL = helper
                process.arguments = args
            }
            let output = Pipe()
            let stdin = Pipe()
            process.standardOutput = output
            process.standardError = output
            process.standardInput = stdin
            try process.run()
            if let input { try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8)) }
            try? stdin.fileHandleForWriting.close()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                let message = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                throw HelperFailure(text: message.isEmpty ? "Operation failed (\(process.terminationStatus))." : message)
            }
            return data
        }.value
    }
}

private struct ControllerStatus: Decodable {
    let `protocol`: Int
    let version: String
    let ready: Bool
}

struct LatencyResult: Decodable {
    let id: String
    let milliseconds: Int
    let error: String?
}

extension Backend {
    static func latencyStream(subscription: String? = nil, server: String? = nil) -> AsyncThrowingStream<LatencyResult, Error> {
        AsyncThrowingStream { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = helper
            var args = ["--home", home, "latency"]
            if let subscription { args += ["--subscription", subscription] }
            if let server { args += ["--server", server] }
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = pipe
            process.standardInput = FileHandle.nullDevice
            do { try process.run() }
            catch { continuation.finish(throwing: error); return }
            continuation.onTermination = { _ in
                if process.isRunning { process.terminate() }
            }
            DispatchQueue.global(qos: .userInitiated).async {
                var buffer = Data()
                var messages = ""
                while true {
                    let data = pipe.fileHandleForReading.availableData
                    if data.isEmpty { break }
                    buffer.append(data)
                    while let newline = buffer.firstIndex(of: 10) {
                        let line = Data(buffer[..<newline])
                        buffer.removeSubrange(...newline)
                        if let result = try? JSONDecoder().decode(LatencyResult.self, from: line) {
                            continuation.yield(result)
                        } else { messages += String(decoding: line, as: UTF8.self) + "\n" }
                    }
                }
                process.waitUntilExit()
                if process.terminationStatus == 0 { continuation.finish() }
                else { continuation.finish(throwing: HelperFailure(text: messages.isEmpty ? "Latency check stopped." : messages.trimmingCharacters(in: .whitespacesAndNewlines))) }
            }
        }
    }
}
