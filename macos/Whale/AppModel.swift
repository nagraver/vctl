import SwiftUI
import AppKit

// Explicit wrapper type avoids the newer SDK State macro (not shipped with CLT).
typealias ViewState<Value> = SwiftUI.State<Value>

@MainActor
final class AppModel: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var busy: String?
    @Published var error: String?
    @Published var details: String?
    @Published var statusError: String?
    @Published var latency: [String: String] = [:]
    @Published var pinging = false
    @Published var pendingPingIDs: Set<String> = []
    private var pingTask: Task<Void, Never>?
    private var pingGeneration = UUID()
    private var refreshing = false

    func refresh(reportErrors: Bool = false) async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let data = try await Backend.run(["snapshot"])
            snapshot = try Backend.decodeSnapshot(data)
            statusError = nil
        } catch {
            statusError = "Status unavailable. The last displayed connection state may be out of date."
            if reportErrors || snapshot == nil { self.error = error.localizedDescription }
        }
    }
    func poll() async {
        await refresh()
        while !Task.isCancelled {
            do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { return }
            if busy == nil { await refresh() }
        }
    }
    func perform(_ label: String, _ args: [String], input: String? = nil, admin: Bool = false, showOutput: Bool = false) {
        Task {
            do {
                try await execute(label, args, input: input, admin: admin, showOutput: showOutput)
            } catch { self.error = error.localizedDescription }
        }
    }
    func execute(_ label: String, _ args: [String], input: String? = nil, admin: Bool = false, showOutput: Bool = false) async throws {
        guard busy == nil else { throw HelperFailure(text: "Wait for the current operation to finish.") }
        busy = label
        defer { busy = nil }
        let data = try await Backend.run(args, input: input, administrator: admin)
        if showOutput { details = String(decoding: data, as: UTF8.self) }
        await refresh(reportErrors: true)
    }
    func tunnel(_ action: String) {
        perform(action == "down" ? "Disconnecting VPN…" : "Connecting VPN…", ["_tun", action], admin: true)
    }
    func stopPing() {
        pingGeneration = UUID()
        pingTask?.cancel()
        pingTask = nil
        pinging = false
        pendingPingIDs = []
    }
    func ping(subscription: String? = nil, server: String? = nil) {
        guard !pinging, busy == nil else { return }
        let nodes = subscription.flatMap { name in snapshot?.subscriptions.first { $0.commandName == name }?.nodes } ?? snapshot?.nodes ?? []
        pendingPingIDs = Set(nodes.filter { server == nil || $0.id == server }.map(\.id))
        for id in pendingPingIDs { latency.removeValue(forKey: id) }
        pinging = true
        let generation = UUID()
        pingGeneration = generation
        pingTask = Task {
            defer { if pingGeneration == generation { pinging = false; pingTask = nil; pendingPingIDs = [] } }
            do {
                for try await result in Backend.latencyStream(subscription: subscription, server: server) {
                    guard !Task.isCancelled, pingGeneration == generation else { break }
                    pendingPingIDs.remove(result.id)
                    latency[result.id] = result.error ?? "\(result.milliseconds) ms"
                }
            } catch {
                if !Task.isCancelled, pingGeneration == generation { self.error = error.localizedDescription }
            }
        }
    }

}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"), let icon = NSImage(contentsOf: url) {
            NSApp.applicationIconImage = icon
        }
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil) }
        return true
    }
}

@main
struct WhaleApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()
    var body: some Scene {
        Window("Whale", id: "main") {
            ContentView().environmentObject(model).frame(minWidth: 780, minHeight: 540)
                .task { await model.poll() }
        }
        .defaultSize(width: 1020, height: 700)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("Refresh status") { Task { await model.refresh(reportErrors: true) } }.keyboardShortcut("r")
            }
        }
    }
}
