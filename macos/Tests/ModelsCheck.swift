import Foundation

@main struct ModelsCheck {
    static func main() throws {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        let snapshot = try Backend.decodeSnapshot(data)
        precondition(Set(snapshot.nodes.map(\.id)).count == snapshot.nodes.count)
        precondition(["on", "off", "starting", "unknown"].contains(snapshot.tun.state))
        precondition(Backend.shellQuote("a'b") == "'a'\\''b'")
        precondition(Backend.appleQuote("a\"b\\c\nd") == "\"a\\\"b\\\\c\\nd\"")
        var invalid = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        invalid["protocol"] = 1
        do {
            _ = try Backend.decodeSnapshot(JSONSerialization.data(withJSONObject: invalid))
            preconditionFailure("Accepted an incompatible helper protocol")
        } catch { }
        let failed = try JSONDecoder().decode(Connection.self, from: Data("{\"state\":\"unknown\",\"installed\":true,\"connection_state\":\"failed\"}".utf8))
        precondition(failed.canDisconnect, "A failed or stale runtime must still be stoppable")
        let named = try JSONDecoder().decode(Subscription.self, from: JSONSerialization.data(withJSONObject: ["key": "Original\n", "name": "Original", "count": 0, "nodes": [], "interval": 60, "updated": 0]))
        precondition(named.commandName == "Original\n" && named.name == "Original", "Display cleanup must preserve command identity")
        let assets = try JSONDecoder().decode([String: Asset].self, from: Data("""
        {"geoip":{"url":"https://example.org/ip.dat","sha256":"abc","updated":0,"interval":600,"redacted":true},"geosite":{"url":"https://example.org/site.dat","sha256":"def","updated":0,"interval":900,"redacted":true}}
        """.utf8))
        let unchanged = Backend.geodataArguments(geoip: assets["geoip"]!.url, geosite: assets["geosite"]!.url, interval: "600", original: assets)
        precondition(unchanged == ["geodata", "update"], "Unedited source credentials or intervals would be replaced")
        let changed = Backend.geodataArguments(geoip: "https://example.org/new.dat", geosite: assets["geosite"]!.url, interval: "1200", original: assets)
        precondition(changed == ["geodata", "update", "--geoip-url", "https://example.org/new.dat", "--interval", "1200"])
        try Backend.validateController(Data("{\"protocol\":2,\"version\":\"test\",\"ready\":true}".utf8))
        precondition(Backend.requiresControllerInstallation(action: "install", compatible: true), "Explicit repair must replace even a compatible controller")
        precondition(!Backend.requiresControllerInstallation(action: "up", compatible: true))
        precondition(Backend.requiresControllerInstallation(action: "down", compatible: false))
        do {
            try Backend.validateController(Data("{\"version\":\"legacy\",\"ready\":true}".utf8))
            preconditionFailure("Accepted a legacy controller")
        } catch { }
        print("Native snapshot, protocol, geodata preservation and argument quoting checks passed")
    }
}
