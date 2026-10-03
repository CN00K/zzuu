//  HIDBridgeMain.swift
//  [zzuu-jb] Hidden CLI surface of the main zzuu binary:
//    zzuu --zzuu-hid <base64 JSON>     → touch injection
//    zzuu --zzuu-uidump <base64 JSON>  → UI tree dump (self + inject path)
//  Root (over JB SSH) execs the app binary directly with these flags.
//  The app-side entrypoint calls this early in main before UIKit app init.
//
//  JSON schema for --zzuu-hid:
//    {"action":"tap","x":100,"y":200}
//    {"action":"double_tap","x":100,"y":200}
//    {"action":"long_press","x":100,"y":200,"duration":1.0}
//    {"action":"swipe","x":100,"y":600,"x2":100,"y2":200,"duration":0.3}
//    {"action":"pinch","x":200,"y":400,"scale":1.5,"duration":0.4}
//    {"action":"home"}
//    {"action":"type_text","text":"hello"}
//
//  JSON schema for --zzuu-uidump:
//    {"bundle_id":"", "max_depth":12}   // empty bundle_id = self dump

import Foundation

#if canImport(UIKit)
import UIKit

enum HIDBridge {

    /// Returns true if the argv was a zzuu bridge command (process should exit after).
    static func handleCLIArgs() -> Bool {
        let args = CommandLine.arguments
        guard args.count >= 3 else { return false }
        switch args[1] {
        case "--zzuu-hid":   runHID(payloadB64: args[2]); return true
        case "--zzuu-uidump": runUIDump(payloadB64: args[2]); return true
        default: return false
        }
    }

    // MARK: - HID injection

    private static func runHID(payloadB64: String) {
        guard let data = Data(base64Encoded: payloadB64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            FileHandle.standardError.write("BAD_PAYLOAD\n".data(using: .utf8)!)
            exit(2)
        }
        let action = obj["action"] as? String ?? ""
        let x = (obj["x"] as? NSNumber)?.doubleValue ?? 0
        let y = (obj["y"] as? NSNumber)?.doubleValue ?? 0
        let x2 = (obj["x2"] as? NSNumber)?.doubleValue ?? 0
        let y2 = (obj["y2"] as? NSNumber)?.doubleValue ?? 0
        let duration = (obj["duration"] as? NSNumber)?.doubleValue ?? 0
        let scale = (obj["scale"] as? NSNumber)?.doubleValue ?? 1.5
        let text = obj["text"] as? String ?? ""

        let inj = HIDTouchInjector.shared()
        switch action {
        case "tap":        inj.tap(at: CGPoint(x: x, y: y))
        case "double_tap": inj.doubleTap(at: CGPoint(x: x, y: y))
        case "long_press": inj.longPress(at: CGPoint(x: x, y: y), duration: duration)
        case "swipe":      inj.swipe(from: CGPoint(x: x, y: y), to: CGPoint(x: x2, y: y2), duration: duration)
        case "pinch":      inj.pinch(in: CGRect(x: x - 80, y: y - 80, width: 160, height: 160),
                                     scale: scale, angle: 0, duration: duration)
        case "home":       inj.pressHomeButton()
        case "type_text":  inj.typeText(text)
        default:
            FileHandle.standardError.write("UNKNOWN_ACTION \(action)\n".data(using: .utf8)!)
            exit(3)
        }
        // Let queued events flush before process exit.
        Thread.sleep(forTimeInterval: 0.3)
        print("HID_OK \(action)")
        exit(0)
    }

    // MARK: - UI dump

    private static func runUIDump(payloadB64: String) {
        guard let data = Data(base64Encoded: payloadB64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            FileHandle.standardError.write("BAD_PAYLOAD\n".data(using: .utf8)!)
            exit(2)
        }
        let bundleID = obj["bundle_id"] as? String ?? ""
        let maxDepth = (obj["max_depth"] as? NSNumber)?.intValue ?? 12

        if bundleID.isEmpty {
            // Self dump: current process owns its windows already.
            let json = zzuuDumpUITreeJSON(maxDepth)
            print(json ?? "UIDUMP_FAILED")
            exit(json == nil ? 4 : 0)
        }

        // Target dump: locate app, re-exec ITS binary with an injected dumper.
        // Strategy: find the .app, use posix_spawn with DYLD_INSERT_LIBRARIES
        // pointing at our dumper dylib (works with AMFI disabled on jb).
        let script = """
        APP=$(find /var/containers/Bundle/Application -maxdepth 3 -name "*.app" 2>/dev/null | while read A; do
          BID=$(defaults read "$A/Info.plist" CFBundleIdentifier 2>/dev/null)
          [ "$BID" = "\(bundleID)" ] && echo "$A" && break
        done | head -1)
        [ -z "$APP" ] && {{ echo "APP_NOT_FOUND"; exit 0; }}
        BIN=$(defaults read "$APP/Info.plist" CFBundleExecutable)
        DYLIB=/var/tmp/zzuu_uidumper.dylib
        [ -f "$DYLIB" ] || {{ echo "DUMPER_DYLIB_MISSING"; exit 0; }}
        # launch, wait for UI, dump, terminate
        open "$APP" 2>/dev/null || uiopen -b "\(bundleID)" 2>/dev/null
        sleep 3
        # The dumper writes /var/tmp/zzuu_uidump_<bid>.json on load
        if [ -f "/var/tmp/zzuu_uidump_\(bundleID).json" ]; then
          cat "/var/tmp/zzuu_uidump_\(bundleID).json"
        else
          echo "DUMP_NOT_PRODUCED"
        fi
        """
        // NOTE: this re-exec path is a fallback; primary path is frida or
        // dylib_inject + relaunch by the agent itself.
        print(script)
        exit(0)
    }
}

// Called from main before UIApplicationMain.
@inline(__always) func zzuuBridgeMain() {
    if HIDBridge.handleCLIArgs() {
        // handleCLIArgs exits on its own
        exit(0)
    }
}
#endif
