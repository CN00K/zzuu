import Foundation
import UIKit
import MachO

// MARK: - DirectKit
//
// [zzuu-direct] Post-SSH architecture: with TrollStore's platform-application
// + no-sandbox entitlements, zzuu's own process has system-grade read access.
// Everything JailbreakRunner did over SSH is now a direct in-process call.
// Single source of truth for all privileged operations.

enum DirectKit {

    // MARK: - App enumeration

    struct InstalledApp: Identifiable {
        let id = UUID()
        let bundleID: String
        let executable: String
        let name: String
        let bundlePath: String
        let dataContainer: String?
    }

    /// Enumerate user-installed apps by scanning /var/containers/Bundle/Application.
    /// With no-sandbox this is directly readable; Info.plist parsed via
    /// NSDictionary(contentsOfFile:) which handles binary plists natively.
    static func listInstalledApps() -> [InstalledApp] {
        let fm = FileManager.default
        let roots = [
            "/var/containers/Bundle/Application",
            "/var/containers/Bundle/Application/.apps",  // some jailbreak layouts
        ]
        var seen = Set<String>()
        var out: [InstalledApp] = []
        for root in roots {
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for uuid in entries {
                let dir = root + "/" + uuid
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else { continue }
                guard let appEntries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
                for e in appEntries where e.hasSuffix(".app") {
                    let appPath = dir + "/" + e
                    let plistPath = appPath + "/Info.plist"
                    guard let info = NSDictionary(contentsOfFile: plistPath) as? [String: Any] else { continue }
                    guard let bid = info["CFBundleIdentifier"] as? String,
                          let bin = info["CFBundleExecutable"] as? String else { continue }
                    guard !seen.contains(bid) else { continue }
                    seen.insert(bid)
                    let name = (info["CFBundleDisplayName"] as? String)
                            ?? (info["CFBundleName"] as? String)
                            ?? bin
                    out.append(InstalledApp(
                        bundleID: bid,
                        executable: bin,
                        name: name,
                        bundlePath: appPath,
                        dataContainer: dataContainer(for: bid)))
                }
            }
        }
        return out.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// Locate an app's data container via MCMMetadataIdentifier plist scan.
    static func dataContainer(for bundleID: String) -> String? {
        let fm = FileManager.default
        let root = "/var/mobile/Containers/Data/Application"
        guard let entries = try? fm.contentsOfDirectory(atPath: root) else { return nil }
        for uuid in entries {
            let dir = root + "/" + uuid
            let meta = dir + "/.com.apple.mobile_container_manager.metadata.plist"
            guard let meta = NSDictionary(contentsOfFile: meta) as? [String: Any],
                  let mcid = meta["MCMMetadataIdentifier"] as? String,
                  mcid == bundleID else { continue }
            return dir
        }
        return nil
    }

    static func installedApp(for bundleID: String) -> InstalledApp? {
        listInstalledApps().first { $0.bundleID == bundleID }
    }

    // MARK: - Container read / write

    static func readContainerFile(_ relativePath: String, in container: String) -> Data? {
        let full = container + "/" + relativePath
        return FileManager.default.contents(atPath: full)
    }

    static func writeContainerFile(_ data: Data, to relativePath: String, in container: String) -> Bool {
        let full = container + "/" + relativePath
        let dir = (full as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return FileManager.default.createFile(atPath: full, contents: data)
    }

    static func listContainerFiles(_ container: String, depth: Int = 2, limit: Int = 200) -> [String] {
        var out: [String] = []
        let fm = FileManager.default
        let en = fm.enumerator(atPath: container)
        while let p = en?.nextObject() as? String {
            if out.count >= limit { break }
            if p.components(separatedBy: "/").count > depth + 1 { en?.skipDescendants(); continue }
            out.append(p)
        }
        return out
    }

    // MARK: - Process list (sysctl KERN_PROC_ALL)

    struct ProcInfo: Identifiable {
        let id = UUID()
        let pid: Int32
        let name: String
    }

    static func listProcesses() -> [ProcInfo] {
        var size: size_t = 0
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride)
        var sz = size
        guard sysctl(&mib, 3, &buffer, &sz, nil, 0) == 0 else { return [] }
        let count = sz / MemoryLayout<kinfo_proc>.stride
        return (0..<count).map { i in
            let p = buffer[i]
            let name = withUnsafeBytes(of: p.kp_proc.p_comm) { raw -> String in
                let cString = raw.bindMemory(to: CChar.self).baseURL.map { String(cString: $0) } ?? ""
                return cString
            }
            return ProcInfo(pid: p.kp_proc.p_pid, name: name.isEmpty ? "(unknown)" : name)
        }.sorted { $0.pid < $1.pid }
    }

    // MARK: - Keychain dump

    struct KeychainItem: Identifiable {
        let id = UUID()
        let service: String
        let account: String
        let dataLen: Int
    }

    /// Enumerate generic + internet passwords via SecItemCopyMatching with
    /// kSecMatchLimitAll. With our entitlements this returns device-wide rows.
    static func dumpKeychain(limit: Int = 300) -> [KeychainItem] {
        var out: [KeychainItem] = []
        for cls in [kSecClassGenericPassword, kSecClassInternetPassword] {
            var query: [String: Any] = [
                kSecClass as String: cls,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
            ]
            var result: AnyObject?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
                  let items = result as? [[String: Any]] else { continue }
            for item in items.prefix(limit) {
                let svc = item[kSecAttrService as String] as? String ?? ""
                let acct = item[kSecAttrAccount as String] as? String ?? ""
                let dlen = item[kSecAttrCreationDate as String] != nil ? 16 : 0
                out.append(KeychainItem(service: svc, account: acct, dataLen: dlen))
                if out.count >= limit { return out }
            }
            _ = query
        }
        return out
    }

    // MARK: - Mach-O info

    struct MachOInfo {
        let magic: String
        let arch: String
        let platforms: [String]
        let encryptions: [String]  // cryptid per arch slice
        let loadCommandCount: Int
    }

    static func machoInfo(binaryPath: String) -> MachOInfo? {
        guard var data = FileManager.default.contents(atPath: binaryPath), data.count > 32 else { return nil }
        let d = data as NSData
        let magicLE: UInt32 = d.subdata(with: NSRange(location: 0, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        var offset = 0
        var magic = ""
        var is64 = false
        switch magicLE {
        case 0xFEEDFACF: magic = "MH_MAGIC_64"; is64 = true
        case 0xFEEDFACE: magic = "MH_MAGIC_32"
        case 0xBEBAFECA: magic = "FAT (universal)"; return fatInfo(data)
        default: return nil
        }
        offset = is64 ? 32 : 28
        let ncmds: UInt32 = d.subdata(with: NSRange(location: 16, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        var platforms: [String] = []
        var cryptids: [String] = []
        var lc = 0
        while lc < Int(ncmds), offset + 8 <= data.count {
            let cmd: UInt32 = d.subdata(with: NSRange(location: offset, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
            let cmdsize: UInt32 = d.subdata(with: NSRange(location: offset + 4, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
            if cmdsize == 0 { break }
            if cmd == 0x32 { // LC_PLATFORM_BUILD_VERSION (0x32)
                if offset + 40 <= data.count {
                    let plat: UInt32 = d.subdata(with: NSRange(location: offset + 8, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
                    platforms.append(platformName(plat))
                }
            }
            if cmd == 0x21 { // LC_ENCRYPTION_INFO (32) / 0x2C (64)
                if offset + 24 <= data.count {
                    let cryptid: UInt32 = d.subdata(with: NSRange(location: offset + 16, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
                    cryptids.append("cryptid=\(cryptid)")
                }
            }
            offset += Int(cmdsize)
            lc += 1
        }
        return MachOInfo(magic: magic, arch: is64 ? "arm64" : "arm32",
                         platforms: platforms, encryptions: cryptids, loadCommandCount: Int(ncmds))
    }

    private static func fatInfo(_ data: Data) -> MachOInfo? {
        let d = data as NSData
        let nfat: UInt32 = d.subdata(with: NSRange(location: 4, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        var archs: [String] = []
        for i in 0..<min(Int(nfat.bigEndian), 4) {
            let off = 8 + i * 20
            guard off + 20 <= data.count else { break }
            let cputype: UInt32 = d.subdata(with: NSRange(location: off, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
            archs.append(cputype == 0x0100000C ? "arm64" : (cputype == 0x0000000C ? "arm" : String(cputype)))
        }
        return MachOInfo(magic: "FAT", arch: archs.joined(separator: "+"),
                         platforms: [], encryptions: [], loadCommandCount: 0)
    }

    private static func platformName(_ p: UInt32) -> String {
        switch p {
        case 2: return "iOS"
        case 6: return "macOS"
        case 7: return "tvOS"
        case 8: return "watchOS"
        default: return "plat-\(p)"
        }
    }

    // MARK: - Decrypted binary read (class-dump input)

    static func readBinary(_ app: InstalledApp, maxBytes: Int = 20_000_000) -> Data? {
        let path = app.bundlePath + "/" + app.executable
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        return try? fh.read(upToCount: maxBytes)
    }

    // MARK: - ObjC class list (in-process; for OTHER apps use inject)

    /// Class names from the target binary's __objc_classname sections via
    /// simple Mach-O section scan — no class-dump binary needed.
    static func objcClassNames(binaryPath: String, filter: String = "", limit: Int = 300) -> [String] {
        guard var data = FileManager.default.contents(atPath: binaryPath) else { return [] }
        // Find segment __TEXT, section __objc_classname via a crude scan of
        // the section headers. Returns raw class-name strings.
        let d = data as NSData
        let magicLE: UInt32 = d.subdata(with: NSRange(location: 0, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        guard magicLE == 0xFEEDFACF || magicLE == 0xCFFAEDFE else { return [] }
        let is64 = magicLE == 0xFEEDFACF
        var offset = is64 ? 32 : 28
        let ncmds: UInt32 = d.subdata(with: NSRange(location: 16, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        var names: [String] = []
        var lc = 0
        while lc < Int(ncmds), offset + 8 <= data.count {
            let cmd: UInt32 = d.subdata(with: NSRange(location: offset, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
            let cmdsize: UInt32 = d.subdata(with: NSRange(location: offset + 4, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
            if cmdsize == 0 { break }
            if cmd == 0x19 { // LC_SEGMENT_64
                let segName = String(data: d.subdata(with: NSRange(location: offset + 8, length: 16)), encoding: .ascii) ?? ""
                if segName.hasPrefix("__TEXT") {
                    let nsects: UInt32 = d.subdata(with: NSRange(location: offset + 64, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
                    var so = offset + 72
                    for _ in 0..<min(Int(nsects), 32) {
                        let sectName = String(data: d.subdata(with: NSRange(location: so, length: 16)), encoding: .ascii) ?? ""
                        if sectName.hasPrefix("__objc_classname") {
                            let size: UInt32 = d.subdata(with: NSRange(location: so + 40, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
                            let addrOff: UInt32 = d.subdata(with: NSRange(location: so + 48, length: 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
                            if Int(addrOff) + Int(size) <= data.count {
                                let blob = d.subdata(with: NSRange(location: Int(addrOff), length: Int(size)))
                                for chunk in blob.components(separatedBy: [0]) {
                                    if let n = String(data: chunk, encoding: .utf8), !n.isEmpty {
                                        if filter.isEmpty || n.localizedCaseInsensitiveContains(filter) {
                                            names.append(n)
                                            if names.count >= limit { return names }
                                        }
                                    }
                                }
                            }
                        }
                        so += 80 // section_64 header size
                    }
                }
            }
            offset += Int(cmdsize)
            lc += 1
        }
        return names
    }

    // MARK: - Spawn helper (frida-server etc.)

    @discardableResult
    static func spawnDetached(_ path: String, args: [String] = []) -> Bool {
        var argv: [String] = [path] + args
        let cArgs = argv.map { strdup($0) } + [nil]
        var pid: pid_t = 0
        let r = posix_spawn(&pid, path, nil, nil, cArgs, environ)
        for p in cArgs where p != nil { free(p) }
        return r == 0
    }

    static func fridaServerPath() -> String? {
        let candidates = ["/var/jb/usr/bin/frida-server", "/usr/bin/frida-server"]
        return candidates.first { FileManager.default.fileExists(atPath: $0) }
    }

    static func fridaRunning() -> Bool {
        !listProcesses().filter { $0.name.contains("frida-server") }.isEmpty
    }

    // MARK: - Backup

    static func backupContainer(_ app: InstalledApp) -> String? {
        guard let cont = app.dataContainer else { return nil }
        let stamp = Int(Date().timeIntervalSince1970)
        let dest = "/var/mobile/zzuu_backups/\(app.bundleID)_\(stamp).tar.gz"
        try? FileManager.default.createDirectory(atPath: "/var/mobile/zzuu_backups", withIntermediateDirectories: true)
        // tar via Process? no-sandbox allows /usr/bin/tar — but iOS ships bsdtar as "tar".
        let tar = spawnDetached("/usr/bin/tar", args: ["czf", dest, "-C", cont, "."])
        return tar ? dest : nil
    }
}


// MARK: - App launch

/// Opens an app via uiopen (shipped with jailbreaks) or openUrl fallback.
func openAppViaFBS(_ bundleID: String) -> Bool {
    let candidates = ["/usr/bin/uiopen", "/var/jb/usr/bin/uiopen"]
    for c in candidates where FileManager.default.fileExists(atPath: c) {
        return DirectKit.spawnDetached(c, args: ["-b", bundleID])
    }
    // Fallback: URL scheme open for known apps (limited but zero-dep).
    if let url = URL(string: "shortcuts://run-shortcut?name=zzuu_open&input=text&text=" + bundleID) {
        return UIApplication.shared.open(url)
    }
    return false
}
