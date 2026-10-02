import Foundation
import Security

// MARK: - Jailbreak SSH configuration
//
// [zzuu-jb] Connection settings for the `root_execute` tool: SSH access to the
// jailbroken iOS host (OpenSSH tweak). The password is stored in the Keychain
// only; host/port/user live in UserDefaults. `isConfigured` gates the tool
// definition and the system-prompt bullet, so a device that was never linked
// never advertises the capability to the model.
final class JailbreakConfigStore: ObservableObject {
    static let shared = JailbreakConfigStore()

    @Published var host: String { didSet { UserDefaults.standard.set(host, forKey: "jb.host") } }
    @Published var port: Int { didSet { UserDefaults.standard.set(port, forKey: "jb.port") } }
    @Published var user: String { didSet { UserDefaults.standard.set(user, forKey: "jb.user") } }
    /// True once key-based auth has been verified against the device.
    @Published var linked: Bool { didSet { UserDefaults.standard.set(linked, forKey: "jb.linked") } }

    private init() {
        let d = UserDefaults.standard
        host = d.string(forKey: "jb.host") ?? ""
        port = d.object(forKey: "jb.port") as? Int ?? 22
        user = d.string(forKey: "jb.user") ?? "root"
        linked = d.bool(forKey: "jb.linked")
    }

    var isConfigured: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty && linked
    }

    var sshTarget: String { "\(user)@\(host)" }

    /// Common flags: key-only auth, no host-key prompts, quiet, liveness pings.
    var sshBaseArgs: String {
        "-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        + "-o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -p \(port)"
    }

    // MARK: - Password (Keychain, generic password item)

    private static let kcService = "com.zzuu.zero.jailbreak-ssh"

    func setPassword(_ password: String) {
        SecItemDelete(Self.query() as CFDictionary)
        var attrs = Self.query()
        attrs[kSecValueData as String] = Data(password.utf8)
        SecItemAdd(attrs as CFDictionary, nil)
    }

    func password() -> String? {
        var q = Self.query()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func clearPassword() { SecItemDelete(Self.query() as CFDictionary) }

    private static func query() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: "ssh",
        ]
    }

    func reset() {
        host = ""
        port = 22
        user = "root"
        linked = false
        clearPassword()
    }
}

// MARK: - Standalone runner (settings screen has no chat view model)
//
// Wraps ISHShellExecutor directly so linking/detection work outside a chat
// session. Every command issued here is self-bounding (nc -w, ssh
// ConnectTimeout, apk with network bounds), so no external watchdog is needed.
enum JailbreakRunner {
    struct Result {
        let output: String
        let exitCode: Int
    }

    static func run(_ command: String) async throws -> Result {
        try await withCheckedThrowingContinuation { cont in
            var resumed = false
            let finish: (Result?) -> Void = { res in
                guard !resumed else { return }
                resumed = true
                if let res { cont.resume(returning: res) }
                else {
                    cont.resume(throwing: NSError(
                        domain: "zzuu.jb", code: -2,
                        userInfo: [NSLocalizedDescriptionKey: "sandbox process creation failed"]))
                }
            }
            DispatchQueue.global(qos: .userInitiated).async {
                // `result` is non-optional (ISHShellCompletionCallback passes
                // a concrete ISHShellExecutionResult); combine outputs safely.
                let pid = ISHShellExecutor.executeCommand(command, lineCallback: nil, completion: { result in
                    finish(Result(
                        output: result.output + (result.errorOutput ?? ""),
                        exitCode: Int(result.exitCode)))
                })
                if pid < 0 { finish(nil) }
            }
        }
    }
}
