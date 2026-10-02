import SwiftUI

// MARK: - Settings › Jailbreak SSH
//
// [zzuu-jb] Configure + verify the root_execute channel to the jailbroken
// host. Flow: fill host/port/user → enter password → Link (pushes the
// sandbox pubkey once) → Test. After linking, no password is ever needed.
struct JailbreakSettingsView: View {
    @ObservedObject private var cfg = JailbreakConfigStore.shared
    @State private var password = ""
    @State private var status: String?
    @State private var statusOK = false
    @State private var busy = false

    var body: some View {
        Form {
            Section("Host") {
                TextField("127.0.0.1", text: $cfg.host)
                    .autocorrectionDisabled()
                Stepper("Port: \(cfg.port)", value: $cfg.port, in: 1...65535)
                TextField("root", text: $cfg.user)
                    .autocorrectionDisabled()
            }

            Section {
                if cfg.linked {
                    Label("Linked (key auth)", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else {
                    Label("Not linked", systemImage: "exclamationmark.circle")
                        .foregroundStyle(.orange)
                }
            } footer: {
                Text("Linking pushes a key from the Linux sandbox into the device's authorized_keys using the password once. Afterwards all commands run key-only as root.")
            }

            if !cfg.linked {
                Section("Password (one-time)") {
                    SecureField("SSH password", text: $password)
                        .autocorrectionDisabled()
                }
            }

            Section {
                Button {
                    run { await linkOrTest(link: true) }
                } label: {
                    HStack {
                        if busy { ProgressView() }
                        Text(cfg.linked ? "Re-link" : "Link Device")
                            .frame(maxWidth: .infinity)
                    }
                }
                .disabled(busy || (!cfg.linked && password.isEmpty))

                Button {
                    run { await linkOrTest(link: false) }
                } label: {
                    HStack {
                        if busy { ProgressView() }
                        Text("Test Connection")
                            .frame(maxWidth: .infinity)
                    }
                }
                .disabled(busy || !cfg.linked)

                if let status {
                    Text(status)
                        .font(.footnote)
                        .foregroundStyle(statusOK ? Color.green : Color.red)
                        .textSelection(.enabled)
                }
            }

            if cfg.linked {
                Section {
                    Button("Forget Password", role: .destructive) {
                        cfg.clearPassword()
                    }
                    Button("Unlink", role: .destructive) {
                        cfg.reset()
                        status = nil
                    }
                }
            }
        }
        .navigationTitle("Jailbreak SSH")
    }

    private func run(_ op: @escaping () async -> Void) {
        busy = true
        Task {
            await op()
            busy = false
        }
    }

    @MainActor
    private func linkOrTest(link: Bool) async {
        // Stand-in view model access: linking lives on AIChatViewModel but is
        // stateless w.r.t. any session — route through a throwaway instance
        // would be wrong, so we call the static-ish path directly instead.
        if link {
            let r = await JBLinker.link(host: cfg.host, port: cfg.port, user: cfg.user,
                                        password: password)
            status = r.message
            statusOK = r.ok
            if r.ok { password = "" }
        } else {
            let r = await JBLinker.test(host: cfg.host, port: cfg.port, user: cfg.user)
            status = r.message
            statusOK = r.ok
        }
    }
}

// Stateless runner so the settings screen doesn't need a chat view model.
enum JBLinker {
    struct Outcome { let ok: Bool; let message: String }

    static let jbKeyPath = "~/.ssh/id_ed25519_jb"

    static func sshBase(port: Int) -> String {
        "-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        + "-o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -p \(port)"
    }

    static func ensureKey() async throws -> String {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let priv = dir.appendingPathComponent("id_ed25519_jb")
        if FileManager.default.fileExists(atPath: priv.path) {
            return try String(data: Data(contentsOf: dir.appendingPathComponent("id_ed25519_jb.pub")),
                              encoding: .utf8)!
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let gen = try await JailbreakRunner.run(
            "ssh-keygen -t ed25519 -N '' -f \(priv.path) -C zzuu-jb -q")
        if gen.exitCode != 0 {
            throw NSError(domain: "zzuu.jb", code: -3,
                          userInfo: [NSLocalizedDescriptionKey: "ssh-keygen failed: \(gen.output)"])
        }
        return try String(data: Data(contentsOf: dir.appendingPathComponent("id_ed25519_jb.pub")),
                          encoding: .utf8)!
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func test(host: String, port: Int, user: String) async -> Outcome {
        do {
            let _ = try await ensureKey()
            let r = try await JailbreakRunner.run(
                "ssh \(sshBase(port: port)) -i \(jbKeyPath) \(user)@\(host) 'echo OK $(uname -a | cut -c1-40)'")
            if r.output.contains("OK") {
                return Outcome(ok: true, message: r.output.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            return Outcome(ok: false, message: String(r.output.trimmingCharacters(in: .whitespacesAndNewlines).suffix(200)))
        } catch {
            return Outcome(ok: false, message: error.localizedDescription)
        }
    }

    static func link(host: String, port: Int, user: String, password: String) async -> Outcome {
        do {
            let pub = try await ensureKey()
            JailbreakConfigStore.shared.setPassword(password)

            let probe = try await JailbreakRunner.run(
                "nc -z -w 5 \(host) \(port) && echo PORT_OK || echo PORT_FAIL")
            if !probe.output.contains("PORT_OK") {
                return Outcome(ok: false,
                               message: "Cannot reach \(host):\(port) from the sandbox. Check host/port and that OpenSSH is running on the device.")
            }

            let pwFile = "/tmp/.zzuu_jb_pw"
            try Data(password.utf8).write(to: URL(fileURLWithPath: pwFile), options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pwFile)

            let expectScript = """
            #!/usr/bin/expect -f
            set timeout 30
            set pw [read [open /tmp/.zzuu_jb_pw r]]
            set pw [string trim $pw]
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p \(port) \(user)@\(host) "mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qF '\(pub)' ~/.ssh/authorized_keys 2>/dev/null || echo '\(pub)' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; echo KEY_INSTALLED"
            expect {
                -re "(?i)password:" { send "$pw\\r"; exp_continue }
                "KEY_INSTALLED" { exit 0 }
                timeout { exit 124 }
                eof { exit 0 }
            }
            """
            let scriptPath = "/tmp/.zzuu_jb_link.exp"
            try expectScript.write(toFile: scriptPath, atomically: true, encoding: .utf8)
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptPath)

            let install = try await JailbreakRunner.run(
                "apk add --no-cache expect >/dev/null 2>&1 || true\n"
                + "expect \(scriptPath); rc=$?; rm -f \(scriptPath) \(pwFile); exit $rc")
            if install.exitCode != 0 || !install.output.contains("KEY_INSTALLED") {
                return Outcome(ok: false,
                               message: "Password authentication failed or timed out. Output: \(install.output.suffix(300))")
            }

            let verify = try await JailbreakRunner.run(
                "ssh \(sshBase(port: port)) -i \(jbKeyPath) \(user)@\(host) 'echo ZZUU_KEY_OK'")
            if verify.output.contains("ZZUU_KEY_OK") {
                JailbreakConfigStore.shared.linked = true
                return Outcome(ok: true, message: "Linked. root_execute is now available — key-based auth verified.")
            }
            return Outcome(ok: false,
                           message: "Pubkey installed but key auth verification failed: \(verify.output.suffix(300))")
        } catch {
            return Outcome(ok: false, message: "Link error: \(error.localizedDescription)")
        }
    }
}
