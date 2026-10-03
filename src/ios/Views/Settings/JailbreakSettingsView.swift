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

    static let jbKeyPath = "/root/.ssh/id_ed25519_jb"

    static func sshBase(port: Int) -> String {
        "-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        + "-o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -p \(port)"
    }

        /// Ensure key in iSH sandbox /root/.ssh/ (NOT iOS filesystem).
    static func ensureKey() async throws -> String {
        let deps = try await JailbreakRunner.run(
            "which ssh-keygen >/dev/null 2>&1 && echo DEPS_OK || apk add --no-cache openssh-client >/dev/null 2>&1 && echo DEPS_OK")
        guard deps.output.contains("DEPS_OK") else {
            throw NSError(domain: "zzuu.jb", code: -5,
                userInfo: [NSLocalizedDescriptionKey: "Failed to install openssh-client. \(deps.output.suffix(200))"])
        }
        let gen = try await JailbreakRunner.run(
            "/bin/sh -c \"mkdir -p /root/.ssh && ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519_jb -C zzuu-jb -q\"")
        guard gen.exitCode == 0 else {
            throw NSError(domain: "zzuu.jb", code: -3,
                userInfo: [NSLocalizedDescriptionKey: "ssh-keygen failed: \(gen.output)"])
        }
        let read = try await JailbreakRunner.run("cat /root/.ssh/id_ed25519_jb.pub")
        guard read.exitCode == 0 else {
            throw NSError(domain: "zzuu.jb", code: -4,
                userInfo: [NSLocalizedDescriptionKey: "Cannot read pubkey: \(read.output)"])
        }
        return read.output.trimmingCharacters(in: .whitespacesAndNewlines)
    }


