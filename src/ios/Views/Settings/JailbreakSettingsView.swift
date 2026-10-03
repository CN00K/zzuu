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
            Section("Authentication") {
                if cfg.linked {
                    Label("Linked (key auth)", systemImage: "checkmark.shield")
                        .foregroundStyle(.green)
                    Button("Unlink", role: .destructive) {
                        cfg.reset()
                        status = "Unlinked."
                        statusOK = false
                    }
                } else {
                    SecureField("SSH password (used once)", text: $password)
                    Button {
                        busy = true
                        status = nil
                        Task {
                            let r = await linkOrTest(link: true)
                            status = r.message
                            statusOK = r.ok
                            busy = false
                        }
                    } label: {
                        if busy { ProgressView() } else { Text("Link Device") }
                    }
                    .disabled(busy || password.isEmpty)
                }
            }
            if let status {
                Section("Status") {
                    Text(status)
                        .font(.footnote)
                        .foregroundStyle(statusOK ? .green : .red)
                }
            }
            if !cfg.linked {
                Section {
                    Text("Linking pushes a key from the Linux sandbox into the device's authorized_keys using the password once. Afterwards all commands run key-only as root.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            Section("Test") {
                Button {
                    busy = true
                    status = nil
                    Task {
                        let r = await linkOrTest(link: false)
                        status = r.message
                        statusOK = r.ok
                        busy = false
                    }
                } label: {
                    if busy { ProgressView() } else { Text("Test Connection") }
                }
                .disabled(busy || !cfg.linked)
            }
            if cfg.linked {
                Section("What this enables") {
                    Text("root_execute: run commands on the jailbroken device as root (frida, dpkg, system logs, class-dump).")
                        .font(.footnote)
                }
            }
        }
        .navigationTitle("Jailbreak SSH")
    }

    private func linkOrTest(link: Bool) async -> JBLinker.Outcome {
        if link {
            return await JBLinker.link(host: cfg.host, port: cfg.port, user: cfg.user, password: password)
        } else {
            return await JBLinker.test(host: cfg.host, port: cfg.port, user: cfg.user)
        }
    }
}

// MARK: - JBLinker
//
// Stateless runner so the settings screen doesn't need a chat view model.
enum JBLinker {
    struct Outcome { let ok: Bool; let message: String }

    static let jbKeyPath = "/root/.ssh/id_ed25519_jb"

    static func sshBase(port: Int) -> String {
        "-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        + "-o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -p \(port)"
    }

    /// Ensure key in iSH sandbox /root/.ssh/ — all ops inside the sandbox.
    static func ensureKey() async throws -> String {
        // Install openssh-client if missing (provides ssh-keygen and ssh).
        let deps = try await JailbreakRunner.run(
            "which ssh-keygen >/dev/null 2>&1 && echo DEPS_OK || apk add --no-cache openssh-client >/dev/null 2>&1 && echo DEPS_OK")
        guard deps.output.contains("DEPS_OK") else {
            throw NSError(domain: "zzuu.jb", code: -5,
                userInfo: [NSLocalizedDescriptionKey: "Failed to install openssh-client in sandbox. \(deps.output.suffix(200))"])
        }
        // Reuse an existing key when present.
        let check = try await JailbreakRunner.run(
            "test -f /root/.ssh/id_ed25519_jb.pub && echo HAVE_KEY || echo NO_KEY")
        if check.output.contains("HAVE_KEY") {
            let read = try await JailbreakRunner.run("cat /root/.ssh/id_ed25519_jb.pub")
            guard read.exitCode == 0 else {
                throw NSError(domain: "zzuu.jb", code: -4,
                    userInfo: [NSLocalizedDescriptionKey: "Cannot read pubkey: \(read.output)"])
            }
            return read.output.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // Generate keypair inside the sandbox (sandbox path, NOT iOS FS).
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

    static func test(host: String, port: Int, user: String) async -> Outcome {
        do {
            let _ = try await ensureKey()
            let r = try await JailbreakRunner.run(
                "ssh \(sshBase(port: port)) -i \(jbKeyPath) \(user)@\(host) 'echo OK; uname -a'")
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

            // Probe reachability with ssh (nc/netcat may not exist in rootfs;
            // ssh is reliable once openssh-client is installed).
            let probe = try await JailbreakRunner.run(
                "ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p \(port) \(user)@\(host) 'echo PORT_OK' 2>&1 || echo PORT_FAIL")
            guard probe.output.contains("PORT_OK") else {
                return Outcome(ok: false,
                    message: "Cannot reach \(host):\(port). Check host/port and that OpenSSH is running on the device. Output: \(probe.output.suffix(180))")
            }

            // Push the pubkey using sshpass (already in rootfs; avoids the
            // expect dependency entirely).
            let inst = try await JailbreakRunner.run(
                "which sshpass >/dev/null 2>&1 && echo SP_OK || apk add --no-cache sshpass >/dev/null 2>&1 && echo SP_OK")
            guard inst.output.contains("SP_OK") else {
                return Outcome(ok: false,
                    message: "Failed to install sshpass in the sandbox. Output: \(inst.output.suffix(180))")
            }
            // Write the pubkey into the sandbox /tmp, then pipe it over ssh.
            let write = try await JailbreakRunner.run(
                "cat > /tmp/.zzuu_jb_pub << 'ZZEOF'\n\(pub)\nZZEOF\necho PUB_SAVED")
            guard write.output.contains("PUB_SAVED") else {
                return Outcome(ok: false, message: "Failed to stage pubkey: \(write.output.suffix(180))")
            }
            let push = try await JailbreakRunner.run(
                "/bin/sh -c \"sshpass -p '\(password)' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p \(port) \(user)@\(host) 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qF \"$(cat /tmp/.zzuu_jb_pub)\" ~/.ssh/authorized_keys 2>/dev/null || cat /tmp/.zzuu_jb_pub >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; echo KEY_INSTALLED'\"")
            guard push.output.contains("KEY_INSTALLED") else {
                return Outcome(ok: false,
                    message: "Key push failed. Check the password. Output: \(push.output.suffix(220))")
            }
            // Verify key-only auth works.
            let verify = try await JailbreakRunner.run(
                "ssh \(sshBase(port: port)) -i \(jbKeyPath) \(user)@\(host) 'echo ZZUU_KEY_OK'")
            guard verify.output.contains("ZZUU_KEY_OK") else {
                return Outcome(ok: false,
                    message: "Key installed but key-only auth failed: \(verify.output.suffix(180))")
            }
            JailbreakConfigStore.shared.linked = true
            return Outcome(ok: true, message: "Linked (key auth).")
        } catch {
            return Outcome(ok: false, message: "Link error: \(error.localizedDescription)")
        }
    }
}
