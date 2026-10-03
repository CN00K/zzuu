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
// Password auth uses the OpenSSH-native SSH_ASKPASS mechanism: a small script
// echoes the password, ssh invokes it when it needs one. No sshpass, no
// expect, no quote-escaping layer — the password never appears in argv.
enum JBLinker {
    struct Outcome { let ok: Bool; let message: String }

    static let jbKeyPath = "/root/.ssh/id_ed25519_jb"

    static func sshBase(port: Int) -> String {
        "-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        + "-o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -p \(port)"
    }

    /// Stage the password + askpass script inside the sandbox. The script
    /// simply echoes the password (read from a 0600 file); ssh calls it via
    /// SSH_ASKPASS whenever it needs a password. Any password characters
    /// survive verbatim (base64 transport).
    static func stagePassword(_ password: String) async throws {
        let b64 = Data(password.utf8).base64EncodedString()
        let r = try await JailbreakRunner.run(
            "echo \(b64) | base64 -d > /tmp/.zzuu_jb_pw && chmod 600 /tmp/.zzuu_jb_pw && "
            + "printf '#!/bin/sh\\ncat /tmp/.zzuu_jb_pw\\n' > /tmp/.zzuu_askpass && chmod 700 /tmp/.zzuu_askpass && echo ASKPASS_OK")
        guard r.output.contains("ASKPASS_OK") else {
            throw NSError(domain: "zzuu.jb", code: -6,
                userInfo: [NSLocalizedDescriptionKey: "Failed to stage password: \(r.output.suffix(200))"])
        }
    }

    /// Password-auth ssh via SSH_ASKPASS. DISPLAY forces askpass mode even
    /// without a TTY; setsid detaches from the controlling terminal so ssh
    /// cannot prompt interactively (it must use SSH_ASKPASS).
    static func pwSSHCmd(_ remote: String, port: Int, user: String, host: String) -> String {
        "/bin/sh -c \"DISPLAY=:0 SSH_ASKPASS=/tmp/.zzuu_askpass SSH_ASKPASS_REQUIRE=force setsid ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -p \(port) \(user)@\(host) '\(remote)'\""
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
            try await stagePassword(password)

            // 1) Probe with password auth (key not installed yet on first Link).
            let probe = try await JailbreakRunner.run(
                pwSSHCmd("echo PORT_OK", port: port, user: user, host: host) + " 2>&1 || echo PORT_FAIL")
            guard probe.output.contains("PORT_OK") else {
                let denied = probe.output.contains("Permission denied")
                return Outcome(ok: false,
                    message: denied
                        ? "Password rejected by sshd. Check the SSH password on the device."
                        : "Cannot reach \(host):\(port). \(probe.output.suffix(180))")
            }

            // 2) Push the pubkey: pipe the key file over ssh stdin. The key
            //    text never appears in any command line.
            let push = try await JailbreakRunner.run(
                "/bin/sh -c \"cat /root/.ssh/id_ed25519_jb.pub | DISPLAY=:0 SSH_ASKPASS=/tmp/.zzuu_askpass SSH_ASKPASS_REQUIRE=force setsid ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -p \(port) \(user)@\(host) 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo PUSH_OK'\" 2>&1 || echo PUSH_FAIL"
            )
            guard push.output.contains("PUSH_OK") else {
                return Outcome(ok: false,
                    message: "Key push failed. \(push.output.suffix(220))")
            }

            // 3) Verify key-only auth works.
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
