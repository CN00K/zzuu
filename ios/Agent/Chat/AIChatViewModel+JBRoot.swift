import Foundation

private let logger = AppLogger(category: "AIChatVM+JBRoot")

// MARK: - Root command execution on the jailbroken host
//
// [zzuu-jb] The `root_execute` tool path. Runs commands on the iOS host over
// local SSH (OpenSSH tweak) with root privileges. Design notes:
//
//  * Command transfer is base64-piped (`echo <b64> | base64 -d | /bin/sh`) so
//    multi-line scripts, quotes and backticks survive verbatim — no shell
//    escaping layer between the model and the host shell.
//  * Auth is key-only after linking (see JBLinker): the sandbox holds an
//    ed25519 private key; the password was used exactly once at link time and
//    never appears in any later command line or process argv.
//  * Execution reuses the iSH sandbox as the transport (its ssh client talks
//    to the device over loopback/LAN), so no new networking stack is added.
extension AIChatViewModel {

    /// Execute `command` as root on the jailbroken host.
    func executeRootCommand(_ command: String,
                            timeout: TimeInterval? = nil,
                            lineCallback: @escaping (String) -> Void) async throws -> CommandResult {
        let cfg = JailbreakConfigStore.shared
        guard cfg.isConfigured else {
            throw NSError(domain: "zzuu.jb", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Jailbreak SSH not configured"])
        }
        // Base64 the payload; decode+exec on the HOST side (dash + base64 ship
        // with iOS). Single-quoted remote program keeps everything literal.
        let b64 = Data(command.utf8).base64EncodedString()
        let remote = "'echo \(b64) | base64 -d | /bin/sh'"
        let wrapped = "ssh \(cfg.sshBaseArgs) -i \(JBLinker.jbKeyPath) \(cfg.sshTarget) \(remote)"
        let effectiveTimeout = timeout ?? defaultCommandTimeout

        logger.info("Executing ROOT command via JB SSH (timeout: \(Int(effectiveTimeout))s): \(command.prefix(200))")

        return try await executeCommand(wrapped, timeout: effectiveTimeout, lineCallback: lineCallback)
    }
}
