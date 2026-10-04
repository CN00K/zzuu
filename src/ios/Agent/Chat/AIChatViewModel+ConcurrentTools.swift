//
//  AIChatViewModel+ConcurrentTools.swift
//  MinisApp
//
//  Concurrent tool execution: dispatches up to `maxConcurrentTools` tool
//  calls in parallel via TaskGroup, waits for all to complete, then
//  returns results ordered to match the original tool_use sequence
//  (Anthropic API requires tool_result order to mirror tool_use order
//  within the same user message).
//
//  Created for T-concurrent-tools 2026-05-25.
//

import Foundation
import UIKit

private let ctLogger = AppLogger(category: "AIChatVM")

extension AIChatViewModel {

    /// Hard cap on simultaneous in-flight tool executions per agent turn.
    /// 10 is the requested ceiling; iSH itself can fan out further but
    /// concurrent shell forks on the emulator past this start to compete
    /// for emulator scheduling.
    static let maxConcurrentTools = 10

    /// Set-typed view of currently-running shell PIDs.
    ///
    /// Backed by the singular `runningCommandPid: Int32` slot on
    /// AIChatViewModel so `AIChatViewModel+ISHCommand`'s pidCallback
    /// (which assigns `runningCommandPid = pid`) keeps working
    /// unchanged. The stop button enumerates this Set to kill every
    /// in-flight shell across a concurrent batch. When per-task PID
    /// tracking lands this can be promoted to true Set storage with
    /// per-task insert/remove.
    ///
    /// [T-ios-concurrent-toolcall-dup-id]
    var runningCommandPids: Set<Int32> {
        get { runningCommandPid > 0 ? [runningCommandPid] : [] }
        set { runningCommandPid = newValue.first ?? 0 }
    }

    /// Tiny actor wrapping the per-turn image budget so concurrent tool
    /// tasks can race-free claim a slot for their image bytes.
    /// `reserveSlot()` returns true iff a slot was claimed; the caller
    /// then attaches `imageData` to its toolResult. False → caller must
    /// substitute a text placeholder.
    actor BatchImageBudget {
        private var remaining: Int
        private(set) var strippedCount: Int = 0

        init(initial: Int) { self.remaining = max(0, initial) }

        /// Claim one image slot. Returns true if granted.
        func reserveSlot() -> Bool {
            if remaining > 0 {
                remaining -= 1
                return true
            }
            strippedCount += 1
            return false
        }

        var strippedSoFar: Int { strippedCount }
    }

    /// Outcome of executing a single tool call. Collected by each child
    /// task and merged in original index order by the outer dispatcher.
    struct ToolExecOutcome {
        let toolId: String
        let toolName: String
        let resultPart: AgentContentPart            // .toolResult(...)
        let snapshotEntry: (toolName: String, snapshot: ToolSnapshot)?
        let snapshotItem: ToolSnapshotItem?
        let cancelled: Bool
    }

    /// Execute a single tool use, returning a self-contained outcome.
    /// All mutations to `messages[msgIdx].blocks[blockIdx]` happen inside
    /// (the VM is @MainActor so this is safe even when invoked from
    /// concurrent child tasks). The outcome carries the toolResult part,
    /// snapshot, and cancellation flag so the dispatcher can collect them
    /// in original tool_use order after every child task completes.
    func executeSingleToolUse(
        tu: StreamResult.ToolEntry,
        msgIdx: Int,
        tools: [AgentToolDefinition],
        batchBudget: BatchImageBudget
    ) async -> ToolExecOutcome {
        let blockIdx = tu.blockIdx

        // [T-perf-cpu-probe] Every tool call in the app funnels through this
        // function, so one pair of samples here covers them all — no per-tool
        // instrumentation to keep in sync as tools are added.
        //
        // `defer` rather than a call before each `return`: this function exits
        // from many places (early cancel checks, per-tool error paths, two
        // catch blocks), and a missed exit would silently drop the "after"
        // sample for exactly the failure cases most worth measuring.
        // [T-perf-cpu-probe] Identify WHICH conversation issued the call, not
        // just which tool ran. A sub agent reports its job id (and its agent
        // name, since several agents can share a tool and the name is what a
        // reader recognises); the main conversation reports its session id.
        // Without this, a `browser_use` line under concurrent sub agents says
        // the tool is expensive but not which agent is spending it.
        let perfJobId: String = {
            if let cfg = helperConfig {
                let name = cfg.subAgentName.isEmpty ? "builtin" : cfg.subAgentName
                return "\(name)#\(cfg.jobId.prefix(8))"
            }
            return "main:\(sessionId?.prefix(8) ?? "none")"
        }()
        let perfStarted = PerfProbe.toolBefore(tool: tu.name, job: perfJobId)
        defer { PerfProbe.toolAfter(tool: tu.name, job: perfJobId, started: perfStarted) }

        // Graceful cancel pre-check: any task that begins after the user
        // tapped Stop short-circuits with a synthetic cancellation result
        // so history stays paired.
        if Task.isCancelled || self.userDidCancel {
            let cancelContent = "<system-reminder>The user cancelled this operation. The returned result may be incomplete.</system-reminder>"
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].toolStatus = .cancelled
                messages[msgIdx].blocks[blockIdx].content = cancelContent
            }
            let cancelSnap = ToolSnapshot(type: .text, text: cancelContent, mediaRef: nil, duration: nil)
            let item = ToolSnapshotItem(
                id: tu.id, toolName: tu.name, snapshot: cancelSnap,
                mediaResolver: await ChatStore.shared.mediaFileURLResolver()
            )
            return ToolExecOutcome(
                toolId: tu.id, toolName: tu.name,
                resultPart: .toolResult(id: tu.id, name: tu.name, content: cancelContent, isError: true),
                snapshotEntry: (toolName: tu.name, snapshot: cancelSnap),
                snapshotItem: item,
                cancelled: true
            )
        }

        var toolOutput: String = ""
        var toolSuccess: Bool = false
        var toolImageData: Data?
        var toolImageMimeType: String?
        var toolImageLinuxPath: String?
        var toolPageURL: String?
        var cancelledHere = false

        // Loop-detector pre-check: short-circuit when the model is stuck
        // in a runaway pattern (unknown tool spam, no-progress polling, etc).
        let loopPreCheck = toolLoopDetector.check(toolName: tu.name, params: tu.args)
        if loopPreCheck.level == .critical, let blockedMsg = loopPreCheck.message {
            toolOutput = blockedMsg
            toolSuccess = false
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = blockedMsg
                messages[msgIdx].blocks[blockIdx].toolStatus = .failed(message: "loop blocked")
            }
            toolLoopDetector.record(
                toolName: tu.name, params: tu.args,
                result: nil, errorMessage: blockedMsg, toolCallId: tu.id
            )
            let blockedSnap = ToolSnapshot(type: .text, text: blockedMsg, mediaRef: nil, duration: nil)
            let item = ToolSnapshotItem(
                id: tu.id, toolName: tu.name, snapshot: blockedSnap,
                mediaResolver: await ChatStore.shared.mediaFileURLResolver()
            )
            return ToolExecOutcome(
                toolId: tu.id, toolName: tu.name,
                resultPart: .toolResult(id: tu.id, name: tu.name, content: blockedMsg, isError: true),
                snapshotEntry: (toolName: tu.name, snapshot: blockedSnap),
                snapshotItem: item,
                cancelled: false
            )
        }

        // JSON Repair (T-tool-json-repair b2c4f8a6).
        var toolArgs: [String: Any] = tu.args
        let needsRepair: Bool = {
            guard let toolDef = tools.first(where: { $0.name == tu.name }) else { return false }
            if tu.args.isEmpty && !toolDef.required.isEmpty { return true }
            for field in toolDef.required {
                guard let raw = tu.args[field] else { return true }
                if raw is NSNull { return true }
                if let s = raw as? String,
                   s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
                if !(raw is String) && !(raw is [Any]) && !(raw is [String: Any]) { return true }
            }
            return false
        }()
        // [T-truncated-args-visibility #119] Tracks whether THIS call's
        // arguments arrived truncated and were glued shut by the repair pass.
        // Non-nil ⇒ the args are not what the model actually emitted.
        var truncationRepairTag: String? = nil
        if needsRepair {
            let rawJoined = tu.inputChunkRing.joined()
            let repairOutcome = Self.repairToolArgs(
                name: tu.name, args: tu.args, rawTail: rawJoined, tools: tools
            )
            if !repairOutcome.repairs.isEmpty {
                AppLogger(category: "ToolPreflight").warning(
                    "[ToolRepair] REPAIRED tool=\(tu.name) id=\(tu.id) strategies=[\(repairOutcome.repairs.joined(separator: ", "))] beforeKeys=[\(tu.args.keys.sorted().joined(separator: ","))] afterKeys=[\(repairOutcome.args.keys.sorted().joined(separator: ","))] rawJoined=<<<\(rawJoined.prefix(500))>>>"
                )
                toolArgs = repairOutcome.args
                // Only the truncation strategy means "the value itself was cut
                // short". Type-coercion and fuzzy-name repairs fix the SHAPE of
                // a fully-received argument and are not a data-loss signal.
                truncationRepairTag = repairOutcome.repairs.first { $0.hasPrefix("truncation+") }
            }
        }

        // [T-truncated-args-visibility #119] Refuse to execute a WRITE whose
        // argument stream was truncated.
        //
        // The repair pass closes an unterminated JSON string by appending `"}`,
        // which for file_write is indistinguishable from the model having ended
        // `content` right there: the JSON parses, every required field is
        // present, preflight passes, and a HALF file lands on disk while both
        // the UI and the model's tool result report plain success. The user
        // finds a truncated file later; the model, seeing "success", keeps
        // building on it.
        //
        // For writes a partial artifact is strictly worse than none — it is
        // silent corruption of the user's data, and unlike a blocked call it
        // cannot be recovered by simply retrying. Read-only and shell tools
        // keep the existing repair-and-run behaviour: there the repaired call
        // is at worst a wasted round-trip, and refusing them would regress
        // recoveries that work today.
        if let tag = truncationRepairTag,
           tu.name == "file_write" || tu.name == "file_edit" {
            let path = (toolArgs["path"] as? String) ?? (toolArgs["file_path"] as? String) ?? ""
            AppLogger(category: "ToolPreflight").warning(
                "[ToolRepair] REFUSED truncated write tool=\(tu.name) id=\(tu.id) strategy=\(tag) path=\(path)"
            )
            let uiMessage = AppLocalized("Blocked: arguments were truncated in transit")
            let modelMessage = """
            Error: This call was NOT executed. Its argument stream was truncated in transit \
            (repair strategy: \(tag)), so the `content` your client sent was cut short and would \
            have written an incomplete file\(path.isEmpty ? "" : " to \(path)"). Nothing was \
            written to disk — the target file is unchanged.

            The most likely cause is the response hitting its output-token limit mid-argument. \
            Re-issue this write in smaller pieces: write the first part, then append the rest \
            with follow-up calls, rather than repeating the same oversized call.
            """
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = uiMessage
                messages[msgIdx].blocks[blockIdx].toolStatus = .failed(message: uiMessage)
            }
            toolLoopDetector.record(
                toolName: tu.name, params: tu.args,
                result: nil, errorMessage: modelMessage, toolCallId: tu.id
            )
            let refusedSnap = ToolSnapshot(type: .text, text: modelMessage, mediaRef: nil, duration: nil)
            let item = ToolSnapshotItem(
                id: tu.id, toolName: tu.name, snapshot: refusedSnap,
                mediaResolver: await ChatStore.shared.mediaFileURLResolver()
            )
            return ToolExecOutcome(
                toolId: tu.id, toolName: tu.name,
                resultPart: .toolResult(id: tu.id, name: tu.name, content: modelMessage, isError: true),
                snapshotEntry: (toolName: tu.name, snapshot: refusedSnap),
                snapshotItem: item,
                cancelled: false
            )
        }

        // [T-offload-placeholder-write-guard issue #374] Refuse to execute a
        // WRITE whose payload IS an offload placeholder.
        //
        // offloadContextIfNeeded rewrites a historical file_write's `content`
        // argument in `agentHistory` to the "[CONTEXT OFFLOADED] … saved to: …"
        // stub, to reclaim the tokens. That rewritten tool_use is what the model
        // sees from then on — so a call re-issued from it (a retry, a resumed
        // pending call, the model copying its own earlier call) carries the
        // ~130-char stub where the real file body used to be. Nothing in the
        // write path could tell the difference: the args are complete and
        // well-formed, so the stub landed on disk over the user's real file and
        // was reported as a plain success with a byte count matching the stub.
        //
        // Same reasoning as the truncated-write refusal above: for a write, a
        // wrong artifact is strictly worse than none, and it silently destroys
        // data. Refuse, and tell the model what actually happened so it re-reads
        // the offloaded file instead of repeating the call verbatim. Reads and
        // shell calls are untouched — a stub as a *path* is just a miss.
        if tu.name == "file_write" || tu.name == "file_edit" {
            // Only the fields whose value BECOMES file bytes: file_write's
            // `content` and file_edit's replacement text. A stub in
            // file_edit's `old_string` is merely a search that will not match,
            // which the edit tool already reports clearly.
            let payloadKeys = tu.name == "file_write" ? ["content"] : ["new_string"]
            // Both stub formats, current and legacy — see isOffloadedStub.
            if let offendingKey = payloadKeys.first(where: {
                guard let v = toolArgs[$0] as? String else { return false }
                return Self.isOffloadedStub(v)
            }) {
                let path = (toolArgs["path"] as? String) ?? (toolArgs["file_path"] as? String) ?? ""
                AppLogger(category: "ToolPreflight").warning(
                    "[ToolRepair] REFUSED offload-placeholder write tool=\(tu.name) id=\(tu.id) field=\(offendingKey) path=\(path)"
                )
                let uiMessage = AppLocalized("Blocked: content was offloaded from context")
                let modelMessage = """
                Error: This call was NOT executed. Its `\(offendingKey)` is an offload \
                placeholder, not real content — the original text was moved out of context \
                to free tokens, and only a reference notice survived in the conversation. \
                Writing it would have replaced the file\(path.isEmpty ? "" : " at \(path)") \
                with that notice. Nothing was written to disk — the target file is unchanged.

                Use file_read on the path named inside the placeholder to recover the real \
                content, then re-issue this write with it. Do not resend the placeholder.
                """
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = uiMessage
                    messages[msgIdx].blocks[blockIdx].toolStatus = .failed(message: uiMessage)
                }
                toolLoopDetector.record(
                    toolName: tu.name, params: tu.args,
                    result: nil, errorMessage: modelMessage, toolCallId: tu.id
                )
                let refusedSnap = ToolSnapshot(type: .text, text: modelMessage, mediaRef: nil, duration: nil)
                let item = ToolSnapshotItem(
                    id: tu.id, toolName: tu.name, snapshot: refusedSnap,
                    mediaResolver: await ChatStore.shared.mediaFileURLResolver()
                )
                return ToolExecOutcome(
                    toolId: tu.id, toolName: tu.name,
                    resultPart: .toolResult(id: tu.id, name: tu.name, content: modelMessage, isError: true),
                    snapshotEntry: (toolName: tu.name, snapshot: refusedSnap),
                    snapshotItem: item,
                    cancelled: false
                )
            }
        }

        // Preflight: reject empty / missing-required-field tool calls.
        if let preflightError = Self.preflightValidateToolCall(name: tu.name, args: toolArgs, tools: tools) {
            let chunkRing = tu.inputChunkRing
            AppLogger(category: "ToolPreflight").warning(
                "[ToolPreflight] BLOCKED tool=\(tu.name) id=\(tu.id) reason=\"\(preflightError)\" argsKeys=[\(tu.args.keys.sorted().joined(separator: ","))] chunkCount=\(chunkRing.count) lastChunk=<<<\(chunkRing.last?.prefix(500) ?? "")>>>"
            )
            let uiMessage = AppLocalized("Blocked invalid tool call")
            let modelMessage = "Error: Tool call rejected before execution. \(preflightError) The arguments your client sent were empty or missing required fields — re-issue the call with all required parameters filled in. Do not retry with the same empty arguments."
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = uiMessage
                messages[msgIdx].blocks[blockIdx].toolStatus = .failed(message: uiMessage)
            }
            toolLoopDetector.record(
                toolName: tu.name, params: tu.args,
                result: nil, errorMessage: modelMessage, toolCallId: tu.id
            )
            let blockedSnap = ToolSnapshot(type: .text, text: modelMessage, mediaRef: nil, duration: nil)
            let item = ToolSnapshotItem(
                id: tu.id, toolName: tu.name, snapshot: blockedSnap,
                mediaResolver: await ChatStore.shared.mediaFileURLResolver()
            )
            return ToolExecOutcome(
                toolId: tu.id, toolName: tu.name,
                resultPart: .toolResult(id: tu.id, name: tu.name, content: modelMessage, isError: true),
                snapshotEntry: (toolName: tu.name, snapshot: blockedSnap),
                snapshotItem: item,
                cancelled: false
            )
        }

        let argsJson: String = {
            if let data = try? JSONSerialization.data(withJSONObject: toolArgs),
               let str = String(data: data, encoding: .utf8) {
                return str
            }
            return "{}"
        }()

        do {
        switch tu.name {
        case "apps_open":
            let aoBid = (toolArgs["bundle_id"] as? String) ?? ""
            guard !aoBid.isEmpty else {
                toolOutput = "Error: Missing 'bundle_id'."
                toolSuccess = false
                break
            }
            let okOpen = openAppViaFBS(aoBid)
            toolOutput = okOpen ? "OPENED: \(aoBid)" : "Error: open failed (uiopen not found)"
            toolSuccess = okOpen
            break
        case "container_read":
            let crBid = (toolArgs["bundle_id"] as? String) ?? ""
            let crPath = (toolArgs["relative_path"] as? String) ?? ""
            guard !crBid.isEmpty, !crPath.isEmpty else {
                toolOutput = "Error: Missing 'bundle_id' or 'relative_path'."
                toolSuccess = false
                break
            }
            guard let crApp = DirectKit.installedApp(for: crBid),
                  let crCont = crApp.dataContainer else {
                toolOutput = "Error: container for \(crBid) not found."
                toolSuccess = false
                break
            }
            guard let data = DirectKit.readContainerFile(crPath, in: crCont) else {
                toolOutput = "Error: file not found: \(crPath)"
                toolSuccess = false
                break
            }
            if let str = String(data: data, encoding: .utf8) {
                toolOutput = str.count > 15000 ? String(str.prefix(15000)) + "\n...[truncated]" : str
            } else {
                toolOutput = "(binary, \(data.count) bytes) at \(crCont)/\(crPath)"
            }
            toolSuccess = true
            break
        case "container_write_text":
            let cwBid = (toolArgs["bundle_id"] as? String) ?? ""
            let cwPath = (toolArgs["relative_path"] as? String) ?? ""
            let cwContent = (toolArgs["content"] as? String) ?? ""
            guard !cwBid.isEmpty, !cwPath.isEmpty else {
                toolOutput = "Error: Missing 'bundle_id' or 'relative_path'."
                toolSuccess = false
                break
            }
            guard let cwApp = DirectKit.installedApp(for: cwBid),
                  let cwCont = cwApp.dataContainer else {
                toolOutput = "Error: container for \(cwBid) not found."
                toolSuccess = false
                break
            }
            let okW = DirectKit.writeContainerFile(Data(cwContent.utf8), to: cwPath, in: cwCont)
            toolOutput = okW ? "Written: \(cwPath)" : "Error: write failed"
            toolSuccess = okW
            break
        case "decrypted_list":
            // [zzuu-direct] In-process enumeration; no SSH needed.
            let apps = DirectKit.listInstalledApps()
            if apps.isEmpty {
                toolOutput = "(no apps found — check storage entitlements)"
                toolSuccess = false
            } else {
                var out = "=== Installed apps (\(apps.count)) ===\n"
                for a in apps.prefix(60) {
                    out += "\(a.bundleID) | \(a.executable) | \(a.name)\n"
                }
                toolOutput = out
                toolSuccess = true
            }
            break
        case "process_list":
            // [zzuu-direct] sysctl KERN_PROC_ALL in-process.
            let procs = DirectKit.listProcesses()
            if procs.isEmpty {
                toolOutput = "(no processes returned — check entitlements)"
                toolSuccess = false
            } else {
                var out = "PID\tNAME\n"
                for pr in procs.prefix(200) {
                    out += "\(pr.pid)\t\(pr.name)\n"
                }
                toolOutput = out
                toolSuccess = true
            }
            break
        case "dylib_inject":
            let diBid = (toolArgs["bundle_id"] as? String) ?? ""
            let diDylib = (toolArgs["dylib_path"] as? String) ?? "/var/tmp/zzuu_uidumper.dylib"
            guard !diBid.isEmpty else {
                toolOutput = "Error: Missing 'bundle_id'."
                toolSuccess = false
                break
            }
            guard let app = DirectKit.installedApp(for: diBid) else {
                toolOutput = "Error: app \(diBid) not found."
                toolSuccess = false
                break
            }
            let main = app.bundlePath + "/" + app.executable
            guard FileManager.default.fileExists(atPath: main) else {
                toolOutput = "Error: main binary missing."
                toolSuccess = false
                break
            }
            guard FileManager.default.fileExists(atPath: diDylib) else {
                toolOutput = "Error: dylib not found: \(diDylib)"
                toolSuccess = false
                break
            }
            let optoolPaths = ["/usr/bin/optool", "/var/jb/usr/bin/optool", "/var/mobile/optool"]
            let tool = optoolPaths.first { FileManager.default.fileExists(atPath: $0) }
            guard let ot = tool else {
                toolOutput = "optool not found. Install once via re-ios-triage skill, then retry."
                toolSuccess = false
                break
            }
            DirectKit.spawnDetached(ot, args: ["install", "-c", "load", "-p", diDylib, "-t", main])
            DirectKit.spawnDetached("/usr/bin/ldid", args: ["-S", main])
            toolOutput = "INJECT_OK: \(diDylib) -> \(main) (re-signed)"
            toolSuccess = true
            break
        case "frida_control":
            let fcAction = (toolArgs["action"] as? String) ?? "status"
            switch fcAction {
            case "start":
                guard let fs = DirectKit.fridaServerPath() else {
                    toolOutput = "Error: frida-server binary not found on device."
                    toolSuccess = false
                    break
                }
                let ok = DirectKit.spawnDetached(fs, args: ["-l", "0.0.0.0:27042"])
                toolOutput = ok ? "STARTED" : "Error: spawn failed"
                toolSuccess = ok
            case "stop":
                for pr in DirectKit.listProcesses() where pr.name.contains("frida-server") {
                    kill(pr.pid, SIGKILL)
                }
                toolOutput = "STOPPED"
                toolSuccess = true
            case "ps":
                toolOutput = DirectKit.listProcesses().prefix(40).map { "\($0.pid)\t\($0.name)" }.joined(separator: "\n")
                toolSuccess = true
            case "apps":
                toolOutput = DirectKit.listInstalledApps().prefix(40).map { "\($0.bundleID)  \($0.name)" }.joined(separator: "\n")
                toolSuccess = true
            default:
                toolOutput = DirectKit.fridaRunning() ? "RUNNING" : "NOT_RUNNING"
                toolSuccess = true
            }
            break
        case "keychain_dump":
            let kcFilter = ((toolArgs["filter"] as? String) ?? "").lowercased()
            let items = DirectKit.dumpKeychain(limit: 300)
            let filtered = kcFilter.isEmpty ? items : items.filter {
                $0.service.lowercased().contains(kcFilter) || $0.account.lowercased().contains(kcFilter)
            }
            if filtered.isEmpty {
                toolOutput = "(no keychain items matched)"
                toolSuccess = false
            } else {
                var out = "service | account\n"
                for it in filtered.prefix(300) {
                    out += "\(it.service) | \(it.account)\n"
                }
                toolOutput = out
                toolSuccess = true
            }
            break
        case "syslog_stream":
            let slFilter = ((toolArgs["filter"] as? String) ?? "").replacingOccurrences(of: "'", with: "")
            let slLines = (toolArgs["lines"] as? NSNumber)?.intValue ?? 200
            let candidates = ["/var/log/syslog", "/var/log/system.log"]
            let logPath = candidates.first { FileManager.default.fileExists(atPath: $0) }
            guard let lp = logPath, let fh = FileHandle(forReadingAtPath: lp) else {
                toolOutput = "Error: no syslog file found on device."
                toolSuccess = false
                break
            }
            defer { try? fh.close() }
            let size = (try? fh.seekToEnd()) ?? 0
            let chunk = min(Int(size), 1000000)
            try? fh.seek(toOffset: UInt64(max(0, Int(size) - chunk)))
            let data = (try? fh.readToEnd()) ?? Data()
            var lines = (String(data: data, encoding: .utf8) ?? "").components(separatedBy: "\n").suffix(slLines)
            if !slFilter.isEmpty {
                lines = lines.filter { $0.localizedCaseInsensitiveContains(slFilter) }
            }
            toolOutput = String(lines.joined(separator: "\n").prefix(30000))
            toolSuccess = !toolOutput.isEmpty
            break
        case "app_backup":
            let abBid = (toolArgs["bundle_id"] as? String) ?? ""
            let abAction = (toolArgs["action"] as? String) ?? "backup"
            guard let abApp = DirectKit.installedApp(for: abBid) else {
                toolOutput = "Error: app \(abBid) not found."
                toolSuccess = false
                break
            }
            if abAction == "list" {
                let files = (try? FileManager.default.contentsOfDirectory(atPath: "/var/mobile/zzuu_backups")) ?? []
                let mine = files.filter { $0.hasPrefix(abBid) }
                toolOutput = mine.isEmpty ? "(no backups)" : mine.joined(separator: "\n")
                toolSuccess = true
            } else {
                guard let dest = DirectKit.backupContainer(abApp) else {
                    toolOutput = "Error: backup failed."
                    toolSuccess = false
                    break
                }
                toolOutput = "BACKUP_OK: \(dest)"
                toolSuccess = true
            }
            break
        case "resign_ipa":
            let riPath = (toolArgs["path"] as? String) ?? ""
            guard !riPath.isEmpty else {
                toolOutput = "Error: Missing 'path'."
                toolSuccess = false
                break
            }
            let ldidCandidates = ["/usr/bin/ldid", "/usr/local/bin/ldid", "/opt/ldid"]
            let ld = ldidCandidates.first { FileManager.default.fileExists(atPath: $0) }
            guard let ldidBin = ld else {
                toolOutput = "ldid not found in sandbox. Install via: apk add ldid (iSH shell)."
                toolSuccess = false
                break
            }
            DirectKit.spawnDetached(ldidBin, args: ["-S", riPath])
            toolOutput = "RESIGNED: " + riPath
            toolSuccess = true
            break
        case "macho_info":
            let miPath = (toolArgs["path"] as? String) ?? ""
            let miBid = (toolArgs["bundle_id"] as? String) ?? ""
            var resolved = miPath
            if resolved.isEmpty, !miBid.isEmpty,
               let a = DirectKit.installedApp(for: miBid) {
                resolved = a.bundlePath + "/" + a.executable
            }
            guard !resolved.isEmpty else {
                toolOutput = "Error: provide 'path' or 'bundle_id'."
                toolSuccess = false
                break
            }
            guard let info = DirectKit.machoInfo(binaryPath: resolved) else {
                toolOutput = "Error: not a valid Mach-O: \(resolved)"
                toolSuccess = false
                break
            }
            toolOutput = "magic: \(info.magic)\narch: \(info.arch)\nload commands: \(info.loadCommandCount)\nplatforms: \(info.platforms.joined(separator: ", "))\nencryption: \(info.encryptions.joined(separator: ", "))"
            toolSuccess = true
            break
        case "class_dump":
            let cdPath = (toolArgs["path"] as? String) ?? ""
            let cdBid = (toolArgs["bundle_id"] as? String) ?? ""
            let cdFilter = (toolArgs["class_filter"] as? String) ?? ""
            var binPath = cdPath
            if binPath.isEmpty, !cdBid.isEmpty,
               let a = DirectKit.installedApp(for: cdBid) {
                binPath = a.bundlePath + "/" + a.executable
            }
            guard !binPath.isEmpty else {
                toolOutput = "Error: provide 'path' or 'bundle_id'."
                toolSuccess = false
                break
            }
            let names = DirectKit.objcClassNames(binaryPath: binPath, filter: cdFilter, limit: 300)
            if names.isEmpty {
                toolOutput = "(no ObjC class names found - Swift-only or stripped binary)"
                toolSuccess = false
            } else {
                toolOutput = names.joined(separator: "\n")
                toolSuccess = true
            }
            break
        case "theos_build":
            let tbProject = (toolArgs["project_path"] as? String) ?? ""
            let tbFinal = (toolArgs["final"] as? NSNumber)?.boolValue ?? false
            guard !tbProject.isEmpty else {
                toolOutput = "Error: Missing 'project_path'."
                toolSuccess = false
                break
            }
            let makeCandidates = ["/usr/bin/make", "/usr/local/bin/make"]
            let mk = makeCandidates.first { FileManager.default.fileExists(atPath: $0) }
            guard let make = mk else {
                toolOutput = "make not found in sandbox. Install Theos in iSH first."
                toolSuccess = false
                break
            }
            DirectKit.spawnDetached(make, args: ["-C", tbProject, tbFinal ? "package" : "all"])
            toolOutput = "BUILD_DISPATCHED: " + tbProject
            toolSuccess = true
            break
        case "screen_control":
            let scAction = (toolArgs["action"] as? String) ?? ""
            guard !scAction.isEmpty else {
                toolOutput = "Error: Missing 'action'."
                toolSuccess = false
                break
            }
            let inj = HIDTouchInjector.shared()
            let scX = (toolArgs["x"] as? NSNumber)?.doubleValue ?? 0
            let scY = (toolArgs["y"] as? NSNumber)?.doubleValue ?? 0
            let scX2 = (toolArgs["x2"] as? NSNumber)?.doubleValue ?? 0
            let scY2 = (toolArgs["y2"] as? NSNumber)?.doubleValue ?? 0
            let scDur = (toolArgs["duration"] as? NSNumber)?.doubleValue ?? 0
            let scScale = (toolArgs["scale"] as? NSNumber)?.doubleValue ?? 1.5
            let scText = (toolArgs["text"] as? String) ?? ""
            var scOK = true
            switch scAction {
            case "tap":        inj.tap(at: CGPoint(x: scX, y: scY))
            case "double_tap": inj.doubleTap(at: CGPoint(x: scX, y: scY))
            case "long_press": inj.longPress(at: CGPoint(x: scX, y: scY), duration: scDur)
            case "swipe":      inj.swipe(from: CGPoint(x: scX, y: scY), to: CGPoint(x: scX2, y: scY2), duration: scDur)
            case "pinch":      inj.pinch(inBounds: CGRect(x: scX - 80, y: scY - 80, width: 160, height: 160), scale: scScale, angle: 0, duration: scDur)
            case "home":       inj.pressHomeButton()
            case "type_text":  inj.typeText(scText)
            default:
                scOK = false
            }
            if scOK {
                toolOutput = "HID_OK \(scAction)"
                toolSuccess = true
            } else {
                toolOutput = "Error: unknown action \(scAction)"
                toolSuccess = false
            }
            break

        case "ui_dump":
            let udBid = (toolArgs["bundle_id"] as? String) ?? ""
            let udDepth = (toolArgs["max_depth"] as? NSNumber)?.intValue ?? 12
            if udBid.isEmpty || udBid == Bundle.main.bundleIdentifier {
                guard let json = zzuuDumpUITreeJSON(udDepth) else {
                    toolOutput = "Error: dump failed."
                    toolSuccess = false
                    break
                }
                toolOutput = json.count > 60000 ? String(json.prefix(60000)) + "\n...[truncated]" : json
                toolSuccess = true
            } else {
                guard let target = DirectKit.installedApp(for: udBid) else {
                    toolOutput = "Error: app \(udBid) not found."
                    toolSuccess = false
                    break
                }
                toolOutput = "App found: \(target.name) (\(target.bundleID)). To dump ITS UI: dylib_inject with UIDumpInjector dylib, relaunch the app, then read /var/tmp/zzuu_uidump.json."
                toolSuccess = true
            }
            break
        case "root_execute":
            guard JailbreakConfigStore.shared.isConfigured else {
                toolOutput = "Error: Jailbreak SSH is not configured. Ask the user to set host/port/user/password under Settings > Jailbreak SSH."
                toolSuccess = false
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = toolOutput
                }
                break
            }
            let (rCommand, rTimeout, _) = parseToolInput(from: argsJson)
            if rCommand.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                toolOutput = "Error: Missing required 'command' parameter for root_execute."
                toolSuccess = false
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = toolOutput
                }
                break
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].kind = .rootShellTool(command: rCommand)
            }
            do {
                var rLineBuffer: [String] = []
                var rLastFlush = Date.distantPast
                let flushRLines: () -> Void = { [weak self] in
                    guard let self, !rLineBuffer.isEmpty else { return }
                    let joined = rLineBuffer.joined(separator: "\n")
                    rLineBuffer.removeAll()
                    rLastFlush = Date()
                    Task { @MainActor in
                        guard msgIdx < self.messages.count,
                              blockIdx < self.messages[msgIdx].blocks.count else { return }
                        let current = self.messages[msgIdx].blocks[blockIdx].content
                        let newContent = current.hasSuffix("Executing...")
                            ? joined : current + "\n" + joined
                        self.messages[msgIdx].blocks[blockIdx].content =
                            newContent.count > 30_000
                            ? "…[output truncated]…\n" + String(newContent.suffix(30_000))
                            : newContent
                        self.scrollToBottomSignal.send()
                    }
                }
                let rResult = try await executeRootCommand(rCommand, timeout: rTimeout) { line in
                    rLineBuffer.append(line)
                    if Date().timeIntervalSince(rLastFlush) >= 0.2 { flushRLines() }
                }
                flushRLines()
                toolOutput = rResult.output
                toolSuccess = rResult.exitCode == 0
            } catch {
                toolOutput = "Error: \(error.localizedDescription)"
                toolSuccess = false
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                let existing = messages[msgIdx].blocks[blockIdx].content
                if existing.isEmpty || existing.hasSuffix("Executing...") {
                    let trimmed = toolOutput.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty { messages[msgIdx].blocks[blockIdx].content = trimmed }
                }
            }
            break
        case "shell_execute":
            let (command, timeout, delay) = parseToolInput(from: argsJson)

            if command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                ctLogger.warning("[ToolArgsProbe] shell_execute called with empty command — argsJson=<<<\(argsJson)>>>")
                toolOutput = "Error: Missing required 'command' parameter. Please call shell_execute again with a non-empty `command` field."
                toolSuccess = false
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = toolOutput
                }
                break
            }

            // Offload permission check.
            ctLogger.info("[OffloadPerm] shell command: \(command)")
            if let offloadCmd = OffloadPermissionManager.extractOffloadCommand(from: command) {
                ctLogger.info("[OffloadPerm] matched offload: \(offloadCmd), level: \(OffloadPermissionManager.shared.permissionLevel(for: offloadCmd).rawValue)")
                let permResult = await OffloadPermissionManager.shared.checkPermission(
                    for: offloadCmd, sessionId: self.sessionId, fullCommand: command
                )
                if case .denied(let msg) = permResult {
                    ctLogger.info("[OffloadPerm] DENIED: \(offloadCmd)")
                    toolOutput = msg
                    toolSuccess = false
                    if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                        messages[msgIdx].blocks[blockIdx].content = msg
                    }
                    break
                }
                ctLogger.info("[OffloadPerm] ALLOWED: \(offloadCmd)")
            } else {
                ctLogger.info("[OffloadPerm] no offload match for first token")
            }

            // Delay execution.
            if delay > 0 {
                toolDelayWaitCount += 1
                defer { toolDelayWaitCount -= 1 }
                // [T-delay-stop-latency] The stop button during the countdown
                // sets `commandCancelledByUser` (stopCurrentCommand guards on
                // `toolDelayWaitActive`), but the old loop only re-checked that
                // flag once per whole second and then slept a FULL second — a
                // tap landing just after a check waited up to ~1s before the
                // next check, which read as "stop does nothing" during the
                // delay phase (the user report). Poll on a short tick instead so
                // both the button flag AND Task cancellation are honored within
                // ~100ms, while the visible countdown still refreshes once per
                // whole second.
                let totalSeconds = Int(delay)
                let tickNanos: UInt64 = 100_000_000 // 100ms
                let ticksPerSecond = 10
                var lastShownRemaining = -1
                for tick in 0..<(totalSeconds * ticksPerSecond) {
                    if commandCancelledByUser || Task.isCancelled {
                        throw CancellationError()
                    }
                    let remaining = totalSeconds - (tick / ticksPerSecond)
                    if remaining != lastShownRemaining,
                       msgIdx < self.messages.count, blockIdx < self.messages[msgIdx].blocks.count {
                        lastShownRemaining = remaining
                        let mm = remaining / 60
                        let ss = remaining % 60
                        let countdown = mm > 0 ? String(format: "%d:%02d", mm, ss) : "\(ss)s"
                        self.messages[msgIdx].blocks[blockIdx].content = "⏳ Waiting \(countdown) before executing..."
                        self.scrollToBottomSignal.send()
                    }
                    try await Task.sleep(nanoseconds: tickNanos)
                }
                // Final cancellation check after the last tick so a tap in the
                // final 100ms window still aborts before we launch the process.
                if commandCancelledByUser || Task.isCancelled {
                    throw CancellationError()
                }
            }

            let preSnapshot = snapshotMinisFiles()
            let result: CommandResult
            do {
                var lineBuffer: [String] = []
                var lastFlush = Date.distantPast
                let kMaxStreamingDisplayChars = 30_000
                // [T-ios-flushlines-mainactor] Hop to the main actor before
                // touching `messages`.
                //
                // This closure runs on ISHShellExecutor's reader queue (it is
                // `executeCommand`'s per-line callback), but `messages` is
                // @Published on a @MainActor view model and
                // `scrollToBottomSignal` drives UI. Writing both from a
                // background queue is a data race on SwiftUI state — the kind
                // that corrupts the view graph rather than failing cleanly.
                //
                // The buffer drain stays OUTSIDE the hop and remains
                // synchronous: `lineBuffer` and `lastFlush` belong to the
                // reader queue, and deferring their reset would let the next
                // callback re-read lines this flush already claimed. So the
                // lines are taken here, and only the UI write is hopped.
                //
                // The bounds check moves inside the hop with the access it
                // guards — checking on the reader queue and using the value on
                // the main actor would be checking a snapshot that could have
                // changed by the time it is used.
                let flushLines: () -> Void = { [weak self] in
                    guard let self, !lineBuffer.isEmpty else { return }
                    let joined = lineBuffer.joined(separator: "\n")
                    lineBuffer.removeAll()
                    lastFlush = Date()
                    Task { @MainActor in
                        guard msgIdx < self.messages.count,
                              blockIdx < self.messages[msgIdx].blocks.count else { return }
                        let current = self.messages[msgIdx].blocks[blockIdx].content
                        var newContent: String
                        if current.hasSuffix("Executing...") {
                            newContent = joined
                        } else {
                            newContent = current + "\n" + joined
                        }
                        if newContent.count > kMaxStreamingDisplayChars {
                            newContent = "…[output truncated]…\n" + String(newContent.suffix(kMaxStreamingDisplayChars))
                        }
                        self.messages[msgIdx].blocks[blockIdx].content = newContent
                        self.scrollToBottomSignal.send()
                    }
                }
                // [T-tool-exec-breadcrumb] Durable, written BEFORE the command
                // launches. `[ToolLifecycle] COMPLETED` only lands after a tool
                // returns, so a process killed mid-execution (watchdog SIGKILL,
                // Jetsam, SIGABRT) left no record of what was running. This line
                // is on disk (O_SYNC) before executeCommand is entered, so the
                // last breadcrumb after a kill names the command that was live.
                // Command is truncated — enough to identify it, not enough to
                // bloat the file with a large heredoc.
                #if DEBUG
                CrashReporter.writeToolBreadcrumb(
                    "[ToolExec] STARTING shell_execute id=\(tu.id.prefix(20)) sid=\(sessionId?.prefix(8) ?? "nil") timeout=\(timeout)s command=\"\(command.prefix(500))\""
                )
                #endif
                result = try await executeCommand(command, timeout: timeout) { [weak self] line in
                    guard let self else { return }
                    let (cleanedLine, capturedURLs) = MinisURLMarker.extract(from: line)
                    if !capturedURLs.isEmpty {
                        Task { @MainActor in
                            for raw in capturedURLs {
                                if let u = URL(string: raw),
                                   MinisOpenURLBroker.isSupportedScheme(u.scheme) {
                                    MinisOpenURLBroker.shared.offer(u)
                                }
                            }
                        }
                    }
                    if cleanedLine.isEmpty && !line.isEmpty { return }
                    lineBuffer.append(cleanedLine)
                    if Date().timeIntervalSince(lastFlush) >= 0.2 {
                        flushLines()
                    }
                }
                flushLines()
            } catch {
                result = CommandResult(output: "Error: \(error.localizedDescription)", exitCode: -1)
            }
            // [T-tool-exec-breadcrumb] Pair for the STARTING line above. The
            // existing `[ToolLifecycle] COMPLETED` covers every tool, but it
            // travels the droppable NSLog pipe; this one shares the STARTING
            // line's durable file so a STARTING with no matching FINISHED is
            // unambiguous evidence that the process died inside this command.
            #if DEBUG
            CrashReporter.writeToolBreadcrumb(
                "[ToolExec] FINISHED shell_execute id=\(tu.id.prefix(20)) exit=\(result.exitCode)"
            )
            #endif
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                let existingContent = messages[msgIdx].blocks[blockIdx].content
                let hasStreamedContent = !existingContent.isEmpty
                    && !existingContent.hasSuffix("Executing...")
                if !hasStreamedContent {
                    let (cleaned, capturedURLs) = MinisURLMarker.extract(from: result.output)
                    for raw in capturedURLs {
                        if let u = URL(string: raw),
                           MinisOpenURLBroker.isSupportedScheme(u.scheme) {
                            MinisOpenURLBroker.shared.offer(u)
                        }
                    }
                    let resultTrimmed = cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !resultTrimmed.isEmpty {
                        messages[msgIdx].blocks[blockIdx].content = resultTrimmed
                    }
                }
            }
            if commandCancelledByUser {
                // NOTE: don't reset commandCancelledByUser here under
                // concurrent execution — sibling shell tasks still need
                // the signal to abort their own delay loops. The outer
                // dispatcher resets it once per batch.
                toolOutput = "<system-reminder>The user cancelled this operation. The returned result may be incomplete.</system-reminder>\n" + result.output
                cancelledHere = true
            } else {
                toolOutput = result.output
            }
            toolSuccess = result.exitCode == 0

            // Scan for new/modified files under /var/minis/
            let postSnapshot = snapshotMinisFiles()
            let newOrModified = postSnapshot.filter { key, date in
                preSnapshot[key] == nil || preSnapshot[key]! < date
            }
            if !newOrModified.isEmpty {
                for (path, _) in newOrModified {
                    var isDir: ObjCBool = false
                    if let hostURL = resolveHostPath(path) {
                        FileManager.default.fileExists(atPath: hostURL.path, isDirectory: &isDir)
                    }
                    ensureParentDirsInMetaDB(for: path)
                    ensureFakefsMetadata(for: path, isDirectory: isDir.boolValue)
                }
                toolOutput += "\n\n[minis] New/modified files:"
                for path in newOrModified.keys.sorted() {
                    if let url = linuxPathToMinisURL(path) {
                        toolOutput += "\n  \(url)"
                    }
                }
            }

            let (redactedOut, redactHits) = EnvVarRedactor.redactIfEnabled(toolOutput)
            if redactHits > 0 {
                ctLogger.info("[EnvVarRedact] shell_execute: masked \(redactHits) env-var value(s) in tool result")
            }
            toolOutput = redactedOut

        case "file_read":
            let fileResult: FileToolResult
            do {
                fileResult = try await executeFileRead(from: argsJson)
            } catch {
                fileResult = FileToolResult(output: "Error: \(error.localizedDescription)", success: false)
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = fileResult.output
            }
            toolOutput = fileResult.output
            toolSuccess = fileResult.success
            if fileResult.success,
               let data = argsJson.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let readPath = dict["path"] as? String,
               let skillId = SkillStore.shared.skillIdFromPath(readPath) {
                await MainActor.run { SkillStore.shared.recordSkillUse(skillId) }
            }

        case "file_write":
            let fileResult: FileToolResult
            do {
                fileResult = try await executeFileWrite(from: argsJson)
            } catch {
                fileResult = FileToolResult(output: "Error: \(error.localizedDescription)", success: false)
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = fileResult.output
            }
            toolOutput = fileResult.output
            toolSuccess = fileResult.success
            if fileResult.success,
               let data = argsJson.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let writtenPath = dict["path"] as? String,
               writtenPath.contains("/skills/") && writtenPath.hasSuffix("SKILL.md") {
                await MainActor.run { SkillStore.shared.reload() }
            }

        case "file_edit":
            let fileResult: FileToolResult
            do {
                fileResult = try await executeFileEdit(from: argsJson)
            } catch {
                fileResult = FileToolResult(output: "Error: \(error.localizedDescription)", success: false)
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = fileResult.output
            }
            toolOutput = fileResult.output
            toolSuccess = fileResult.success
            if fileResult.success,
               let data = argsJson.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let editedPath = dict["path"] as? String,
               editedPath.contains("/skills/") && editedPath.hasSuffix("SKILL.md") {
                await MainActor.run { SkillStore.shared.reload() }
            }

        case "browser_use":
            // [T-tools-master-switch] Not in the schema when off; a request
            // built before the switch flipped can still name it.
            guard AgentToolSwitch.isToolEnabled(tu.name) else {
                toolOutput = Self.toolsDisabledMessage
                toolSuccess = false
                break
            }
            var browserResult: BrowserActionResult
            if let input = BrowserActionInput.parse(from: argsJson) {
                do {
                    browserResult = try await browserTabPool.execute(action: input, owner: sessionId)
                } catch {
                    browserResult = .error(error.localizedDescription)
                }
            } else {
                browserResult = .error("Invalid browser_use input. Required: 'action' parameter.")
            }

            if browserTakeoverActive {
                if let freshResult = await waitForMidActionTakeover() {
                    let originalText = browserResult.text
                    let takeoverNote = "\n[Browser takeover] User manually operated the browser. Screenshot updated."
                    browserResult = BrowserActionResult(
                        text: originalText + takeoverNote,
                        success: browserResult.success,
                        base64Image: freshResult.base64Image,
                        imageFilePath: freshResult.imageFilePath,
                        pageURL: freshResult.pageURL ?? browserResult.pageURL
                    )
                }
            }
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = browserResult.text
                messages[msgIdx].blocks[blockIdx].imageFilePath = browserResult.imageFilePath
                if let pageURL = browserResult.pageURL {
                    messages[msgIdx].blocks[blockIdx].browserURL = pageURL
                }
            }
            toolOutput = browserResult.text
            toolSuccess = browserResult.success
            toolPageURL = browserResult.pageURL
            if let b64 = browserResult.base64Image, let data = Data(base64Encoded: b64) {
                toolImageData = Self.resizedImageData(data, maxLongEdge: 2000) ?? data
                toolImageMimeType = "image/jpeg"

                let timestamp = Int(Date().timeIntervalSince1970)
                let screenshotFilename = "screenshot_\(timestamp).jpg"
                let sid = sessionId ?? "unknown"
                let persistDir = Self.minisBrowserPersistentDir(for: sid)
                let fm = FileManager.default
                try? fm.createDirectory(at: persistDir, withIntermediateDirectories: true)
                let persistPath = persistDir.appendingPathComponent(screenshotFilename)
                try? data.write(to: persistPath)

                let linuxPath = "\(Self.minisBrowserLinuxDir)/\(screenshotFilename)"
                toolImageLinuxPath = linuxPath

                if let minisURL = linuxPathToMinisURL(linuxPath) {
                    toolOutput += "\nminis_url: \(minisURL)"
                }
            }

            if let fetchData = browserResult.fetchedFileData,
               let fetchName = browserResult.fetchedFileName {
                let sid = sessionId ?? "unknown"
                let persistDir = Self.minisBrowserPersistentDir(for: sid)
                try? FileManager.default.createDirectory(at: persistDir, withIntermediateDirectories: true)
                let persistPath = persistDir.appendingPathComponent(fetchName)
                try? fetchData.write(to: persistPath)

                let linuxPath = "\(Self.minisBrowserLinuxDir)/\(fetchName)"
                if let minisURL = linuxPathToMinisURL(linuxPath) {
                    toolOutput += "\nminis_url: \(minisURL)"
                }
            }

            // [T-browser-download-ux] Surface native WKDownload activity in the
            // tool result so the agent KNOWS a page interaction triggered a
            // download and doesn't re-download the same file via shell
            // curl/wget. WebKit's decideDestination callback can land a beat
            // after the action resolves (navigation-turned-download resumes
            // the continuation first), so if a download is in flight but not
            // yet registered, wait briefly for the filename to be known.
            if let sid = sessionId {
                var downloadReport = BrowserDownloadCenter.shared.agentReport(for: sid)
                if downloadReport == nil,
                   browserTabPool.activeManager?.hasInflightDownloads == true {
                    try? await Task.sleep(nanoseconds: 500_000_000)
                    downloadReport = BrowserDownloadCenter.shared.agentReport(for: sid)
                        ?? "[browser_downloads] This action triggered a native browser file "
                         + "download that is still starting (filename not yet resolved). It will "
                         + "be saved into /var/minis/workspace/ — do NOT re-download it with "
                         + "curl/wget; check the workspace or the next browser_use result instead."
                }
                if let downloadReport {
                    toolOutput += "\n\n" + downloadReport
                }
            }

        case "read_image":
            let pathArg = toolArgs["path"] as? String ?? ""
            let resolvedURL = await resolveMinisPath(pathArg)
            ctLogger.info("[read_image] pathArg=\(pathArg) resolvedURL=\(resolvedURL?.path ?? "nil") exists=\(resolvedURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false)")
            if let resolvedURL {
                let dataOK = (try? Data(contentsOf: resolvedURL)) != nil
                let uiOK = (try? Data(contentsOf: resolvedURL)).flatMap { UIImage(data: $0) } != nil
                ctLogger.info("[read_image] dataReadable=\(dataOK) uiImageDecodable=\(uiOK) fileSize=\((try? FileManager.default.attributesOfItem(atPath: resolvedURL.path)[.size]) ?? "?")")
            }

            if let fileURL = resolvedURL,
               let fileData = try? Data(contentsOf: fileURL),
               let uiImage = UIImage(data: fileData) {
                let originalSize = fileData.count
                let originalW = uiImage.cgImage.map { $0.width } ?? Int(uiImage.size.width)
                let originalH = uiImage.cgImage.map { $0.height } ?? Int(uiImage.size.height)

                let inferenceData: Data
                let resizedW: Int
                let resizedH: Int
                if let resized = Self.resizedImageData(fileData, maxLongEdge: 2000),
                   let resizedImage = UIImage(data: resized) {
                    inferenceData = resized
                    resizedW = resizedImage.cgImage.map { $0.width } ?? Int(resizedImage.size.width)
                    resizedH = resizedImage.cgImage.map { $0.height } ?? Int(resizedImage.size.height)
                } else {
                    inferenceData = uiImage.jpegData(compressionQuality: 0.85) ?? fileData
                    resizedW = originalW
                    resizedH = originalH
                }

                if pathArg.hasPrefix("/var/minis/") {
                    toolImageLinuxPath = pathArg
                } else if pathArg.hasPrefix("minis://") {
                    let tail = String(pathArg.dropFirst("minis://".count))
                    if !tail.isEmpty {
                        toolImageLinuxPath = "/var/minis/\(tail)"
                    }
                }

                var meta = "Image loaded successfully."
                meta += "\nPath: \(pathArg)"
                meta += "\nOriginal: \(originalW)x\(originalH), \(formatBytes(originalSize))"
                if resizedW != originalW || resizedH != originalH {
                    meta += "\nResized for analysis: \(resizedW)x\(resizedH)"
                }
                meta += "\nMIME: image/jpeg"

                // [T-ios-vision-group #182] Two ways to answer this call.
                //
                // Native-vision models keep the original behaviour exactly:
                // attach the pixels and let the model look at them.
                //
                // A model WITHOUT native vision only reaches this line because a
                // Vision Group is configured (that's the tool-exposure gate), so
                // hand the bytes to that group and return its DESCRIPTION as
                // text. Crucially we then leave `toolImageData` nil: attaching
                // pixels a text-only model can't decode is what the providers
                // silently drop today, and on the OpenAI Chat Completions path
                // they'd be dropped without even a placeholder.
                // [T-ios-vision-group-t264 #182] Optional caller-supplied question
                // about the image. Only load-bearing on the vision-group branch —
                // there it steers the describing model, which is the host model's
                // only way to follow up on a detail it cannot look at itself.
                let visionPrompt = (toolArgs["prompt"] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)

                // [T-ios-vision-branch-mismatch #182] MUST be the same source the
                // registration used — see `activeModelHasNativeVision`. Reading
                // `selectedModel` here (while the request is built from
                // resolveCurrentEntry) is what made a text-only model fall into
                // the native pixel branch and get metadata instead of a
                // description.
                let nativeVision = self.activeModelHasNativeVision
                if nativeVision {
                    toolImageData = inferenceData
                    toolImageMimeType = "image/jpeg"
                    // Native models see the pixels, so the prompt isn't needed to
                    // direct anything — but echo it so the transcript shows what
                    // the model was looking for. Image data is untouched.
                    if let p = visionPrompt, !p.isEmpty {
                        toolOutput = meta + "\nRequested focus: \(p)"
                    } else {
                        toolOutput = meta
                    }
                    toolSuccess = true
                } else {
                    do {
                        // [T-ios-vision-group-attribution #182] Name the model
                        // that is currently reading, live. Previously the card
                        // just said "Reading image <path>…" for however many
                        // seconds the call took, so the user could not tell
                        // which member of the group was working — nor see a
                        // fallback happen. `onAttempt` fires before each
                        // candidate, so a switch is visible as it occurs.
                        let groupLabel = VisionGroupResolver.groupName()
                        let pathForUI = pathArg
                        let outcome = try await VisionGroupResolver.describe(
                            imageData: inferenceData,
                            mimeType: "image/jpeg",
                            customPrompt: visionPrompt,
                            seed: abs(tu.id.hashValue),
                            onAttempt: { [weak self] attempt in
                                guard let self,
                                      msgIdx < self.messages.count,
                                      blockIdx < self.messages[msgIdx].blocks.count else { return }
                                let via = groupLabel.map { " (\($0))" } ?? ""
                                let retry = attempt.index > 1
                                    ? " — attempt \(attempt.index)/\(attempt.total)" : ""
                                self.messages[msgIdx].blocks[blockIdx].content =
                                    "Reading image \(pathForUI) via \(attempt.modelName)\(via)\(retry)…"
                            }
                        )
                        let framed = VisionGroupResolver.framedDescription(
                            outcome,
                            groupName: groupLabel,
                            question: visionPrompt
                        )
                        toolOutput = meta + "\n\n" + framed
                        toolSuccess = true
                        ctLogger.info("[read_image] vision-group described image (\(outcome.description.count) chars) via \(outcome.modelName), priorFailures=\(outcome.priorFailures.count)")
                    } catch {
                        // Deliberately a SUCCESSFUL result carrying failure text:
                        // an errored tool result tends to make models retry in a
                        // loop, whereas this lets the model tell the user plainly.
                        let reason = (error as? VisionGroupResolver.VisionError)?.errorDescription
                            ?? error.localizedDescription
                        toolOutput = meta + "\n\n" + VisionGroupResolver.failureText(reason)
                        toolSuccess = true
                        ctLogger.error("[read_image] vision-group describe FAILED: \(reason)")
                    }
                }

                // The on-screen tool block shows the image itself in BOTH
                // branches — the user can always see what was read, regardless
                // of what the model received.
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].imageFilePath = fileURL.path
                    messages[msgIdx].blocks[blockIdx].content = toolOutput
                }
            } else {
                ctLogger.error("[read_image] FAILED pathArg=\(pathArg) resolvedURL=\(resolvedURL?.path ?? "nil")")
                toolOutput = "Error: Could not read image at '\(pathArg)'. Verify the path exists and is a valid image file."
                toolSuccess = false
            }

        case "memory_write":
            let memResult = executeMemoryWrite(from: argsJson)
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = memResult.output
            }
            toolOutput = memResult.output
            toolSuccess = memResult.success

        case "memory_get":
            let memResult = executeMemoryGet(from: argsJson)
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = memResult.output
            }
            toolOutput = memResult.output
            toolSuccess = memResult.success

        case SubAgentDefinition.toolName:
            // [T-agents-debug-only] A refusal in the sub-agent result dialect,
            // so HelperBlockInfo renders the block as "Rejected" (a plain
            // string parsed as the `.starting` phase and left a spinner on a
            // call that never ran — Release device run).
            guard AgentToolSwitch.isToolEnabled(tu.name) else {
                toolOutput = Self.jsonString(["ok": false, "status": "rejected", "reason": "tools_disabled",
                                              "detail": Self.toolsDisabledMessage])
                toolSuccess = false
                // The live block reads `content`, not `toolOutput` — the latter
                // only reaches the block via applyToolResults on a session
                // reload. Without this write the row stayed on the "starting"
                // spinner for the rest of the turn and only read "Rejected"
                // after reopening the session. Same as HelperRunner.reject.
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = toolOutput
                }
                break
            }
            // [T-sub-agents-v1] One tool, three actions:
            // delegating and inspecting/stopping what was delegated are the
            // same capability, so they share a declaration. `delegate` is the
            // default because it is what the model calls almost every time.
            switch (toolArgs["action"] as? String)?.lowercased() ?? "delegate" {
            case "resume":
                let r = await executeResumeAgents(args: toolArgs)
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = r.output
                }
                toolOutput = r.output
                toolSuccess = r.success
            case "status", "steer", "cancel":
                let statusResult = executeAgentStatus(args: toolArgs)
                if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                    messages[msgIdx].blocks[blockIdx].content = statusResult.output
                }
                toolOutput = statusResult.output
                toolSuccess = statusResult.success
            default:
                // [T-p1-delegate-task] Runs a sub agent in a hidden child
                // session; wait mode blocks this tool call on it. See
                // HelperRunner.swift.
                let helperResult = await executeDelegateTask(args: toolArgs, toolUseId: tu.id,
                                                             msgIdx: msgIdx, blockIdx: blockIdx)
                toolOutput = helperResult.output
                toolSuccess = helperResult.success
            }

        default:
            toolOutput = "Error: Unknown tool '\(tu.name)'"
            toolSuccess = false
        }
        } catch is CancellationError {
            let cancelContent = "<system-reminder>The user cancelled this operation. The returned result may be incomplete.</system-reminder>"
            let existing = (msgIdx < messages.count && blockIdx < messages[msgIdx].blocks.count)
                ? messages[msgIdx].blocks[blockIdx].content : ""
            toolOutput = existing.isEmpty ? cancelContent : existing + "\n" + cancelContent
            toolSuccess = false
            cancelledHere = true
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].toolStatus = .cancelled
            }
        } catch {
            ctLogger.error("Tool execution threw non-cancellation error: \(error)")
            toolOutput = "Error: \(error.localizedDescription)"
            toolSuccess = false
        }

        // Tail cancel-detection: if Task got cancelled mid-execution.
        if !cancelledHere && Task.isCancelled && self.userDidCancel {
            cancelledHere = true
            toolOutput += "\n<system-reminder>The user cancelled this operation. The returned result may be incomplete.</system-reminder>"
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
                messages[msgIdx].blocks[blockIdx].content = toolOutput
                messages[msgIdx].blocks[blockIdx].toolStatus = .cancelled
            }
        }

        let toolDuration: TimeInterval? = {
            if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count,
               let start = messages[msgIdx].blocks[blockIdx].toolStartTime {
                return Date().timeIntervalSince(start)
            }
            return nil
        }()

        // Create snapshot from tool output.
        let snapshot: ToolSnapshot
        switch tu.name {
        case "browser_use":
            if let imagePath = (msgIdx < messages.count && blockIdx < messages[msgIdx].blocks.count)
                ? messages[msgIdx].blocks[blockIdx].imageFilePath : nil,
               let imageData = try? Data(contentsOf: URL(fileURLWithPath: imagePath)),
               let sid = sessionId {
                let ref = await ChatStore.shared.saveMedia(
                    data: imageData, mimeType: "image/jpeg", sessionId: sid,
                    originalFileName: "browser_snapshot.jpg", subdir: "browser",
                    linuxPath: toolImageLinuxPath
                )
                snapshot = ToolSnapshot(type: .image, text: nil, mediaRef: ref, duration: toolDuration)
            } else {
                let lines = toolOutput.components(separatedBy: "\n")
                let lastLines = lines.suffix(20).joined(separator: "\n")
                snapshot = ToolSnapshot(type: .text, text: lastLines, mediaRef: nil, duration: toolDuration)
            }
        case "read_image":
            if let imagePath = (msgIdx < messages.count && blockIdx < messages[msgIdx].blocks.count)
                ? messages[msgIdx].blocks[blockIdx].imageFilePath : nil,
               let imageData = try? Data(contentsOf: URL(fileURLWithPath: imagePath)),
               let sid = sessionId {
                let fileURL = URL(fileURLWithPath: imagePath)
                let mime = Self.detectImageMime(imageData)
                let ref = await ChatStore.shared.saveMedia(
                    data: imageData, mimeType: mime, sessionId: sid,
                    originalFileName: fileURL.lastPathComponent, subdir: "images",
                    linuxPath: toolImageLinuxPath
                )
                snapshot = ToolSnapshot(type: .image, text: nil, mediaRef: ref, duration: toolDuration)
            } else {
                snapshot = ToolSnapshot(type: .text, text: toolOutput, mediaRef: nil, duration: toolDuration)
            }
        case "file_write", "file_edit":
            if let path = toolArgs["path"] as? String,
               let hostURL = await resolvePathForDirectRead(path),
               let fileContent = try? String(contentsOf: hostURL, encoding: .utf8) {
                let lines = fileContent.components(separatedBy: "\n")
                let preview = lines.prefix(200).joined(separator: "\n")
                snapshot = ToolSnapshot(type: .text, text: preview, mediaRef: nil, duration: toolDuration)
            } else {
                snapshot = ToolSnapshot(type: .text, text: toolOutput, mediaRef: nil, duration: toolDuration)
            }
        default:
            snapshot = ToolSnapshot(type: .text, text: toolOutput, mediaRef: nil, duration: toolDuration)
        }

        let snapshotResolver = await ChatStore.shared.mediaFileURLResolver()
        let snapshotItem = ToolSnapshotItem(
            id: tu.id, toolName: tu.name, snapshot: snapshot, mediaResolver: snapshotResolver
        )

        // Update tool block status and store execution duration.
        if msgIdx < messages.count, blockIdx < messages[msgIdx].blocks.count {
            let blk = messages[msgIdx].blocks[blockIdx]
            blk.toolDuration = toolDuration
            if cancelledHere {
                blk.toolStatus = .cancelled
            } else if toolSuccess, truncationRepairTag != nil {
                // [T-truncated-args-visibility #119] A repaired call must not
                // render as a clean success — that is exactly the silence the
                // user reported. Surface it with the same weight the blocked
                // path already gets, so "arguments were altered" is visible in
                // the transcript rather than buried in a log line.
                blk.toolStatus = .failed(
                    message: AppLocalized("Arguments truncated in transit — result may be incomplete")
                )
            } else {
                blk.toolStatus = toolSuccess
                    ? .success
                    : .failed(message: toolOutput.components(separatedBy: "\n").first ?? "Failed")
            }
            // [T-p2-agent-in-toolbar] A delegate_task that returned
            // `status: running` (background mode) is NOT finished from the
            // user's point of view: keep the block `.running` so the floating
            // tool bar / Live Activity treat it as active until the job's
            // completion hook writes the final state.
            if tu.name == SubAgentDefinition.toolName,
               let obj = AIChatViewModel.parseDelegateResult(toolOutput),
               (obj["status"] as? String) == "running" {
                blk.toolStatus = .running
            }
            ctLogger.info("[ToolLifecycle] COMPLETED toolId=\(tu.id.prefix(20)) tool=\(tu.name) sid=\(sessionId?.prefix(8) ?? "nil") appState=\(UIApplication.shared.applicationState == .active ? "fg" : "bg") suspended=\(streamingUIUpdatesSuspended) isProcessing=\(isProcessing) success=\(toolSuccess) duration=\(String(format: "%.1f", toolDuration ?? 0))s")
            scrollToBottomSignal.send()
        }

        // [T-offload-readback-loop] GH#343. Is this result merely the content of
        // a file the offloader itself wrote, fetched back by `file_read`?
        //
        // Decided from the ARGUMENT the call was made with, before the content
        // is looked at — by the time it is content, it is byte-for-byte the
        // original payload and indistinguishable from new material, which is
        // precisely the bug. Only `file_read` performs such a fetch; every
        // other tool reaching the offload store produces genuinely new output.
        let isOffloadReadback: Bool = {
            guard tu.name == "file_read",
                  let path = toolArgs["path"] as? String else { return false }
            return AIChatViewModel.isOffloadStorePath(path)
        }()

        // Compose finalOutput with truncation/offload.
        let maxToolResultLength = Self.kMaxToolResultChars
        var finalOutput: String
        if toolOutput.isEmpty {
            finalOutput = "(no output)"
        } else if toolOutput.count > maxToolResultLength && isOffloadReadback {
            // [T-offload-readback-loop] PATH B of the loop. This branch used to
            // write a SECOND copy of content that is already on disk — the
            // `file_read_<ts>_c-read-*.txt` files observed piling up on device —
            // and hand the model a stub pointing at the new copy, which it read,
            // which produced another copy.
            //
            // Truncate (the 15K cap still protects the context) but do NOT
            // write, and point the model back at the file it already has. Note
            // the tail differs from the normal branch on purpose: telling it to
            // "use file_read to read the complete output" is exactly the advice
            // that starts the cycle over.
            finalOutput = String(toolOutput.prefix(maxToolResultLength))
                + "\n\n[OUTPUT TRUNCATED] Showing the first \(maxToolResultLength) of \(toolOutput.count) chars. "
                + "This content is already stored at the path you just read — it has not been copied "
                + "anywhere new. To see more, call file_read on that same path again with the "
                + "`offset` from the `next_offset=` value in the header above."
            ctLogger.info("♻️[OffloadReadback] file_read id:\(tu.id.prefix(8)) returned offload-store content — truncated WITHOUT writing a second copy")
        } else if toolOutput.count > maxToolResultLength {
            let offloadResult = offloadToolOutput(toolOutput, toolName: tu.name, toolId: tu.id)
            let offloadMinisURL = linuxPathToMinisURL(offloadResult.linuxPath)
            let truncatedBody: String
            if tu.name == "shell_execute" || tu.name == "root_execute" || tu.name == "browser_use" {
                let halfLen = maxToolResultLength / 2
                truncatedBody = String(toolOutput.prefix(halfLen))
                    + "\n\n...\n\n"
                    + String(toolOutput.suffix(halfLen))
            } else {
                truncatedBody = String(toolOutput.prefix(maxToolResultLength))
            }
            finalOutput = truncatedBody
                + "\n\n[OUTPUT TRUNCATED] Full output (\(toolOutput.count) chars) saved to: \(offloadResult.linuxPath)"
                + (offloadMinisURL.map { "\nminis_url: \($0)" } ?? "")
                + "\nUse file_read tool to read the complete output."
        } else {
            finalOutput = toolOutput
        }

        // Image budget: reserve a slot atomically via the actor. If
        // declined, swap image bytes for a text placeholder.
        if let imgData = toolImageData {
            let granted = await batchBudget.reserveSlot()
            if !granted {
                let placeholder = Self.imagePlaceholderText(data: imgData, originalPath: toolArgs["path"] as? String, snapshotPath: nil)
                if finalOutput.isEmpty || !toolSuccess {
                    finalOutput = placeholder
                } else {
                    finalOutput += "\n\n" + placeholder
                }
                toolImageData = nil
                toolImageMimeType = nil
                ctLogger.info("🖼️ Tool image budget exhausted, stripped image from \(tu.name) id:\(tu.id.prefix(8))")
            }
        }

        // Loop-detector post-record.
        let postCheck = toolLoopDetector.record(
            toolName: tu.name, params: toolArgs,
            result: toolSuccess ? finalOutput : nil,
            errorMessage: toolSuccess ? nil : finalOutput,
            toolCallId: tu.id
        )
        if postCheck.level == .warning, let warningMsg = postCheck.message {
            if finalOutput.isEmpty {
                finalOutput = warningMsg
            } else {
                finalOutput += "\n\n" + warningMsg
            }
        }

        // [T-truncated-args-visibility #119] Tell the MODEL when the call it
        // just got a success for was built from truncated arguments.
        //
        // Writes never reach here (refused above), so this covers the tools we
        // still run repaired — shell_execute, browser_use, file_read, … There
        // the repaired call may well have done the right thing, but the model
        // has no way to know its own arguments were altered, and silently
        // assuming they were intact is how a half-truth propagates downstream.
        // Stating it lets the model verify rather than guess.
        if let tag = truncationRepairTag {
            finalOutput += "\n\n<system-reminder>The argument stream for this call was truncated in "
                + "transit and auto-closed by the client (repair strategy: \(tag)) before execution. "
                + "The arguments actually used may be incomplete — verify the result and re-issue "
                + "the call with complete arguments if anything is missing.</system-reminder>"
        }

        let resultPart = AgentContentPart.toolResult(
            id: tu.id, name: tu.name, content: finalOutput, isError: !toolSuccess,
            imageData: toolImageData, imageMimeType: toolImageMimeType,
            pageURL: toolPageURL, imageLinuxPath: toolImageLinuxPath,
            isOffloadReadback: isOffloadReadback
        )

        #if DEBUG
        let head = String(finalOutput.prefix(200))
        let tail = finalOutput.count > 400 ? "...\(String(finalOutput.suffix(200)))" : ""
        ctLogger.debug("🔧 Tool result [\(tu.name)] id:\(tu.id.prefix(8)) success:\(toolSuccess) len:\(finalOutput.count) head=\"\(head)\" \(tail)")
        #endif

        return ToolExecOutcome(
            toolId: tu.id, toolName: tu.name,
            resultPart: resultPart,
            snapshotEntry: (toolName: tu.name, snapshot: snapshot),
            snapshotItem: snapshotItem,
            cancelled: cancelledHere
        )
    }
}
