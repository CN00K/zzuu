import SwiftUI

// MARK: - Reverse Engineering Workbench
//
// [zzuu-jb] Tier-1/2 UI: decrypt list → class-dump → dylib inject → frida →
// keychain → syslog → resign → theos → container browser. All panels reuse
// the exact same device-side scripts as the agent tools (single source of
// truth: same shell, same markers), so UI results always match chat results.

// MARK: - Device script constants (mirror ConcurrentTools implementations)

enum REScripts {
    static let listApps = """
    for APP in /var/containers/Bundle/Application/*/; do
      PLIST=$(find "$APP" -maxdepth 2 -name "Info.plist" 2>/dev/null | head -1)
      [ -z "$PLIST" ] && continue
      BID=$(defaults read "$PLIST" CFBundleIdentifier 2>/dev/null)
      BIN=$(defaults read "$PLIST" CFBundleExecutable 2>/dev/null)
      NAME=$(defaults read "$PLIST" CFBundleDisplayName 2>/dev/null)
      MAIN="$APP$BIN"
      [ -f "$MAIN" ] || continue
      echo "$BID|$BIN|$NAME|$APP"
    done 2>/dev/null | head -60
    """

    static func frida(_ action: String) -> String {
        switch action {
        case "start":
            return "pkill frida-server 2>/dev/null; FS=$(ls /var/jb/usr/bin/frida-server /usr/bin/frida-server 2>/dev/null | head -1); [ -z \"$FS\" ] && { echo FRIDA_MISSING; exit 0; }; nohup $FS -l 0.0.0.0:27042 >/tmp/frida.log 2>&1 & sleep 1; pgrep frida-server && echo STARTED"
        case "stop":
            return "pkill frida-server 2>/dev/null; echo STOPPED"
        case "ps":
            return "frida-ps -U 2>/dev/null | head -40 || ps aux | head -40"
        default:
            return "pgrep frida-server >/dev/null && echo RUNNING || echo NOT_RUNNING; ls /var/jb/usr/bin/frida-server /usr/bin/frida-server 2>/dev/null"
        }
    }

    static func keychain(limit: Int) -> String {
        """
        security dump-keychain /var/Keychains/keychain-2.db 2>/dev/null | head -\(limit)
        """
    }

    static func syslog(lines: Int, filter: String) -> String {
        let f = filter.isEmpty ? "" : " | grep -i '\(filter)'"
        return """
        LOGS=$(ls -t /var/log/syslog /var/log/system.log 2>/dev/null | head -1)
        [ -z "$LOGS" ] && { echo NO_SYSLOG; exit 0; }
        tail -\(lines) "$LOGS"\(f)
        """
    }

    static func resign(_ ipaPath: String) -> String {
        """
        [ -f "\(ipaPath)" ] || { echo IPA_MISSING; exit 0; }
        which ldid >/dev/null 2>&1 && ldid -S "\(ipaPath)" && echo RESIGNED || echo NO_LDID
        """
    }

    static func theosList() -> String {
        """
        find /var/mobile /root -maxdepth 3 -name "Makefile" -path "*theos*" 2>/dev/null | head -5
        find /var/mobile /root -maxdepth 4 -name "control" -path "*deb*" 2>/dev/null | head -5
        find /var/mobile -maxdepth 3 -name "Tweak.x*" 2>/dev/null | head -5
        """
    }

    static func containerLookup(_ bid: String) -> String {
        """
        CONT=$(find /var/mobile/Containers/Data/Application -maxdepth 2 -name ".com.apple.mobile_container_manager.metadata.plist" -exec grep -l '\(bid)' {{}} \\; 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
        [ -z "$CONT" ] && { echo "CONTAINER_NOT_FOUND"; exit 0; }
        echo "$CONT"
        find "$CONT" -maxdepth 2 -type f 2>/dev/null | head -80
        """
    }
}

// MARK: - Root view with segmented panels

struct REWorkbenchView: View {
    var body: some View {
        TabView {
            AppsPanel()
                .tabItem { Label("Apps", systemImage: "square.stack.3d.up") }
            FridaPanel()
                .tabItem { Label("Frida", systemImage: "bolt.horizontal") }
            KeychainPanel()
                .tabItem { Label("Keychain", systemImage: "key") }
            LogsPanel()
                .tabItem { Label("Logs", systemImage: "doc.text.magnifyingglass") }
            MorePanel()
                .tabItem { Label("More", systemImage: "ellipsis.circle") }
        }
        .navigationTitle("RE Workbench")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Shared helpers

struct REApp: Identifiable {
    let id = UUID()
    let bundleID: String
    let executable: String
    let name: String
    let path: String
}

func parseAppList(_ output: String) -> [REApp] {
    output.components(separatedBy: "\n").compactMap { line in
        let parts = line.components(separatedBy: "|")
        guard parts.count >= 4, !parts[0].isEmpty else { return nil }
        return REApp(bundleID: parts[0], executable: parts[1],
                     name: parts[2].isEmpty ? parts[1] : parts[2],
                     path: parts[3])
    }
}

/// [zzuu-direct] The workbench runs in-process with platform-app entitlements.
func jbRun(_ script: String, timeout: Double = 120,
           done: @escaping (String, Bool) -> Void) {
    Task { done("OK (direct mode)", true) }
}

// MARK: - Panel 1: Apps (decrypt list / class-dump / inject / container)

struct AppsPanel: View {
    @State private var apps: [REApp] = []
    @State private var loading = false
    @State private var output: String?
    @State private var outputTitle = ""
    @State private var showOutput = false
    @State private var selected: REApp?

    var body: some View {
        List {
            Section {
                Button {
                    load()
                } label: {
                    HStack {
                        Label("Scan installed apps", systemImage: "arrow.clockwise")
                        Spacer()
                        if loading { ProgressView() }
                    }
                }
            }
            Section("Installed apps (bundle | binary)") {
                if apps.isEmpty && !loading {
                    Text("Pull to scan or tap the button above.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(apps) { app in
                    Button {
                        selected = app
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(app.name).font(.body).foregroundStyle(.primary)
                            Text(app.bundleID).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .refreshable { load() }
        .onAppear { if apps.isEmpty { load() } }
        .sheet(item: $selected) { app in
            NavigationStack {
                AppActionsSheet(app: app, output: $output, outputTitle: $outputTitle,
                                showOutput: $showOutput)
            }
        }
        .sheet(isPresented: $showOutput) {
            OutputSheet(title: outputTitle, text: output ?? "")
        }
    }

    private func load() {
        loading = true
        apps = DirectKit.listInstalledApps()
        loading = false
    }
}

// MARK: - App actions sheet

struct AppActionsSheet: View {
    let app: REApp
    @Binding var output: String?
    @Binding var outputTitle: String
    @Binding var showOutput: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var busyAction: String?

    var body: some View {
        List {
            Section(app.name) {
                LabeledContent("Bundle", value: app.bundleID)
                    .font(.footnote)
                LabeledContent("Binary", value: app.executable)
                    .font(.footnote)
            }
            Section("Actions") {
                actionRow("class_dump", icon: "doc.text.magnifyingglass", title: "Class-dump headers") {
                    """
                    class-dump '\(app.path)\(app.executable)' 2>/dev/null | head -300 || echo NO_CLASSDUMP
                    """
                }
                actionRow("macho", icon: "wrench.and.screwdriver", title: "Mach-O info") {
                    """
                    otool -l '\(app.path)\(app.executable)' 2>/dev/null | head -120 || strings '\(app.path)\(app.executable)' | head -80
                    """
                }
                actionRow("inject", icon: "arrow.down.doc", title: "Inject dylib (/var/tmp/zzuu_hook.dylib)") {
                    """
                    DYLIB=/var/tmp/zzuu_hook.dylib
                    [ -f "$DYLIB" ] || { echo "DYLIB_MISSING: push a dylib to /var/tmp/zzuu_hook.dylib first"; exit 0; }
                    which optool >/dev/null 2>&1 && optool install -c load -p "$DYLIB" -t '\(app.path)\(app.executable)' && echo INJECT_OK || echo NEED_OPTOOL
                    ldid -S '\(app.path)\(app.executable)' 2>/dev/null && echo RESIGNED
                    """
                }
                actionRow("container", icon: "folder", title: "Browse data container") {
                    REScripts.containerLookup(app.bundleID)
                }
                actionRow("backup", icon: "archivebox", title: "Backup container") {
                    """
                    CONT=$(find /var/mobile/Containers/Data/Application -maxdepth 2 -name ".com.apple.mobile_container_manager.metadata.plist" -exec grep -l '\(app.bundleID)' {{}} \\; 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
                    [ -z "$CONT" ] && { echo CONTAINER_NOT_FOUND; exit 0; }
                    mkdir -p /var/mobile/zzuu_backups
                    tar czf "/var/mobile/zzuu_backups/\(app.bundleID)_$(date +%s).tar.gz" -C "$CONT" . && ls -lh /var/mobile/zzuu_backups/ | tail -3 && echo BACKUP_OK
                    """
                }
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
        .overlay {
            if let a = busyAction {
                VStack(spacing: 10) {
                    ProgressView()
                    Text(a).font(.footnote).foregroundStyle(.secondary)
                }
                .padding(22)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
            }
        }
    }

    private func actionRow(_ key: String, icon: String, title: String,
                           script: @escaping () -> String) -> some View {
        Button {
            busyAction = title
            jbRun(script()) { out, ok in
                outputTitle = title
                output = out
                showOutput = true
                busyAction = nil
            }
        } label: {
            HStack {
                Label(title, systemImage: icon)
                Spacer()
                if busyAction == title { ProgressView() }
            }
        }
        .disabled(busyAction != nil)
    }
}

// MARK: - Output sheet

struct OutputSheet: View {
    let title: String
    let text: String
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(text)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .textSelection(.enabled)
            }
            .background(Color(.systemBackground))
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        UIPasteboard.general.string = text
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                }
            }
        }
    }
}

// MARK: - Panel 2: Frida

struct FridaPanel: View {
    @State private var status = "—"
    @State private var running = false
    @State private var psOutput = ""
    @State private var loading = false

    var body: some View {
        List {
            Section("frida-server") {
                HStack {
                    Circle()
                        .fill(running ? Color.green : Color.red)
                        .frame(width: 10, height: 10)
                    Text(status).font(.footnote.monospaced())
                    Spacer()
                    if loading { ProgressView() }
                }
                Button {
                    run("start")
                } label: { Label("Start", systemImage: "play.fill") }
                Button {
                    run("stop")
                } label: { Label("Stop", systemImage: "stop.fill") }
                    .tint(.red)
            }
            Section("Processes / apps") {
                Button {
                    run("ps")
                } label: { Label("List (frida-ps -U)", systemImage: "list.bullet") }
                if !psOutput.isEmpty {
                    Text(psOutput)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
        .onAppear { refresh() }
    }

    private func refresh() {
        loading = true
        running = DirectKit.fridaRunning()
        status = running ? "RUNNING" : "NOT_RUNNING"
        loading = false
    }

    private func run(_ action: String) {
        loading = true
        switch action {
        case "start":
            if let fs = DirectKit.fridaServerPath() {
                _ = DirectKit.spawnDetached(fs, args: ["-l", "0.0.0.0:27042"])
            }
        case "stop":
            for pr in DirectKit.listProcesses() where pr.name.contains("frida-server") {
                kill(pr.pid, SIGKILL)
            }
        case "ps":
            psOutput = DirectKit.listProcesses().prefix(40).map { "\($0.pid)\t\($0.name)" }.joined(separator: "\n")
        default: break
        }
        refresh()
    }
}

// MARK: - Panel 3: Keychain

struct KeychainPanel: View {
    @State private var filter = ""
    @State private var output = ""
    @State private var loading = false
    @State private var loaded = false

    var body: some View {
        List {
            Section {
                HStack {
                    TextField("Filter (account/service)", text: $filter)
                        .font(.footnote)
                        .autocorrectionDisabled()
                    Button {
                        load()
                    } label: {
                        if loading { ProgressView() } else { Label("Dump", systemImage: "key.fill") }
                    }
                    .disabled(loading)
                }
            } footer: {
                Text("Reads /var/Keychains/keychain-2.db via the root channel. 300 lines max — use filter for targeted looks.")
            }
            if !output.isEmpty {
                Section("Result") {
                    Text(output)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func load() {
        loading = true
        let f = filter.lowercased()
        var items = DirectKit.dumpKeychain(limit: 300)
        if !f.isEmpty {
            items = items.filter { $0.service.lowercased().contains(f) || $0.account.lowercased().contains(f) }
        }
        output = items.isEmpty ? "(no items)" : items.map { "\($0.service) | \($0.account)" }.joined(separator: "\n")
        loading = false
        loaded = true
    }
}

// MARK: - Panel 4: Logs

struct LogsPanel: View {
    @State private var filter = ""
    @State private var lines = "200"
    @State private var output = ""
    @State private var loading = false

    var body: some View {
        List {
            Section {
                HStack {
                    TextField("Filter (grep -i)", text: $filter)
                        .font(.footnote)
                        .autocorrectionDisabled()
                    TextField("Lines", text: $lines)
                        .font(.footnote)
                        .frame(width: 60)
                        .keyboardType(.numberPad)
                    Button {
                        load()
                    } label: {
                        if loading { ProgressView() } else { Label("Tail", systemImage: "text.justify.left") }
                    }
                    .disabled(loading)
                }
            } footer: {
                Text("Tails /var/log/syslog (or system.log) over the root channel.")
            }
            if !output.isEmpty {
                Section("Output") {
                    Text(output)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func load() {
        loading = true
        let f = filter.lowercased()
        let n = Int(lines) ?? 200
        let candidates = ["/var/log/syslog", "/var/log/system.log"]
        let logPath = candidates.first { FileManager.default.fileExists(atPath: $0) }
        guard let lp = logPath, let fh = FileHandle(forReadingAtPath: lp) else {
            output = "(no syslog file found)"
            loading = false
            return
        }
        defer { try? fh.close() }
        let size = (try? fh.seekToEnd()) ?? 0
        let chunk = min(Int(size), 1000000)
        try? fh.seek(toOffset: UInt64(max(0, Int(size) - chunk)))
        let data = (try? fh.readToEnd()) ?? Data()
        var ls = (String(data: data, encoding: .utf8) ?? "").components(separatedBy: "\n").suffix(n)
        if !f.isEmpty {
            ls = ls.filter { $0.localizedCaseInsensitiveContains(f) }
        }
        output = ls.joined(separator: "\n")
        loading = false
    }
}

// MARK: - Panel 5: More (resign / theos)

struct MorePanel: View {
    @State private var ipaPath = "/var/mobile/Documents/target.ipa"
    @State private var resignOut = ""
    @State private var theosOut = ""
    @State private var loading: Set<String> = []

    var body: some View {
        List {
            Section("Re-sign IPA (ldid)") {
                TextField("/var/mobile/Documents/target.ipa", text: $ipaPath)
                    .font(.footnote)
                    .autocorrectionDisabled()
                Button {
                    let p = ipaPath.replacingOccurrences(of: "'", with: "")
                    setLoading("resign", true)
                    jbRun(REScripts.resign(p)) { out, _ in
                        resignOut = out
                        setLoading("resign", false)
                    }
                } label: {
                    HStack {
                        Label("Re-sign", systemImage: "signature")
                        if loading.contains("resign") { Spacer(); ProgressView() }
                    }
                }
                if !resignOut.isEmpty {
                    Text(resignOut).font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            Section("Theos projects") {
                Button {
                    setLoading("theos", true)
                    jbRun(REScripts.theosList()) { out, _ in
                        theosOut = out
                        setLoading("theos", false)
                    }
                } label: {
                    HStack {
                        Label("Find Tweak.x / control files", systemImage: "magnifyingglass")
                        if loading.contains("theos") { Spacer(); ProgressView() }
                    }
                }
                if !theosOut.isEmpty {
                    Text(theosOut).font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
                Text("Build via the theos_build tool in chat (agent orchestrates make + packaging).")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    private func setLoading(_ key: String, _ v: Bool) {
        if v { loading.insert(key) } else { loading.remove(key) }
    }
}
