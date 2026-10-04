import SwiftUI

// MARK: - Reverse Engineering Workbench
//
// [zzuu-jb] Tier-1/2 UI: decrypt list → class-dump → dylib inject → frida →
// keychain → syslog → resign → theos → container browser. All panels reuse
// the exact same device-side scripts as the agent tools (single source of
// truth: same shell, same markers), so UI results always match chat results.

// MARK: - Device script constants (mirror ConcurrentTools implementations)


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
                actionRow("Class-dump headers", icon: "doc.text.magnifyingglass") {
                    let names = DirectKit.objcClassNames(
                        binaryPath: app.bundlePath + "/" + app.executable,
                        filter: "", limit: 300)
                    return (names.isEmpty ? "(no ObjC class names)" : names.joined(separator: "\n"),
                            !names.isEmpty)
                }
                actionRow("Mach-O info", icon: "wrench.and.screwdriver") {
                    guard let info = DirectKit.machoInfo(
                        binaryPath: app.bundlePath + "/" + app.executable) else {
                        return ("Not a valid Mach-O", false)
                    }
                    let desc = "magic: " + info.magic + "\narch: " + info.arch
                        + "\nload commands: " + String(info.loadCommandCount)
                        + "\nplatforms: " + info.platforms.joined(separator: ", ")
                        + "\nencryption: " + info.encryptions.joined(separator: ", ")
                    return (desc, true)
                }
                actionRow("Inject dylib (/var/tmp/zzuu_hook.dylib)", icon: "arrow.down.doc") {
                    let dylib = "/var/tmp/zzuu_hook.dylib"
                    let main = app.bundlePath + "/" + app.executable
                    guard FileManager.default.fileExists(atPath: dylib) else {
                        return ("DYLIB_MISSING: push a dylib to " + dylib + " first", false)
                    }
                    let optools = ["/usr/bin/optool", "/var/jb/usr/bin/optool", "/var/mobile/optool"]
                    guard let tool = optools.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
                        return ("optool not found. Install via re-ios-triage skill.", false)
                    }
                    DirectKit.spawnDetached(tool, args: ["install", "-c", "load", "-p", dylib, "-t", main])
                    _ = DirectKit.spawnDetached("/usr/bin/ldid", args: ["-S", main])
                    return ("INJECT_OK (re-signed)", true)
                }
                actionRow("Browse data container", icon: "folder") {
                    guard let cont = app.dataContainer else {
                        return ("(no data container found)", false)
                    }
                    let files = DirectKit.listContainerFiles(cont, depth: 2, limit: 200)
                    return (files.isEmpty ? "(empty)" : files.joined(separator: "\n"), !files.isEmpty)
                }
                actionRow("Backup container", icon: "archivebox") {
                    guard let dest = DirectKit.backupContainer(app) else {
                        return ("Backup failed", false)
                    }
                    return ("BACKUP_OK: " + dest, true)
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

    private func actionRow(_ title: String, icon: String,
                           work: @escaping () -> (String, Bool)) -> some View {
        Button {
            busyAction = title
            DispatchQueue.global(qos: .userInitiated).async {
                let (out, ok) = work()
                DispatchQueue.main.async {
                    outputTitle = title
                    output = out
                    showOutput = true
                    busyAction = nil
                    _ = ok
                }
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
                    setLoading("resign", true)
                    DispatchQueue.global(qos: .userInitiated).async {
                        let ldidBins = ["/usr/bin/ldid", "/usr/local/bin/ldid", "/opt/ldid"]
                        let ld = ldidBins.first { FileManager.default.fileExists(atPath: $0) }
                        var out = "ldid not found in sandbox (apk add ldid)"
                        if let ldBin = ld {
                            let okSpawn = DirectKit.spawnDetached(ldBin, args: ["-S", ipaPath])
                            out = okSpawn ? "RESIGNED: \(ipaPath)" : "spawn failed"
                        }
                        DispatchQueue.main.async {
                            resignOut = out
                            setLoading("resign", false)
                        }
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
                    DispatchQueue.global(qos: .userInitiated).async {
                        let fm = FileManager.default
                        var found: [String] = []
                        for root in ["/var/mobile", "/root"] {
                            if let e = fm.enumerator(atPath: root) {
                                while let p = e.nextObject() as? String {
                                    if p.hasSuffix("Tweak.x") || p.hasSuffix("Tweak.xm") {
                                        found.append(root + "/" + p)
                                        if found.count >= 20 { break }
                                    }
                                }
                            }
                            if found.count >= 20 { break }
                        }
                        DispatchQueue.main.async {
                            theosOut = found.isEmpty ? "(none found)" : found.joined(separator: "\n")
                            setLoading("theos", false)
                        }
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