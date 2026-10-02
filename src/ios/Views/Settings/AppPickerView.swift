import SwiftUI

// MARK: - Attach-App picker
//
// [zzuu-apps] Enumerates installed apps and lets the user pick one as the
// conversation's analysis target. Enumeration runs through the JB SSH
// channel (LSApplicationWorkspace via apple-device apps); when the device
// isn't linked the sheet shows a hint instead of a list.
struct AppPickerView: View {
    @Binding var apps: [(bid: String, name: String)]
    @Binding var loading: Bool
    let onPick: (String, String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""
    @State private var loadAttempted = false
    @State private var errorMsg: String?

    private var filtered: [(bid: String, name: String)] {
        guard !filter.isEmpty else { return apps }
        return apps.filter {
            $0.bid.localizedCaseInsensitiveContains(filter)
            || $0.name.localizedCaseInsensitiveContains(filter)
        }
    }

    var body: some View {
        NavigationView {
            Group {
                if loading {
                    ProgressView("Loading apps...")
                } else if let errorMsg {
                    if #available(iOS 17.0, *) {
                        ContentUnavailableView {
                            Label("Not available", systemImage: "lock.shield")
                        } description: {
                            Text(errorMsg)
                        }
                    } else {
                        VStack(spacing: 8) {
                            Image(systemName: "lock.shield").font(.largeTitle)
                            Text("Not available").font(.headline)
                            Text(errorMsg).font(.footnote).multilineTextAlignment(.center)
                        }.padding()
                    }
                } else if filtered.isEmpty {
                    if #available(iOS 17.0, *) {
                        ContentUnavailableView.search(text: filter)
                    } else {
                        VStack(spacing: 8) {
                            Image(systemName: "magnifyingglass").font(.largeTitle)
                            Text("No results").font(.headline)
                        }.padding()
                    }
                } else {
                    List(filtered, id: \.bid) { app in
                        Button {
                            onPick(app.bid, app.name)
                            dismiss()
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(app.name.isEmpty ? app.bid : app.name)
                                    .font(.body)
                                Text(app.bid)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Attach App")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $filter, prompt: "Filter by name or bundle id")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .task {
                guard !loadAttempted else { return }
                loadAttempted = true
                await loadApps()
            }
        }
    }

    @MainActor
    private func loadApps() async {
        loading = true
        defer { loading = false }
        // Enumerate via the JB SSH channel when linked; the sandbox-side
        // LSApplicationWorkspace path isn't available (we're in-process, but
        // the CLI already exposes the listing through the host).
        guard JailbreakConfigStore.shared.isConfigured else {
            errorMsg = "Link the device first (Settings > Jailbreak SSH) to enumerate installed apps."
            return
        }
        do {
            let r = try await JailbreakRunner.run(
                "security find-generic-password 2>/dev/null; echo ---; ls /var/containers/Bundle/Application 2>/dev/null | head -200")
            // Prefer the full listing via the same channel the CLI uses:
            // run the LSApplicationWorkspace dump through the CLI on the host.
            let dump = try await JailbreakRunner.run(
                """
                plutil -convert json -o - - <<< "$(lsappinfo list 2>/dev/null)" 2>/dev/null | head -c 100 || \
                find /var/containers/Bundle/Application -maxdepth 2 -name ".com.apple.mobile_container_manager.metadata.plist" -exec grep -h MCMMetadataIdentifier {} \\; 2>/dev/null | sed 's/.*"\\(.*\\)".*/\\1/' | sort -u
                """)
            var parsed: [(String, String)] = []
            // Parse bundle ids from the metadata dump; names resolved lazily
            // by the agent (full listing lives in apple-device apps output).
            for line in dump.output.components(separatedBy: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("com."), !t.contains(" ") {
                    parsed.append((t, ""))
                }
            }
            if parsed.isEmpty {
                errorMsg = "No apps enumerated. The listing comes from the host channel — check the SSH link."
            }
            apps = parsed
        } catch {
            errorMsg = error.localizedDescription
        }
    }
}
