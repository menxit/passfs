import AppKit
import CoreServices
import Darwin
import Dispatch
import Foundation
import FSKit
import OSLog
import ServiceManagement
import SwiftUI

@main
struct PassFSMenuApp: App {
    @NSApplicationDelegateAdaptor(PassFSAppDelegate.self)
    private var appDelegate
    @StateObject private var model = PassFSModel()

    var body: some Scene {
        MenuBarExtra {
            PassFSMenuControls(
                model: model,
                open: { tab in
                    appDelegate.showManager(tab: tab)
                }
            )
                .task {
                    await model.refreshIfStale()
                }
                .onReceive(
                    NotificationCenter.default.publisher(
                        for: .passFSFilesystemChanged
                    )
                ) { _ in
                    Task {
                        await model.refresh(silent: true, includeScan: false)
                    }
                }
        } label: {
            PassFSStatusIcon()
                .task {
                    appDelegate.configure(model: model)
                    await model.loadInitialSnapshot()
                }
        }
        .menuBarExtraStyle(.menu)
    }
}

private func localized(_ key: String) -> String {
    Bundle.main.localizedString(forKey: key, value: key, table: nil)
}

private func localizedFormat(
    _ key: String,
    _ arguments: CVarArg...
) -> String {
    String(
        format: localized(key),
        locale: Locale.current,
        arguments: arguments
    )
}

private enum PassFSSetupLog {
    private static let logger = Logger(
        subsystem: "com.menxit.passfs",
        category: "FSKitSetup"
    )
    private static let queue = DispatchQueue(
        label: "com.menxit.passfs.setup-log",
        qos: .utility
    )
    private static let maximumSize: UInt64 = 1_000_000

    static var url: URL {
        let manager = FileManager.default
        let home = manager.homeDirectoryForCurrentUser
        let current = home.appendingPathComponent(".passfs", isDirectory: true)
        let legacy = home
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("passfs", isDirectory: true)
        let currentConfig = current.appendingPathComponent("config.json")
        let legacyConfig = legacy.appendingPathComponent("config.json")
        let directory = manager.fileExists(atPath: currentConfig.path) ||
            !manager.fileExists(atPath: legacyConfig.path)
            ? current
            : legacy
        return directory
            .appendingPathComponent("setup.log", isDirectory: false)
    }

    static func write(_ message: String, isError: Bool = false) {
        if isError {
            logger.error("\(message, privacy: .public)")
        } else {
            logger.notice("\(message, privacy: .public)")
        }
        queue.async {
            append(message)
        }
    }

    static func prepare() -> URL {
        queue.sync {
            prepareFile()
            return url
        }
    }

    private static func prepareFile() {
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        try? manager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        if let attributes = try? manager.attributesOfItem(atPath: url.path),
           let size = attributes[.size] as? UInt64,
           size >= maximumSize {
            let previous = directory.appendingPathComponent("setup.log.1")
            try? manager.removeItem(at: previous)
            try? manager.moveItem(at: url, to: previous)
        }
        if !manager.fileExists(atPath: url.path) {
            manager.createFile(
                atPath: url.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            )
        }
    }

    private static func append(_ message: String) {
        prepareFile()
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let normalized = message.replacingOccurrences(of: "\n", with: " | ")
        guard let data = "\(timestamp) \(normalized)\n".data(using: .utf8),
              let handle = try? FileHandle(forWritingTo: url) else {
            return
        }
        defer {
            try? handle.close()
        }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            logger.error(
                "Unable to append setup diagnostics: \(error.localizedDescription, privacy: .public)"
            )
        }
    }
}

private struct PassFSStatusIcon: View {
    var body: some View {
        Image(nsImage: PassFSMenuIcon.image)
            .renderingMode(.template)
            .frame(width: 18, height: 18)
            .accessibilityLabel("PassFS")
    }
}

private struct PassFSMenuControls: View {
    @ObservedObject var model: PassFSModel
    let open: (PassFSTab) -> Void

    var body: some View {
        Label(
            localized(model.mounted
                ? "Protected filesystem is running"
                : "Protected filesystem is stopped"),
            systemImage: model.mounted
                ? "checkmark.circle.fill"
                : "stop.circle.fill"
        )

        Button {
            if model.mounted {
                model.stop()
            } else {
                model.start()
            }
        } label: {
            Label(
                localized(model.mounted ? "Stop" : "Start"),
                systemImage: model.mounted ? "stop.fill" : "play.fill"
            )
        }
        .disabled(model.busy)

        Button {
            model.runAction(["update"])
        } label: {
            Label(
                model.availableUpdate.map {
                    localizedFormat("Update PassFS to %@…", $0)
                } ?? localized("PassFS is up to date"),
                systemImage: model.availableUpdate == nil
                    ? "checkmark.circle"
                    : "arrow.down.circle.fill"
            )
        }
        .disabled(model.availableUpdate == nil || model.busy)

        Divider()

        Button {
            open(.unprotected)
        } label: {
            Label(
                localizedFormat(
                    "%lld unprotected secrets",
                    Int64(model.unprotected.count)
                ),
                systemImage: PassFSTab.unprotected.symbol
            )
        }

        Button {
            open(.protected)
        } label: {
            Label(
                localized(PassFSTab.protected.rawValue),
                systemImage: PassFSTab.protected.symbol
            )
        }

        Button {
            open(.settings)
        } label: {
            Label(
                localized(PassFSTab.settings.rawValue),
                systemImage: PassFSTab.settings.symbol
            )
        }

        Divider()

        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            Label(localized("Quit PassFS App"), systemImage: "power")
        }
    }
}

@MainActor
private final class PassFSAppDelegate: NSObject, NSApplicationDelegate {
    private var setupWindow: NSWindow?
    private var managerWindow: NSWindow?
    private let managerNavigation = PassFSManagerNavigation()
    private weak var model: PassFSModel?
    private var receivedFSKitSetupRequest = false
    private var receivedManagerRequest = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            try? await Task.sleep(for: .milliseconds(600))
            guard !receivedFSKitSetupRequest else { return }
            await initializeAndMount()
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        if urls.contains(where: {
            $0.scheme == "passfs" &&
                $0.host == "setup" &&
                $0.path == "/fskit"
        }) {
            receivedFSKitSetupRequest = true
            showFSKitSetup()
        }
        if urls.contains(where: {
            $0.scheme == "passfs" &&
                $0.host == "manage"
        }) {
            receivedManagerRequest = true
            showManager()
        }
    }

    private func initializeAndMount() async {
        do {
            _ = try await Task.detached(priority: .userInitiated) {
                try PassFSCommands.run(["init", "--prompt", "native"])
            }.value
            NotificationCenter.default.post(
                name: .passFSFilesystemChanged,
                object: nil
            )
        } catch {
            NotificationCenter.default.post(
                name: .passFSFilesystemChanged,
                object: nil
            )
            let detail = error.localizedDescription
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if detail.localizedCaseInsensitiveContains(
                "authorization cancelled"
            ) {
                return
            }
            if detail.localizedCaseInsensitiveContains("fskit") ||
                detail.localizedCaseInsensitiveContains(
                    "file system extension"
                ) {
                showFSKitSetup()
                return
            }
            showStartupError(detail)
        }
    }

    private func showStartupError(_ detail: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.icon = NSImage(named: "PassFS")
        alert.messageText = localized(
            "PassFS couldn’t start the protected filesystem"
        )
        alert.informativeText = detail.isEmpty
            ? localized("Open PassFS from the menu bar to try again.")
            : detail
        alert.addButton(withTitle: localized("OK"))
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    func configure(model: PassFSModel) {
        self.model = model
        model.keepManagerVisible = { [weak self] in
            self?.keepManagerVisible()
        }
        if receivedManagerRequest {
            showManager()
        }
    }

    func showManager(tab: PassFSTab? = nil) {
        guard let model else {
            receivedManagerRequest = true
            return
        }
        if let tab {
            managerNavigation.tab = tab
        }
        model.setManagerVisible(true)
        receivedManagerRequest = false
        Task {
            await model.refresh(silent: true)
        }
        if let managerWindow {
            NSApplication.shared.activate(ignoringOtherApps: true)
            managerWindow.makeKeyAndOrderFront(nil)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 680),
            styleMask: [
                .titled,
                .closable,
                .miniaturizable,
                .resizable,
            ],
            backing: .buffered,
            defer: false
        )
        window.title = localized("PassFS")
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 680, height: 560)
        window.setFrameAutosaveName("PassFSManagerWindow")
        window.center()
        window.contentViewController = NSHostingController(
            rootView: PassFSManagerView(
                model: model,
                navigation: managerNavigation
            )
        )
        managerWindow = window
        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.model?.setManagerVisible(false)
                self?.managerWindow = nil
            }
        }

        NSApplication.shared.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func keepManagerVisible() {
        guard let managerWindow else {
            showManager()
            return
        }
        NSApplication.shared.unhide(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        managerWindow.deminiaturize(nil)
        managerWindow.orderFrontRegardless()
        managerWindow.makeKey()
    }

    func showFSKitSetup() {
        if let setupWindow {
            NSApplication.shared.activate(ignoringOtherApps: true)
            setupWindow.makeKeyAndOrderFront(nil)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 640),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = localized("Enable PassFS")
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.center()
        window.contentViewController = NSHostingController(
            rootView: FSKitSetupView {
                window.close()
            }
        )
        setupWindow = window
        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.setupWindow = nil
            }
        }

        NSApplication.shared.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }
}

private extension Notification.Name {
    static let passFSFilesystemChanged = Notification.Name(
        "com.menxit.passfs.filesystem-changed"
    )
}

private struct FSKitSetupView: View {
    let close: () -> Void
    @StateObject private var model = FSKitSetupModel()

    var body: some View {
        VStack(spacing: 18) {
            HStack(alignment: .top, spacing: 14) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .renderingMode(.original)
                    .frame(width: 42, height: 42)

                VStack(alignment: .leading, spacing: 5) {
                    Text(localized(model.mounted
                        ? "PassFS is ready"
                        : "Allow PassFS to mount protected files"))
                        .font(.title3.weight(.semibold))
                    Text(localized(model.mounted
                        ? "The protected filesystem is mounted and available."
                        : "Enable PassFS under File System Extensions in System Settings. PassFS will continue automatically."))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if model.mounted {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 34))
                        .foregroundStyle(.green)
                } else if model.busy || model.checkingModuleStatus {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Image(systemName: model.headerStatusSymbol)
                        .font(.system(size: 30))
                        .foregroundStyle(model.moduleStatusColor)
                }
            }

            Divider()

            if model.mounted {
                VStack(spacing: 14) {
                    Image(systemName: "externaldrive.fill.badge.checkmark")
                        .font(.system(size: 58))
                        .foregroundStyle(.green)
                    Text("No further action is required.")
                        .font(.headline)
                    Text("You can manage PassFS from its menu bar icon.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(alignment: .center, spacing: 16) {
                        Image(systemName: "externaldrive.badge.plus")
                            .font(.system(size: 52))
                            .foregroundStyle(Color.accentColor)
                            .accessibilityHidden(true)

                        VStack(alignment: .leading, spacing: 3) {
                            Text("Enable the protected filesystem")
                                .font(.headline)
                            Text("PassFS uses Apple FSKit and does not install a kernel extension.")
                                .foregroundStyle(.secondary)
                        }
                    }

                    Label(
                        "macOS manages this one-time approval in System Settings.",
                        systemImage: "checkmark.shield"
                    )
                    .foregroundStyle(.secondary)

                    VStack(alignment: .leading, spacing: 0) {
                        HStack(spacing: 12) {
                            ZStack {
                                Circle()
                                    .fill(model.moduleStatusColor.opacity(0.16))
                                    .frame(width: 38, height: 38)
                                Image(systemName: "externaldrive.fill")
                                    .font(.system(size: 17, weight: .semibold))
                                    .foregroundStyle(model.moduleStatusColor)
                            }

                            VStack(alignment: .leading, spacing: 2) {
                                Text("PassFS File System Extension")
                                    .font(.headline)
                                Text(model.moduleStatusText)
                                    .font(.callout)
                                    .foregroundStyle(model.moduleStatusColor)
                            }

                            Spacer()

                            if model.checkingModuleStatus {
                                ProgressView()
                                    .controlSize(.small)
                            } else {
                                Circle()
                                    .fill(model.moduleStatusColor)
                                    .frame(width: 10, height: 10)
                                    .accessibilityHidden(true)
                            }
                        }
                        .padding(16)

                        Divider()

                        VStack(alignment: .leading, spacing: 16) {
                            FSKitSetupStep(
                                number: 1,
                                title: "Open File System Extensions",
                                detail: "Use the button below to open Apple's dedicated FSKit settings pane."
                            )
                            FSKitSetupStep(
                                number: 2,
                                title: "Turn on PassFS",
                                detail: "Enable PassFS in the list. PassFS will detect the change automatically."
                            )
                        }
                        .padding(16)
                    }
                    .background(
                        Color(nsColor: .windowBackgroundColor),
                        in: RoundedRectangle(cornerRadius: 12)
                    )
                    .overlay {
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(nsColor: .separatorColor))
                    }

                    if let moduleMessage = model.moduleMessage {
                        Text(moduleMessage)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }

                    if let gatekeeperMessage = model.gatekeeperMessage {
                        Label(
                            gatekeeperMessage,
                            systemImage: "exclamationmark.shield.fill"
                        )
                        .font(.callout)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                    }

                    if let message = model.message, !message.isEmpty {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(
                                model.hasError ? Color.red : Color.secondary
                            )
                            .textSelection(.enabled)
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    Color(nsColor: .controlBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 14)
                )

                HStack {
                    Button("Open File System Extensions") {
                        FSKitSetupModel.openSystemSettings()
                    }
                    .buttonStyle(.borderedProminent)

                    if model.hasError {
                        Button("Try Mounting Again") {
                            Task { await model.retryMount() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.busy)
                    }

                    if model.busy {
                        ProgressView()
                            .controlSize(.small)
                        Text("Starting PassFS…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Button("Open Diagnostics") {
                        FSKitSetupModel.openDiagnostics()
                    }
                    .buttonStyle(.link)
                }
            }

            HStack {
                Text(localized(model.mounted
                    ? "PassFS mounted automatically."
                    : "PassFS will initialize and mount as soon as approval completes."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(action: close) {
                    Text(localized(model.mounted ? "Done" : "Hide Guide"))
                }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(18)
        .frame(minWidth: 680, minHeight: 590)
        .task {
            await model.monitor()
        }
    }

}

private struct FSKitSetupStep: View {
    let number: Int
    let title: LocalizedStringKey
    let detail: LocalizedStringKey

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.callout.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 26, height: 26)
                .background(Color.accentColor, in: Circle())

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

@MainActor
private final class FSKitSetupModel: ObservableObject {
    @Published var mounted = false
    @Published var busy = false
    @Published var message: String?
    @Published var hasError = false
    @Published var moduleEnabled: Bool?
    @Published var moduleInstalled = false
    @Published var moduleMessage: String?
    @Published var checkingModuleStatus = true
    @Published var gatekeeperMessage: String?
    private var retriedAfterEnable = false
    private var lastLoggedModuleState: String?

    var moduleStatusColor: Color {
        if checkingModuleStatus {
            return .secondary
        }
        if moduleEnabled == true {
            return .green
        }
        if moduleEnabled == false {
            return .orange
        }
        return .red
    }

    var headerStatusSymbol: String {
        if moduleEnabled == true {
            return "checkmark.circle.fill"
        }
        if moduleInstalled {
            return "exclamationmark.circle.fill"
        }
        return "xmark.circle.fill"
    }

    var moduleStatusText: String {
        if checkingModuleStatus {
            return localized("Checking extension status…")
        }
        if moduleEnabled == true {
            return localized("Enabled")
        }
        if moduleEnabled == false {
            return localized("Approval required")
        }
        return localized("Extension not detected")
    }

    static func openSystemSettings() {
        PassFSSetupLog.write(
            "Opening the dedicated File System Extensions settings pane"
        )
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.fskit.fsmodule"
        ) else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    static func openDiagnostics() {
        NSWorkspace.shared.open(PassFSSetupLog.prepare())
    }

    func monitor() async {
        let build = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String ?? "unknown"
        PassFSSetupLog.write(
            "FSKit setup started; app=\(Bundle.main.bundlePath); build=\(build)"
        )
        await assessGatekeeper()
        mounted = await Task.detached(priority: .utility) {
            PassFSCommands.fsKitFilesystemMounted()
        }.value
        PassFSSetupLog.write("Filesystem mounted=\(mounted)")
        while !Task.isCancelled {
            await refreshModuleStatus()
            if mounted {
                PassFSSetupLog.write("FSKit setup completed successfully")
                NotificationCenter.default.post(
                    name: .passFSFilesystemChanged,
                    object: nil
                )
                return
            }
            if moduleEnabled == true &&
                !retriedAfterEnable &&
                !busy {
                retriedAfterEnable = true
                await retryMount()
                if mounted {
                    return
                }
            }
            // FSKit does not publish an approval-change notification. A
            // two-second check keeps the one-time setup responsive without
            // waking an unattended Mac more than necessary.
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func assessGatekeeper() async {
        let assessment = await Task.detached(priority: .utility) {
            PassFSCommands.gatekeeperAssessment()
        }.value
        PassFSSetupLog.write(
            "Gatekeeper accepted=\(assessment.accepted); \(assessment.detail)",
            isError: !assessment.accepted
        )
        if !assessment.accepted {
            gatekeeperMessage = localized(
                "This PassFS build is not notarized by Apple. Install a notarized PassFS package before enabling its File System Extension."
            )
        }
    }

    private func refreshModuleStatus() async {
        guard #available(macOS 15.4, *) else {
            moduleInstalled = false
            moduleEnabled = nil
            checkingModuleStatus = false
            moduleMessage = localized(
                "This version of macOS does not provide FSKit."
            )
            logModuleState("unsupported")
            return
        }

        let result: (
            installed: Bool,
            enabled: Bool?,
            error: String?
        ) = await withCheckedContinuation { continuation in
            FSClient.shared.fetchInstalledExtensions { modules, error in
                if let error {
                    continuation.resume(
                        returning: (false, nil, error.localizedDescription)
                    )
                    return
                }
                let module = modules?.first {
                    $0.bundleIdentifier == "com.menxit.passfs.filesystem"
                }
                continuation.resume(
                    returning: (module != nil, module?.isEnabled, nil)
                )
            }
        }
        moduleInstalled = result.installed
        moduleEnabled = result.enabled
        checkingModuleStatus = false
        logModuleState(
            "installed=\(result.installed); enabled=\(String(describing: result.enabled)); error=\(result.error ?? "none")"
        )
        if let error = result.error {
            moduleMessage = localizedFormat(
                "Could not check the FSKit extension: %@",
                error
            )
        } else if !result.installed {
            moduleMessage = localized(
                "PassFS is waiting for macOS to register the installed extension."
            )
        } else {
            moduleMessage = nil
        }
    }

    private func logModuleState(_ state: String) {
        guard state != lastLoggedModuleState else {
            return
        }
        lastLoggedModuleState = state
        PassFSSetupLog.write("FSClient state: \(state)")
    }

    func retryMount() async {
        guard !busy else { return }
        PassFSSetupLog.write("Starting automatic PassFS initialization/mount")
        busy = true
        hasError = false
        message = nil
        do {
            let touchIDEnabled = try? await Task.detached(priority: .utility) {
                try PassFSCommands.loadSnapshot(includeScan: false).touchID
            }.value
            if touchIDEnabled == false {
                PassFSSetupLog.write(
                    "Touch ID is disabled; enabling it for the native FSKit adapter"
                )
                _ = try await Task.detached(priority: .userInitiated) {
                    try PassFSCommands.run([
                        "touchid",
                        "enable",
                        "--prompt",
                        "native",
                    ])
                }.value
                PassFSSetupLog.write("Touch ID enabled for FSKit")
            }
            let output = try await Task.detached(priority: .userInitiated) {
                try PassFSCommands.run([
                    "init",
                    "--prompt",
                    "native",
                    "--no-open",
                ])
            }.value
            message = output.trimmingCharacters(in: .whitespacesAndNewlines)
            mounted = PassFSCommands.fsKitFilesystemMounted()
            PassFSSetupLog.write(
                "PassFS initialization/mount finished; mounted=\(mounted); output=\(message ?? "")"
            )
            if mounted {
                NotificationCenter.default.post(
                    name: .passFSFilesystemChanged,
                    object: nil
                )
            }
        } catch {
            message = error.localizedDescription
            hasError = true
            PassFSSetupLog.write(
                "PassFS initialization/mount failed: \(error.localizedDescription)",
                isError: true
            )
        }
        busy = false
    }
}

private enum PassFSMenuIcon {
    static let image: NSImage = {
        let image = NSImage(named: NSImage.Name("PassFSMenuIcon")) ??
            NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "PassFS")!
        image.isTemplate = true
        return image
    }()
}

private enum PassFSTab: String, CaseIterable, Identifiable {
    case unprotected = "Unprotected Secrets"
    case protected = "Protected Files"
    case ignored = "Ignored"
    case settings = "Settings"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .unprotected:
            return "exclamationmark.shield.fill"
        case .protected:
            return "lock.shield.fill"
        case .ignored:
            return "eye.slash.fill"
        case .settings:
            return "slider.horizontal.3"
        }
    }
}

@MainActor
private final class PassFSManagerNavigation: ObservableObject {
    @Published var tab = PassFSTab.unprotected
}

private struct PassFSManagerView: View {
    @ObservedObject var model: PassFSModel
    @ObservedObject var navigation: PassFSManagerNavigation

    var body: some View {
        PassFSPanel(model: model, navigation: navigation)
            .onReceive(
                NotificationCenter.default.publisher(
                    for: .passFSFilesystemChanged
                )
            ) { _ in
                Task {
                    await model.refresh(silent: true, includeScan: false)
                }
            }
    }
}

private struct PassFSPanel: View {
    @ObservedObject var model: PassFSModel
    @ObservedObject var navigation: PassFSManagerNavigation
    @State private var search = ""
    @State private var pendingUnprotect: PassFSFile?

    var body: some View {
        VStack(spacing: 12) {
            header

            Picker("", selection: $navigation.tab) {
                ForEach(PassFSTab.allCases) { tab in
                    Label(localized(tab.rawValue), systemImage: tab.symbol)
                        .tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityLabel("Section")

            if navigation.tab != .settings {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField(
                        "Search files and projects",
                        text: $search
                    )
                    .textFieldStyle(.plain)
                }
                .padding(.horizontal, 10)
                .frame(height: 34)
                .background(
                    Color(nsColor: .controlBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 9)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 9)
                        .stroke(.separator.opacity(0.7), lineWidth: 1)
                }
            }

            Group {
                switch navigation.tab {
                case .unprotected:
                    fileList(
                        files: model.filtered(model.unprotected, search: search),
                        emptyText: "No unprotected secret files found",
                        actionTitle: "Protect",
                        action: { model.protect($0) },
                        secondaryActionTitle: "Ignore",
                        secondaryAction: { model.ignore($0) }
                    )
                case .protected:
                    fileList(
                        files: model.filtered(model.protected, search: search),
                        emptyText: "No protected files",
                        actionTitle: "Unprotect",
                        action: { pendingUnprotect = $0 }
                    )
                case .ignored:
                    fileList(
                        files: model.filtered(model.ignored, search: search),
                        emptyText: "No ignored scan results",
                        actionTitle: "Restore",
                        action: { model.restore($0) }
                    )
                case .settings:
                    SettingsView(model: model)
                }
            }
            .frame(minHeight: 330)

        }
        .padding(20)
        .frame(minWidth: 680, minHeight: 560)
        .alert(
            localizedFormat(
                "Unprotect %@?",
                pendingUnprotect?.title ?? localized("file")
            ),
            isPresented: Binding(
                get: { pendingUnprotect != nil },
                set: { if !$0 { pendingUnprotect = nil } }
            ),
            presenting: pendingUnprotect
        ) { file in
            Button("Cancel", role: .cancel) {}
            Button("Unprotect", role: .destructive) {
                model.unprotect(file)
                pendingUnprotect = nil
            }
        } message: { file in
            Text("The plaintext file will replace its protected link. PassFS authorization is still required.")
        }
        .alert(
            "PassFS",
            isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.errorMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(nsImage: NSApplication.shared.applicationIconImage)
                .resizable()
                .renderingMode(.original)
                .frame(width: 38, height: 38)

            VStack(alignment: .leading, spacing: 2) {
                Text("PassFS")
                    .font(.title2.weight(.semibold))
                Text(model.summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.showsBusyIndicator {
                ProgressView()
                    .controlSize(.small)
            }
            Button {
                Task { await model.refresh(silent: false) }
            } label: {
                Group {
                    if model.refreshing {
                        ProgressView()
                            .controlSize(.mini)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 12, weight: .semibold))
                    }
                }
                .frame(width: 26, height: 26)
                .background(
                    Color.primary.opacity(0.07),
                    in: Circle()
                )
            }
            .buttonStyle(.borderless)
            .disabled(model.busy || model.refreshing)
            .help("Rescan")
        }
    }

    @ViewBuilder
    private func fileList(
        files: [PassFSFile],
        emptyText: String,
        actionTitle: String,
        action: @escaping (PassFSFile) -> Void,
        secondaryActionTitle: String? = nil,
        secondaryAction: ((PassFSFile) -> Void)? = nil
    ) -> some View {
        if files.isEmpty {
            VStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(emptyStateColor.opacity(0.14))
                        .frame(width: 54, height: 54)
                    Image(systemName: emptyStateSymbol)
                        .font(.system(size: 23, weight: .semibold))
                        .foregroundStyle(emptyStateColor)
                }
                Text(localized(emptyText))
                    .font(.headline)
                Text(localized(
                    navigation.tab == .unprotected
                        ? "PassFS scans likely credential and project locations."
                        : navigation.tab == .protected
                            ? "Protect a detected file to see it here."
                            : "Ignored files can be restored to future scans."
                ))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 12, pinnedViews: [.sectionHeaders]) {
                    ForEach(projectGroups(files)) { group in
                        Section {
                            VStack(spacing: 8) {
                                ForEach(group.files) { file in
                                    FileRow(
                                        file: file,
                                        actionTitle: actionTitle,
                                        actionPending: model.pendingFilePaths
                                            .contains(file.path),
                                        actionsDisabled: model.busy,
                                        action: { action(file) },
                                        showInFinder: {
                                            showInFinder(file)
                                        },
                                        secondaryActionTitle: secondaryActionTitle,
                                        secondaryAction: secondaryAction.map {
                                            action in { action(file) }
                                        }
                                    )
                                }
                            }
                        } header: {
                            ProjectHeader(group: group)
                        }
                    }
                }
            }
        }
    }

    private func showInFinder(_ file: PassFSFile) {
        NSWorkspace.shared.activateFileViewerSelecting([
            URL(fileURLWithPath: file.path),
        ])
    }

    private var emptyStateSymbol: String {
        switch navigation.tab {
        case .unprotected:
            return "checkmark.shield.fill"
        case .protected:
            return "lock.shield.fill"
        case .ignored:
            return "eye.slash.fill"
        case .settings:
            return "slider.horizontal.3"
        }
    }

    private var emptyStateColor: Color {
        switch navigation.tab {
        case .unprotected:
            return .green
        case .protected:
            return .blue
        case .ignored, .settings:
            return Color(nsColor: .secondaryLabelColor)
        }
    }

    private func projectGroups(_ files: [PassFSFile]) -> [PassFSProjectGroup] {
        Dictionary(grouping: files, by: \.project)
            .map { project, files in
                PassFSProjectGroup(
                    project: project,
                    files: files.sorted { $0.lastOpened > $1.lastOpened }
                )
            }
            .sorted {
                ($0.files.first?.lastOpened ?? .distantPast) >
                    ($1.files.first?.lastOpened ?? .distantPast)
            }
    }

}

private struct PassFSProjectGroup: Identifiable {
    let project: String
    let files: [PassFSFile]

    var id: String { project }
}

private struct ProjectHeader: View {
    let group: PassFSProjectGroup

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 6)
                    .fill(Color.orange.opacity(0.16))
                    .frame(width: 28, height: 28)
                Image(systemName: "folder.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.orange)
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(group.project)
                    .font(.headline.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(group.files.count == 1
                    ? localized("1 file")
                    : localizedFormat(
                        "%lld files",
                        Int64(group.files.count)
                    ))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            .regularMaterial,
            in: RoundedRectangle(cornerRadius: 10)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator.opacity(0.55), lineWidth: 1)
        }
    }
}

private struct FileRow: View {
    let file: PassFSFile
    let actionTitle: String
    let actionPending: Bool
    let actionsDisabled: Bool
    let action: () -> Void
    let showInFinder: () -> Void
    let secondaryActionTitle: String?
    let secondaryAction: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7)
                    .fill(statusColor.opacity(0.14))
                    .frame(width: 30, height: 30)
                Image(systemName: statusSymbol)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(statusColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(file.title)
                    .font(.system(.body, design: .monospaced, weight: .semibold))
                    .lineLimit(1)
                Label(file.project, systemImage: "folder.fill")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(
                        Color.primary.opacity(0.08),
                        in: Capsule()
                    )
                    .fixedSize()
                Text(file.preview)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                HStack(spacing: 8) {
                    Text(ByteCountFormatter.string(
                        fromByteCount: file.size,
                        countStyle: .file
                    ))
                    Text(localizedFormat(
                        "Opened %@",
                        file.lastOpened.formatted(
                            .relative(presentation: .named)
                        )
                    ))
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
            .help(file.path)

            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 5) {
                HStack(spacing: 6) {
                    Button {
                        showInFinder()
                    } label: {
                        Image(systemName: "folder.fill")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .help("Show in Finder")

                    Button(action: action) {
                        if actionPending {
                            HStack(spacing: 6) {
                                ProgressView()
                                    .controlSize(.mini)
                                Text(localized("Authorizing…"))
                            }
                        } else {
                            Label(
                                localized(actionTitle),
                                systemImage: actionSymbol
                            )
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(actionsDisabled)
                }
                if let secondaryActionTitle, let secondaryAction {
                    Button(action: secondaryAction) {
                        Label(
                            localized(secondaryActionTitle),
                            systemImage: "eye.slash"
                        )
                    }
                    .buttonStyle(.plain)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .disabled(actionsDisabled)
                }
            }
        }
        .padding(11)
        .background(
            Color(nsColor: .controlBackgroundColor),
            in: RoundedRectangle(cornerRadius: 11)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 11)
                .stroke(.separator.opacity(0.45), lineWidth: 1)
        }
        .contextMenu {
            Button {
                showInFinder()
            } label: {
                Label("Show in Finder", systemImage: "folder")
            }
        }
    }

    private var statusSymbol: String {
        if file.ignored {
            return "eye.slash.fill"
        }
        if file.protected {
            return "lock.shield.fill"
        }
        return "exclamationmark.shield.fill"
    }

    private var statusColor: Color {
        if file.ignored {
            return Color(nsColor: .secondaryLabelColor)
        }
        return file.protected ? .green : .orange
    }

    private var actionSymbol: String {
        if file.ignored {
            return "arrow.uturn.backward"
        }
        return file.protected ? "lock.open.fill" : "lock.fill"
    }
}

private struct SettingsView: View {
    @ObservedObject var model: PassFSModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Filesystem")
                    .font(.headline)

                VStack(spacing: 14) {
                    HStack(spacing: 11) {
                        Circle()
                            .fill(model.mounted ? Color.green : Color.red)
                            .frame(width: 12, height: 12)
                            .shadow(
                                color: (model.mounted ? Color.green : Color.red)
                                    .opacity(0.45),
                                radius: 4
                            )
                        VStack(alignment: .leading, spacing: 3) {
                            Text(localized(model.mounted
                                ? "Protected filesystem is running"
                                : "Protected filesystem is stopped"))
                                .font(.body.weight(.semibold))
                            Text(filesystemDetail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }

                    Divider()

                    HStack {
                        Button {
                            model.start()
                        } label: {
                            Label("Start", systemImage: "play.fill")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.mounted || model.busy)

                        Button {
                            model.stop()
                        } label: {
                            Label("Stop", systemImage: "stop.fill")
                        }
                        .buttonStyle(.bordered)
                        .disabled(!model.initialized || !model.mounted || model.busy)

                        Spacer()
                        if model.showsBusyIndicator {
                            ProgressView()
                                .controlSize(.small)
                        }
                    }
                }
                .passFSCard()

                Text("Authorization")
                    .font(.headline)

                VStack(spacing: 0) {
                    HStack {
                        settingLabel(
                            "Touch ID",
                            detail: "Enabled by default for protected files."
                        )
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { model.touchIDEnabled },
                            set: { model.setTouchID($0) }
                        ))
                        .labelsHidden()
                    }
                    .padding(.vertical, 12)

                    Divider()

                    HStack(alignment: .center, spacing: 12) {
                        settingLabel(
                            "Unlock duration",
                            detail: "Use 0 to authorize every file open."
                        )
                        Spacer()
                        TextField(
                            "0",
                            value: $model.unlockMinutes,
                            format: .number
                        )
                            .frame(width: 64)
                            .textFieldStyle(.roundedBorder)
                            .multilineTextAlignment(.center)
                        Text("min")
                            .foregroundStyle(.secondary)
                        Button("Apply") {
                            model.applyUnlockDuration()
                        }
                    }
                    .padding(.vertical, 12)

                    Divider()

                    HStack {
                        settingLabel(
                            "Recovery passphrase",
                            detail: "Replace the passphrase for this vault."
                        )
                        Spacer()
                        Button("Change…") {
                            model.runAction(["passwd", "--prompt", "native"])
                        }
                    }
                    .padding(.vertical, 12)
                }
                .padding(.horizontal, 14)
                .background(
                    .quaternary.opacity(0.45),
                    in: RoundedRectangle(cornerRadius: 12)
                )
                .disabled(!model.initialized || model.busy)
            }
            .padding(.vertical, 4)
        }
    }

    private var filesystemDetail: String {
        if model.mounted {
            return localized(
                "Protected files are available in the PassFS mount."
            )
        }
        if model.initialized {
            return localized("Your vault is initialized and ready to start.")
        }
        return localized("Start once to create the vault and mount PassFS.")
    }

    private func settingLabel(
        _ title: String,
        detail: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(localized(title))
                .font(.body.weight(.medium))
            Text(localized(detail))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private extension View {
    func passFSCard() -> some View {
        padding(14)
            .background(
                .quaternary.opacity(0.45),
                in: RoundedRectangle(cornerRadius: 12)
            )
    }
}

private struct PassFSFile: Identifiable {
    let path: String
    let title: String
    let project: String
    let size: Int64
    let lastOpened: Date
    let preview: String
    let protected: Bool
    let ignored: Bool

    var id: String { path }

    func withProtection(_ protected: Bool) -> PassFSFile {
        PassFSFile(
            path: path,
            title: title,
            project: project,
            size: size,
            lastOpened: lastOpened,
            preview: protected ? localized("Encrypted by PassFS") : preview,
            protected: protected,
            ignored: false
        )
    }

    func withIgnored(_ ignored: Bool) -> PassFSFile {
        PassFSFile(
            path: path,
            title: title,
            project: project,
            size: size,
            lastOpened: lastOpened,
            preview: ignored
                ? localized("Ignored by the secret scanner")
                : preview,
            protected: false,
            ignored: ignored
        )
    }
}

private struct ProtectedRecord: Decodable {
    let path: String
    let size: UInt64
    let modifiedUnixNano: Int64
    let accessedUnixNano: Int64?
}

private struct UISnapshotRecord: Decodable {
    let unprotected: [String]?
    let protected: [ProtectedRecord]
    let ignored: [String]
    let touchID: Bool
    let unlockDurationNanoseconds: Int64
    let initialized: Bool
    let mounted: Bool
    let availableUpdate: String?
    let stateDirectory: String?
    let vaultMetadataDirectory: String?
}

@MainActor
private final class PassFSModel: ObservableObject {
    @Published var unprotected: [PassFSFile] = []
    @Published var protected: [PassFSFile] = []
    @Published var ignored: [PassFSFile] = []
    @Published var touchIDEnabled = true
    @Published var unlockMinutes = 0
    @Published var initialized = false
    @Published var mounted = false
    @Published var availableUpdate: String?
    @Published var busy = false
    @Published private(set) var pendingFilePaths = Set<String>()
    @Published var showsBusyIndicator = false
    @Published var refreshing = false
    @Published var errorMessage: String?
    private var lastRefresh: Date?
    private var refreshInProgress = false
    private var queuedRefresh = false
    private var queuedScan = false
    private var watchedDirectories = Set<String>()
    private var requestedWatchDirectories = Set<String>()
    private var managerVisible = false
    private var managerScanTask: Task<Void, Never>?
    private var filesystemWatchers: [DispatchSourceFileSystemObject] = []
    private var filesystemRefreshTask: Task<Void, Never>?
    var keepManagerVisible: (() -> Void)?

    private static let openRefreshMaximumAge: TimeInterval = 60
    private static let managerScanInterval = Duration.milliseconds(2_500)

    init() {
        let bundlePath = Bundle.main.bundleURL.standardizedFileURL.path
        let userApplications = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications")
            .path + "/"
        let installed = bundlePath.hasPrefix("/Applications/") ||
            bundlePath.hasPrefix(userApplications)
        if installed && SMAppService.mainApp.status == .notRegistered {
            try? SMAppService.mainApp.register()
        }
    }

    var summary: String {
        localizedFormat(
            "%lld unprotected · %lld protected",
            Int64(unprotected.count),
            Int64(protected.count)
        )
    }

    func filtered(_ files: [PassFSFile], search: String) -> [PassFSFile] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return files }
        return files.filter {
            $0.path.localizedCaseInsensitiveContains(query) ||
                $0.project.localizedCaseInsensitiveContains(query)
        }
    }

    func loadInitialSnapshot() async {
        await refresh(silent: true, includeScan: false)
    }

    func refreshIfStale() async {
        if let lastRefresh,
           Date().timeIntervalSince(lastRefresh) < Self.openRefreshMaximumAge {
            return
        }
        // Opening the lightweight menu must never start a repository/home
        // scan. The manager window performs that work in the background when
        // the user actually asks to manage secrets.
        await refresh(silent: true, includeScan: false)
    }

    func refresh(silent: Bool, includeScan: Bool = true) async {
        guard !busy else { return }
        if refreshInProgress {
            queuedRefresh = true
            queuedScan = queuedScan || includeScan
            return
        }
        refreshInProgress = true
        refreshing = !silent
        defer {
            refreshInProgress = false
            refreshing = false
            if queuedRefresh {
                let scan = queuedScan
                queuedRefresh = false
                queuedScan = false
                Task { [weak self] in
                    await self?.refresh(silent: true, includeScan: scan)
                }
            }
        }
        if !silent { errorMessage = nil }
        do {
            let priority: TaskPriority = silent ? .utility : .userInitiated
            let snapshot = try await Task.detached(priority: priority) {
                try PassFSCommands.loadSnapshot(includeScan: includeScan)
            }.value
            if let refreshedUnprotected = snapshot.unprotected {
                unprotected = refreshedUnprotected
            }
            protected = snapshot.protected
            ignored = snapshot.ignored
            touchIDEnabled = snapshot.touchID
            unlockMinutes = snapshot.unlockMinutes
            initialized = snapshot.initialized
            mounted = snapshot.mounted
            availableUpdate = snapshot.availableUpdate
            configureFilesystemWatchers(
                directories: [
                    snapshot.stateDirectory,
                    snapshot.vaultMetadataDirectory,
                ].compactMap { $0 }
            )
            lastRefresh = Date()
            if !silent { errorMessage = nil }
        } catch {
            if !silent || lastRefresh == nil {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func configureFilesystemWatchers(
        directories: [String]
    ) {
        let requested = Set(directories.map {
            URL(fileURLWithPath: $0).standardizedFileURL.path
        })
        requestedWatchDirectories = requested
        rebuildFilesystemWatchers()
    }

    func setManagerVisible(_ visible: Bool) {
        managerVisible = visible
        updateManagerScanLoop()
        rebuildFilesystemWatchers()
    }

    private func updateManagerScanLoop() {
        guard managerVisible else {
            managerScanTask?.cancel()
            managerScanTask = nil
            return
        }
        guard managerScanTask == nil else { return }
        managerScanTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: Self.managerScanInterval)
                } catch {
                    return
                }
                guard let self, self.managerVisible, !Task.isCancelled else {
                    return
                }
                // Refreshing is serialized by refresh(), so a slow scan never
                // overlaps the next one. The immediate refresh in showManager
                // handles opening; this loop keeps deletions and additions in
                // sync while the window remains open.
                await self.refresh(silent: true)
            }
        }
    }

    private func rebuildFilesystemWatchers() {
        let requested = managerVisible ? requestedWatchDirectories : []
        guard requested != watchedDirectories else { return }

        filesystemRefreshTask?.cancel()
        filesystemRefreshTask = nil
        filesystemWatchers.forEach { $0.cancel() }
        filesystemWatchers.removeAll()
        watchedDirectories = requested

        for directory in requested.sorted() {
            let descriptor = open(directory, O_EVTONLY)
            guard descriptor >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: descriptor,
                eventMask: [.write, .delete, .rename],
                queue: .global(qos: .utility)
            )
            source.setEventHandler { [weak self] in
                Task { @MainActor [weak self] in
                    self?.scheduleFilesystemRefresh()
                }
            }
            source.setCancelHandler {
                close(descriptor)
            }
            source.resume()
            filesystemWatchers.append(source)
        }
    }

    private func scheduleFilesystemRefresh() {
        filesystemRefreshTask?.cancel()
        filesystemRefreshTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .milliseconds(300))
            } catch {
                return
            }
            guard let self, !Task.isCancelled else { return }
            await self.refresh(silent: true, includeScan: false)
        }
    }

    func protect(_ file: PassFSFile) {
        let previousUnprotected = unprotected
        let previousProtected = protected
        runAuthorizedFileAction(
            ["encrypt", file.path],
            path: file.path,
            apply: {
                self.unprotected.removeAll { $0.path == file.path }
                self.protected.removeAll { $0.path == file.path }
                self.protected.append(file.withProtection(true))
                self.protected.sort { $0.lastOpened > $1.lastOpened }
            },
            rollback: {
                self.unprotected = previousUnprotected
                self.protected = previousProtected
            }
        )
    }

    func unprotect(_ file: PassFSFile) {
        let previousUnprotected = unprotected
        let previousProtected = protected
        runAuthorizedFileAction(
            ["unprotect", "--yes", "--prompt", "native", file.path],
            path: file.path,
            apply: {
                self.protected.removeAll { $0.path == file.path }
            },
            rollback: {
                self.unprotected = previousUnprotected
                self.protected = previousProtected
            }
        )
    }

    func ignore(_ file: PassFSFile) {
        let previousUnprotected = unprotected
        let previousIgnored = ignored
        runOptimisticAction(
            ["ignore", file.path],
            apply: {
                self.unprotected.removeAll { $0.path == file.path }
                self.ignored.removeAll { $0.path == file.path }
                self.ignored.append(file.withIgnored(true))
                self.ignored.sort { $0.lastOpened > $1.lastOpened }
            },
            rollback: {
                self.unprotected = previousUnprotected
                self.ignored = previousIgnored
            }
        )
    }

    func restore(_ file: PassFSFile) {
        let previousUnprotected = unprotected
        let previousIgnored = ignored
        runOptimisticAction(
            ["unignore", file.path],
            apply: {
                self.ignored.removeAll { $0.path == file.path }
                self.unprotected.removeAll { $0.path == file.path }
                self.unprotected.append(file.withIgnored(false))
                self.unprotected.sort { $0.lastOpened > $1.lastOpened }
            },
            rollback: {
                self.unprotected = previousUnprotected
                self.ignored = previousIgnored
            }
        )
    }

    func setTouchID(_ enabled: Bool) {
        let previous = touchIDEnabled
        let arguments = enabled
            ? ["touchid", "enable", "--prompt", "native"]
            : ["touchid", "disable"]
        runOptimisticAction(
            arguments,
            apply: {
                self.touchIDEnabled = enabled
            },
            rollback: {
                self.touchIDEnabled = previous
            }
        )
    }

    func applyUnlockDuration() {
        let minutes = max(0, unlockMinutes)
        unlockMinutes = minutes
        let commands = [[
            "config", "--unlock-for", "\(minutes)m",
        ]]
        performAction(
            commands,
            showsProgress: true,
            apply: {},
            rollback: {}
        )
    }

    func stop() {
        let previousMounted = mounted
        runOptimisticAction(
            ["unmount"],
            apply: {
                self.mounted = false
            },
            rollback: {
                self.mounted = previousMounted
            }
        )
    }

    func start() {
        let previousInitialized = initialized
        let previousMounted = mounted
        runOptimisticAction(
            ["init"],
            apply: {
                self.initialized = true
                self.mounted = true
            },
            rollback: {
                self.initialized = previousInitialized
                self.mounted = previousMounted
            }
        )
    }

    func runAction(_ arguments: [String]) {
        performAction(
            [arguments],
            showsProgress: true,
            apply: {},
            rollback: {}
        )
    }

    private func runOptimisticAction(
        _ arguments: [String],
        apply: @escaping () -> Void,
        rollback: @escaping () -> Void,
        completion: @escaping () -> Void = {}
    ) {
        performAction(
            [arguments],
            showsProgress: false,
            apply: apply,
            rollback: rollback,
            completion: completion
        )
    }

    private func runAuthorizedFileAction(
        _ arguments: [String],
        path: String,
        apply: @escaping () -> Void,
        rollback: @escaping () -> Void
    ) {
        guard !busy else { return }
        pendingFilePaths.insert(path)
        keepManagerVisible?()
        performAction(
            [arguments],
            showsProgress: false,
            appliesOptimistically: false,
            apply: { [weak self] in
                apply()
                guard let self else { return }
                self.pendingFilePaths.remove(path)
                self.keepManagerVisible?()
            },
            rollback: rollback,
            completion: { [weak self] in
                guard let self else { return }
                self.pendingFilePaths.remove(path)
                self.keepManagerVisible?()
            }
        )
    }

    private func performAction(
        _ commands: [[String]],
        showsProgress: Bool,
        appliesOptimistically: Bool = true,
        apply: @escaping () -> Void,
        rollback: @escaping () -> Void,
        completion: @escaping () -> Void = {}
    ) {
        guard !busy else { return }
        busy = true
        showsBusyIndicator = showsProgress
        errorMessage = nil
        if appliesOptimistically {
            apply()
        }
        Task {
            do {
                _ = try await Task.detached(priority: .userInitiated) {
                    for arguments in commands {
                        _ = try PassFSCommands.run(arguments)
                    }
                }.value
                if !appliesOptimistically {
                    apply()
                }
                busy = false
                showsBusyIndicator = false
                await refresh(silent: true, includeScan: false)
                completion()
            } catch {
                if appliesOptimistically {
                    rollback()
                }
                errorMessage = error.localizedDescription
                busy = false
                showsBusyIndicator = false
                completion()
            }
        }
    }
}

private struct PassFSSnapshot {
    let unprotected: [PassFSFile]?
    let protected: [PassFSFile]
    let ignored: [PassFSFile]
    let touchID: Bool
    let unlockMinutes: Int
    let initialized: Bool
    let mounted: Bool
    let availableUpdate: String?
    let stateDirectory: String?
    let vaultMetadataDirectory: String?
}

private final class PassFSPipeReader: @unchecked Sendable {
    private let handle: FileHandle
    private(set) var data = Data()

    init(_ handle: FileHandle) {
        self.handle = handle
    }

    func start(in group: DispatchGroup) {
        group.enter()
        DispatchQueue.global(qos: .utility).async { [self] in
            data = handle.readDataToEndOfFile()
            group.leave()
        }
    }
}

private enum PassFSCommands {
    static var executable: URL {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("Helpers")
            .appendingPathComponent("PassFSCLI.bundle")
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("passfs-cli")
    }

    static func run(_ arguments: [String]) throws -> String {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["PASSFS_NO_UPDATE_NOTICE"] = "1"
        if ProcessInfo.processInfo.isLowPowerModeEnabled {
            environment["PASSFS_LOW_POWER_MODE"] = "1"
        } else {
            environment.removeValue(forKey: "PASSFS_LOW_POWER_MODE")
        }
        process.environment = environment
        process.standardOutput = output
        process.standardError = errors
        try process.run()
        let outputReader = PassFSPipeReader(output.fileHandleForReading)
        let errorReader = PassFSPipeReader(errors.fileHandleForReading)
        let readers = DispatchGroup()
        outputReader.start(in: readers)
        errorReader.start(in: readers)
        process.waitUntilExit()
        readers.wait()
        let data = outputReader.data
        let errorData = errorReader.data
        if process.terminationStatus != 0 {
            let detail = String(data: errorData, encoding: .utf8) ??
                "PassFS command failed"
            throw PassFSCommandError(detail: detail)
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func fsKitFilesystemMounted() -> Bool {
        (try? loadSnapshot(includeScan: false).mounted) ?? false
    }

    static func gatekeeperAssessment() -> (
        accepted: Bool,
        detail: String
    ) {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = [
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            Bundle.main.bundleURL.path,
        ]
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
        } catch {
            return (
                false,
                "unable to run Gatekeeper assessment: \(error.localizedDescription)"
            )
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let detail = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (
            process.terminationStatus == 0,
            detail?.isEmpty == false ? detail! : "no assessment details"
        )
    }

    static func loadSnapshot(includeScan: Bool) throws -> PassFSSnapshot {
        let decoder = JSONDecoder()
        var arguments = ["__ui-status"]
        if !includeScan {
            arguments.append("--no-scan")
        }
        let snapshot = try decoder.decode(
            UISnapshotRecord.self,
            from: Data(try run(arguments).utf8)
        )
        let unprotected = snapshot.unprotected?.map {
            makeFile(
                path: $0,
                protected: false,
                ignored: false,
                size: nil,
                modified: nil,
                accessed: nil
            )
        }
        let ignored = snapshot.ignored.map {
            makeFile(
                path: $0,
                protected: false,
                ignored: true,
                size: nil,
                modified: nil,
                accessed: nil
            )
        }
        let protected = snapshot.protected.map {
            makeFile(
                path: $0.path,
                protected: true,
                ignored: false,
                size: Int64(clamping: $0.size),
                modified: Date(
                    timeIntervalSince1970: Double($0.modifiedUnixNano) / 1_000_000_000
                ),
                accessed: $0.accessedUnixNano.flatMap {
                    $0 > 0
                        ? Date(
                            timeIntervalSince1970: Double($0) / 1_000_000_000
                        )
                        : nil
                }
            )
        }
        let newestFirst: (PassFSFile, PassFSFile) -> Bool = {
            $0.lastOpened > $1.lastOpened
        }
        return PassFSSnapshot(
            unprotected: unprotected?.sorted(by: newestFirst),
            protected: protected.sorted(by: newestFirst),
            ignored: ignored.sorted(by: newestFirst),
            touchID: snapshot.touchID,
            unlockMinutes: max(
                0,
                Int(snapshot.unlockDurationNanoseconds / 60_000_000_000)
            ),
            initialized: snapshot.initialized,
            mounted: snapshot.mounted,
            availableUpdate: snapshot.availableUpdate,
            stateDirectory: snapshot.stateDirectory,
            vaultMetadataDirectory: snapshot.vaultMetadataDirectory
        )
    }

    private static func makeFile(
        path: String,
        protected: Bool,
        ignored: Bool,
        size: Int64?,
        modified: Date?,
        accessed: Date?
    ) -> PassFSFile {
        let url = URL(fileURLWithPath: path)
        let values = protected
            ? nil
            : try? url.resourceValues(forKeys: [
                .fileSizeKey,
                .contentAccessDateKey,
                .contentModificationDateKey,
            ])
        let lastOpened: Date
        if protected {
            lastOpened = accessed ?? modified ?? .distantPast
        } else {
            lastOpened = spotlightLastUsed(path) ??
                values?.contentAccessDate ??
                modified ??
                values?.contentModificationDate ??
                .distantPast
        }
        return PassFSFile(
            path: path,
            title: url.lastPathComponent,
            project: projectName(for: url),
            size: size ?? Int64(values?.fileSize ?? 0),
            lastOpened: lastOpened,
            preview: protected
                ? localized("Encrypted by PassFS")
                : ignored
                    ? localized("Ignored by the secret scanner")
                    : maskedPreview(url),
            protected: protected,
            ignored: ignored
        )
    }

    private static func spotlightLastUsed(_ path: String) -> Date? {
        guard let item = MDItemCreate(kCFAllocatorDefault, path as CFString),
              let value = MDItemCopyAttribute(item, kMDItemLastUsedDate as CFString)
        else {
            return nil
        }
        return value as? Date
    }

    private static func projectName(for file: URL) -> String {
        var directory = file.deletingLastPathComponent()
        let home = FileManager.default.homeDirectoryForCurrentUser
        while directory.path != "/" && directory.path.count >= home.path.count {
            let git = directory.appendingPathComponent(".git")
            if FileManager.default.fileExists(atPath: git.path) {
                return repositoryName(root: directory, git: git)
            }
            directory.deleteLastPathComponent()
        }
        let parent = file.deletingLastPathComponent().lastPathComponent
        if parent.hasPrefix(".") {
            return localized("Personal credentials")
        }
        return parent.isEmpty ? localized("Personal files") : parent
    }

    private static func repositoryName(root: URL, git: URL) -> String {
        var config = git.appendingPathComponent("config")
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(
            atPath: git.path,
            isDirectory: &isDirectory
        ), !isDirectory.boolValue,
           let pointer = try? String(contentsOf: git, encoding: .utf8),
           let gitDirectory = pointer
            .split(separator: "\n")
            .first(where: { $0.hasPrefix("gitdir:") })
            .map({ $0.dropFirst("gitdir:".count) })
        {
            let path = gitDirectory.trimmingCharacters(in: .whitespaces)
            config = URL(
                fileURLWithPath: path,
                relativeTo: root
            )
            .standardizedFileURL
            .appendingPathComponent("config")
        }
        guard let text = try? String(contentsOf: config, encoding: .utf8)
        else {
            return root.lastPathComponent
        }
        var inOrigin = false
        for rawLine in text.split(
            separator: "\n",
            omittingEmptySubsequences: false
        ) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") {
                inOrigin = line == "[remote \"origin\"]"
                continue
            }
            guard inOrigin, line.hasPrefix("url"),
                  let separator = line.firstIndex(of: "=")
            else {
                continue
            }
            let remote = line[line.index(after: separator)...]
                .trimmingCharacters(in: .whitespaces)
            let normalized = remote.replacingOccurrences(of: "\\", with: "/")
            let component = normalized
                .split(whereSeparator: { $0 == "/" || $0 == ":" })
                .last
                .map(String.init) ?? ""
            let name = component.hasSuffix(".git")
                ? String(component.dropLast(4))
                : component
            if !name.isEmpty {
                return name
            }
        }
        return root.lastPathComponent
    }

    private static func maskedPreview(_ url: URL) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return "Secret-bearing file"
        }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: 16 * 1024)) ?? Data()
        guard let text = String(data: data, encoding: .utf8) else {
            return "Binary credential or private key"
        }
        if text.contains("PRIVATE KEY-----") {
            return "Private key material"
        }
        var keys: [String] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#") else { continue }
            let separators = ["=", ":"]
            if let separator = separators.compactMap({ line.firstIndex(of: Character($0)) }).min(),
               separator != line.startIndex {
                let key = line[..<separator]
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
                if !key.isEmpty {
                    keys.append("\(key)=••••••")
                }
            }
            if keys.count == 2 { break }
        }
        return keys.isEmpty ? "Secret token detected" : keys.joined(separator: "  ")
    }
}

private struct PassFSCommandError: LocalizedError {
    let detail: String
    var errorDescription: String? {
        detail.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
