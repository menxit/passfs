import AppKit
import Darwin
import Dispatch
import Foundation
import FSKit
import OSLog
import ServiceManagement
import SwiftUI

private let passFSAppGroupIdentifier =
    "3943PK2P39.com.menxit.passfs.shared"
private let passFSControlAgentPlistName =
    "com.menxit.passfs.control-agent.plist"

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
                },
                showAbout: {
                    appDelegate.showAbout()
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
        let directory = manager.containerURL(
            forSecurityApplicationGroupIdentifier: passFSAppGroupIdentifier
        )?.appendingPathComponent("Logs", isDirectory: true) ?? manager
            .urls(for: .cachesDirectory, in: .userDomainMask)[0]
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
    let showAbout: () -> Void

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

        Button(action: showAbout) {
            Label(localized("About PassFS"), systemImage: "info.circle")
        }

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
    private var aboutWindow: NSWindow?
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

    func showAbout() {
        if let aboutWindow {
            NSApplication.shared.activate(ignoringOtherApps: true)
            aboutWindow.makeKeyAndOrderFront(nil)
            return
        }

        let contentSize = PassFSAboutView.contentSize
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = localized("About PassFS")
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(
            rootView: PassFSAboutView()
        )
        window.setContentSize(contentSize)
        window.center()
        aboutWindow = window

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

private struct PassFSAboutView: View {
    static let contentSize = NSSize(width: 560, height: 400)

    private let applicationVersion = PassFSBuildInfo.applicationVersion
    private let applicationBuild = PassFSBuildInfo.applicationBuild
    private let backendVersion = PassFSBuildInfo.backendVersion

    var body: some View {
        VStack(spacing: 18) {
            Image(nsImage: NSImage(named: "PassFS") ?? NSApp.applicationIconImage)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 104, height: 104)

            Text("PassFS")
                .font(.system(size: 30, weight: .bold))

            VStack(spacing: 5) {
                Text(localizedFormat(
                    "Application version: %@ (%@)",
                    applicationVersion,
                    applicationBuild
                ))
                Text(localizedFormat(
                    "Go backend version: %@",
                    backendVersion
                ))
            }
            .font(.system(size: 15, weight: .semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .frame(maxWidth: .infinity)

            Text(localized(
                "Copyright © 2026 passfs contributors. All rights reserved."
            ))
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 440)
        }
        .padding(.horizontal, 48)
        .padding(.vertical, 34)
        .frame(
            width: Self.contentSize.width,
            height: Self.contentSize.height
        )
    }
}

private enum PassFSBuildInfo {
    static let applicationVersion = value(
        in: .main,
        key: "CFBundleShortVersionString"
    )
    static let applicationBuild = value(in: .main, key: "CFBundleVersion")
    static let backendVersion: String = {
        let bundle = Bundle(
            url: Bundle.main.bundleURL
                .appendingPathComponent("Contents")
                .appendingPathComponent("Helpers")
                .appendingPathComponent("PassFSCLI.bundle")
        )
        return bundle?.object(
            forInfoDictionaryKey: "PassFSBackendVersion"
        ) as? String ?? value(
            in: bundle,
            key: "CFBundleShortVersionString"
        )
    }()

    private static func value(in bundle: Bundle?, key: String) -> String {
        bundle?.object(forInfoDictionaryKey: key) as? String ?? "—"
    }
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
        let buildVersion = Bundle.main.object(
            forInfoDictionaryKey: "PassFSBackendVersion"
        ) as? String ?? ""
        let isDevelopmentBuild = buildVersion.contains("-dev")
        PassFSSetupLog.write(
            "Gatekeeper accepted=\(assessment.accepted); \(assessment.detail)",
            isError: !assessment.accepted && !isDevelopmentBuild
        )
        if !assessment.accepted && !isDevelopmentBuild {
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
    case recovery = "Recovery"
    case ignored = "Ignored"
    case settings = "Settings"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .unprotected:
            return "exclamationmark.shield.fill"
        case .protected:
            return "lock.shield.fill"
        case .recovery:
            return "arrow.uturn.backward.circle.fill"
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
    @State private var pendingRecoveryPurge: PassFSFile?

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
                case .recovery:
                    fileList(
                        files: model.filtered(model.recovery, search: search),
                        emptyText: "No files need recovery",
                        actionTitle: "Restore link",
                        action: { model.restoreRecovery($0) },
                        secondaryActionTitle: "Purge",
                        secondaryAction: { pendingRecoveryPurge = $0 }
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
            localizedFormat(
                "Permanently purge %@?",
                pendingRecoveryPurge?.title ?? localized("file")
            ),
            isPresented: Binding(
                get: { pendingRecoveryPurge != nil },
                set: { if !$0 { pendingRecoveryPurge = nil } }
            ),
            presenting: pendingRecoveryPurge
        ) { file in
            Button("Cancel", role: .cancel) {}
            Button("Purge", role: .destructive) {
                model.purgeRecovery(file)
                pendingRecoveryPurge = nil
            }
        } message: { _ in
            Text("This permanently deletes the encrypted copy. Stop PassFS first. This action cannot be undone.")
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
                            : navigation.tab == .recovery
                                ? "Deleted and replaced links remain encrypted until you restore or explicitly purge them."
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
        case .recovery:
            return "arrow.uturn.backward.circle.fill"
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
        case .recovery:
            return .orange
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

                    HStack(alignment: .center, spacing: 12) {
                        settingLabel(
                            "Authorization scope",
                            detail: "Limit which subsequent opens reuse an authorization."
                        )
                        Spacer()
                        Picker("", selection: $model.unlockScope) {
                            Text("Once").tag("once")
                            Text("File").tag("file")
                            Text("Process").tag("process")
                            Text("Vault").tag("vault")
                        }
                        .labelsHidden()
                        .frame(width: 120)
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

                Text("Backup and Restore")
                    .font(.headline)

                VStack(spacing: 0) {
                    HStack(alignment: .center, spacing: 12) {
                        settingLabel(
                            "Create backup",
                            detail: "Temporarily stops PassFS, copies the encrypted vault, verifies every file, then restores its previous state."
                        )
                        Spacer()
                        Button("Create…") {
                            model.createBackup()
                        }
                    }
                    .padding(.vertical, 12)

                    Divider()

                    HStack(alignment: .center, spacing: 12) {
                        settingLabel(
                            "Verify backup",
                            detail: "Checks the manifest, checksums, and decryption without changing the backup."
                        )
                        Spacer()
                        Button("Verify…") {
                            model.verifyBackup()
                        }
                    }
                    .padding(.vertical, 12)

                    Divider()

                    HStack(alignment: .center, spacing: 12) {
                        settingLabel(
                            "Restore backup",
                            detail: "Restores only into a new directory and can make the restored vault active."
                        )
                        Spacer()
                        Button("Restore…") {
                            model.restoreBackup()
                        }
                    }
                    .padding(.vertical, 12)

                    if let operation = model.backupOperation {
                        Divider()
                        HStack(spacing: 9) {
                            ProgressView()
                                .controlSize(.small)
                            Text(operation)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                        .padding(.vertical, 12)
                    } else if let message = model.backupStatusMessage {
                        Divider()
                        Label(message, systemImage: "checkmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.green)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 12)
                    }
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

private struct UIFileRecord: Decodable {
    let path: String
    let project: String
    let size: Int64
    let lastOpenedUnixNano: Int64
    let preview: String?
}

private struct RecoveryRecord: Decodable {
    let path: String
    let project: String
    let state: String
    let observedUnixNano: Int64
    let size: UInt64
}

private struct UISnapshotRecord: Decodable {
    let unprotected: [UIFileRecord]?
    let protected: [UIFileRecord]
    let recovery: [RecoveryRecord]
    let ignored: [UIFileRecord]
    let touchID: Bool
    let unlockDurationNanoseconds: Int64
    let unlockScope: String
    let initialized: Bool
    let mounted: Bool
    let availableUpdate: String?
}

@MainActor
private final class PassFSModel: ObservableObject {
    @Published var unprotected: [PassFSFile] = []
    @Published var protected: [PassFSFile] = []
    @Published var recovery: [PassFSFile] = []
    @Published var ignored: [PassFSFile] = []
    @Published var touchIDEnabled = true
    @Published var unlockMinutes = 0
    @Published var unlockScope = "once"
    @Published var initialized = false
    @Published var mounted = false
    @Published var availableUpdate: String?
    @Published var busy = false
    @Published private(set) var pendingFilePaths = Set<String>()
    @Published var showsBusyIndicator = false
    @Published var refreshing = false
    @Published var errorMessage: String?
    @Published var backupOperation: String?
    @Published var backupStatusMessage: String?
    private var lastRefresh: Date?
    private var refreshInProgress = false
    private var queuedRefresh = false
    private var queuedScan = false
    private var managerVisible = false
    private var managerScanTask: Task<Void, Never>?
    var keepManagerVisible: (() -> Void)?

    private static let openRefreshMaximumAge: TimeInterval = 60
    private static let managerScanInterval = Duration.milliseconds(2_500)

    init() {
        PassFSCommands.registerControlAgentIfNeeded()
        let installed = Bundle.main.bundleURL.pathExtension == "app"
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
            recovery = snapshot.recovery
            ignored = snapshot.ignored
            touchIDEnabled = snapshot.touchID
            unlockMinutes = snapshot.unlockMinutes
            unlockScope = snapshot.unlockScope
            initialized = snapshot.initialized
            mounted = snapshot.mounted
            availableUpdate = snapshot.availableUpdate
            lastRefresh = Date()
            if !silent { errorMessage = nil }
        } catch {
            if !silent || lastRefresh == nil {
                errorMessage = error.localizedDescription
            }
        }
    }

    func setManagerVisible(_ visible: Bool) {
        managerVisible = visible
        updateManagerScanLoop()
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

    func restoreRecovery(_ file: PassFSFile) {
        let previous = recovery
        runOptimisticAction(
            ["recovery", "restore", file.path],
            apply: {
                self.recovery.removeAll { $0.path == file.path }
            },
            rollback: {
                self.recovery = previous
            }
        )
    }

    func purgeRecovery(_ file: PassFSFile) {
        let previous = recovery
        runOptimisticAction(
            ["recovery", "purge", "--yes", file.path],
            apply: {
                self.recovery.removeAll { $0.path == file.path }
            },
            rollback: {
                self.recovery = previous
            }
        )
    }

    func setTouchID(_ enabled: Bool) {
        let previous = touchIDEnabled
        let arguments = enabled
            ? ["touchid", "enable", "--prompt", "native"]
            : ["touchid", "disable"]
        let commands = mounted ? [arguments, ["reload"]] : [arguments]
        performAction(
            commands,
            showsProgress: false,
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
            "--unlock-scope", minutes == 0 ? "once" : unlockScope,
        ]]
        performAction(
            commands,
            showsProgress: true,
            apply: {},
            rollback: {}
        )
    }

    func createBackup() {
        guard !busy, initialized else { return }
        let panel = NSSavePanel()
        panel.title = localized("Create PassFS Backup")
        panel.prompt = localized("Create Backup")
        panel.canCreateDirectories = true
        let date = String(
            ISO8601DateFormatter().string(from: Date()).prefix(10)
        )
        panel.nameFieldStringValue = localizedFormat(
            "PassFS Backup %@",
            date
        )
        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }
        performBackupAction(
            [
                "backup", "create", "--prompt", "native",
                "--restart-service", destination.path,
            ],
            progress: "Creating and verifying backup…",
            success: localizedFormat(
                "Backup created and verified at %@.",
                destination.path
            )
        )
    }

    func verifyBackup() {
        guard !busy, initialized,
              let backup = chooseBackupDirectory(
                  title: "Verify PassFS Backup",
                  prompt: "Verify Backup"
              ) else { return }
        performBackupAction(
            ["backup", "verify", "--prompt", "native", backup.path],
            progress: "Verifying backup…",
            success: localizedFormat(
                "Backup %@ was verified successfully.",
                backup.path
            )
        )
    }

    func restoreBackup() {
        guard !busy, initialized,
              let backup = chooseBackupDirectory(
                  title: "Restore PassFS Backup",
                  prompt: "Choose Backup"
              ) else { return }

        let destinationPanel = NSSavePanel()
        destinationPanel.title = localized("Choose a New Vault Directory")
        destinationPanel.prompt = localized("Choose")
        destinationPanel.canCreateDirectories = true
        destinationPanel.nameFieldStringValue = localized(
            "PassFS Restored Vault"
        )
        guard destinationPanel.runModal() == .OK,
              let destination = destinationPanel.url else { return }

        let choice = restoredVaultChoice(destination: destination)
        guard choice != .cancel else { return }
        let activate = choice == .restoreAndUse
        var arguments = [
            "backup", "restore", "--prompt", "native",
            "--vault", destination.path,
        ]
        if activate {
            arguments.append("--activate")
        }
        arguments.append(backup.path)
        performBackupAction(
            arguments,
            progress: "Verifying and restoring backup…",
            success: activate
                ? localizedFormat(
                    "Backup restored to %@ and made active.",
                    destination.path
                )
                : localizedFormat(
                    "Backup restored to %@.",
                    destination.path
                )
        )
    }

    private enum RestoredVaultChoice {
        case restoreAndUse
        case restoreOnly
        case cancel
    }

    private func chooseBackupDirectory(
        title: String,
        prompt: String
    ) -> URL? {
        let panel = NSOpenPanel()
        panel.title = localized(title)
        panel.prompt = localized(prompt)
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    private func restoredVaultChoice(
        destination: URL
    ) -> RestoredVaultChoice {
        let alert = NSAlert()
        alert.messageText = localized("Use the restored vault?")
        alert.informativeText = localizedFormat(
            "PassFS will restore the backup to %@. You can make it active now or leave the current vault unchanged.",
            destination.path
        )
        alert.alertStyle = .informational
        alert.addButton(withTitle: localized("Restore and Use"))
        alert.addButton(withTitle: localized("Restore Only"))
        alert.addButton(withTitle: localized("Cancel"))
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            return .restoreAndUse
        case .alertSecondButtonReturn:
            return .restoreOnly
        default:
            return .cancel
        }
    }

    private func performBackupAction(
        _ arguments: [String],
        progress: String,
        success: String
    ) {
        guard !busy else { return }
        busy = true
        showsBusyIndicator = true
        errorMessage = nil
        backupStatusMessage = nil
        backupOperation = localized(progress)
        keepManagerVisible?()
        Task {
            do {
                _ = try await Task.detached(priority: .userInitiated) {
                    try PassFSCommands.run(arguments)
                }.value
                backupStatusMessage = success
            } catch {
                errorMessage = error.localizedDescription
            }
            backupOperation = nil
            busy = false
            showsBusyIndicator = false
            await refresh(silent: true, includeScan: false)
            keepManagerVisible?()
        }
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
    let recovery: [PassFSFile]
    let ignored: [PassFSFile]
    let touchID: Bool
    let unlockMinutes: Int
    let unlockScope: String
    let initialized: Bool
    let mounted: Bool
    let availableUpdate: String?
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
    private enum AgentOperation: String, Encodable {
        case uiSnapshot = "ui-snapshot"
        case gatekeeperAssessment = "gatekeeper-assessment"
        case reload
        case unmount
        case update
        case initialize
        case initializeNative = "initialize-native"
        case initializeSetup = "initialize-setup"
        case touchIDEnable = "touch-id-enable"
        case touchIDDisable = "touch-id-disable"
        case changePassphrase = "change-passphrase"
        case configureUnlock = "configure-unlock"
        case encrypt
        case ignore
        case unignore
        case unprotect
        case recoveryRestore = "recovery-restore"
        case recoveryPurge = "recovery-purge"
        case backupCreate = "backup-create"
        case backupVerify = "backup-verify"
        case backupRestore = "backup-restore"
    }

    private struct AgentRequest: Encodable {
        let version = 3
        let operation: AgentOperation
        let path: String?
        let destination: String?
        let duration: String?
        let scope: String?
        let includeScan: Bool?
        let activate: Bool?

        init(
            operation: AgentOperation,
            path: String? = nil,
            destination: String? = nil,
            duration: String? = nil,
            scope: String? = nil,
            includeScan: Bool? = nil,
            activate: Bool? = nil
        ) {
            self.operation = operation
            self.path = path
            self.destination = destination
            self.duration = duration
            self.scope = scope
            self.includeScan = includeScan
            self.activate = activate
        }
    }

    private struct AgentResponse: Decodable {
        let version: Int
        let success: Bool
        let output: String?
        let error: String?
    }

    private struct GatekeeperRecord: Decodable {
        let accepted: Bool
        let detail: String
    }

    static var executable: URL {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("Helpers")
            .appendingPathComponent("PassFSCLI.bundle")
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("passfs-cli")
    }

    private static var usesControlAgent: Bool {
        FileManager.default.fileExists(
            atPath: Bundle.main.bundleURL
                .appendingPathComponent("Contents")
                .appendingPathComponent("Library")
                .appendingPathComponent("LaunchAgents")
                .appendingPathComponent(passFSControlAgentPlistName)
                .path
        )
    }

    static func registerControlAgentIfNeeded() {
        guard usesControlAgent else { return }
        let service = SMAppService.agent(
            plistName: passFSControlAgentPlistName
        )
        let defaultsKey = "PassFSRegisteredControlAgentBuild"
        let build = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String ?? "unknown"
        do {
            if service.status == .enabled,
               UserDefaults.standard.string(forKey: defaultsKey) != build {
                try service.unregister()
            }
            if service.status == .notRegistered {
                try service.register()
            }
            if service.status == .enabled {
                UserDefaults.standard.set(build, forKey: defaultsKey)
            }
        } catch {
            Logger(
                subsystem: "com.menxit.passfs",
                category: "ControlAgent"
            ).error("Unable to register control agent: \(error.localizedDescription, privacy: .public)")
        }
    }

    static func run(_ arguments: [String]) throws -> String {
        if usesControlAgent {
            return try runThroughControlAgent(arguments)
        }
        return try runDirectly(arguments)
    }

    private static func runDirectly(_ arguments: [String]) throws -> String {
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

    private static func runThroughControlAgent(
        _ arguments: [String]
    ) throws -> String {
        let service = SMAppService.agent(
            plistName: passFSControlAgentPlistName
        )
        if service.status == .notRegistered {
            do {
                try service.register()
            } catch {
                throw PassFSCommandError(
                    detail: "Could not register the PassFS control agent: \(error.localizedDescription)"
                )
            }
        }
        switch service.status {
        case .enabled:
            break
        case .requiresApproval:
            throw PassFSCommandError(
                detail: "Allow PassFS under System Settings > General > Login Items, then try again."
            )
        case .notFound:
            throw PassFSCommandError(
                detail: "The PassFS control agent is missing from the application bundle."
            )
        case .notRegistered:
            throw PassFSCommandError(
                detail: "The PassFS control agent is not registered."
            )
        @unknown default:
            throw PassFSCommandError(
                detail: "The PassFS control agent has an unknown status."
            )
        }

        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: passFSAppGroupIdentifier
        ) else {
            throw PassFSCommandError(
                detail: "The PassFS shared container is unavailable. Reinstall the signed application."
            )
        }
        let socketPath = container
            .appendingPathComponent("Control", isDirectory: true)
            .appendingPathComponent("agent.sock", isDirectory: false)
            .path
        let descriptor = try connectToControlAgent(socketPath)
        defer { Darwin.close(descriptor) }

        var noSignal: Int32 = 1
        _ = withUnsafePointer(to: &noSignal) {
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                $0,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        var request = try JSONEncoder().encode(
            agentRequest(for: arguments)
        )
        request.append(0x0a)
        try writeAll(request, to: descriptor)
        _ = shutdown(descriptor, SHUT_WR)
        let responseData = try readAll(from: descriptor)
        let response = try JSONDecoder().decode(
            AgentResponse.self,
            from: responseData
        )
        guard response.version == 3 else {
            throw PassFSCommandError(
                detail: "The PassFS control agent uses an unsupported protocol."
            )
        }
        guard response.success else {
            throw PassFSCommandError(
                detail: response.error ?? "PassFS command failed"
            )
        }
        return response.output ?? ""
    }

    // The UI may keep CLI-shaped commands for the unsigned development
    // fallback, but the privileged boundary is a closed typed protocol. No
    // executable name or flag is serialized to the control agent.
    private static func agentRequest(
        for arguments: [String]
    ) throws -> AgentRequest {
        switch arguments {
        case ["__ui-status"]:
            return AgentRequest(
                operation: .uiSnapshot,
                includeScan: true
            )
        case ["__ui-status", "--no-scan"]:
            return AgentRequest(
                operation: .uiSnapshot,
                includeScan: false
            )
        case ["__gatekeeper-assessment"]:
            return AgentRequest(operation: .gatekeeperAssessment)
        case ["reload"]:
            return AgentRequest(operation: .reload)
        case ["unmount"]:
            return AgentRequest(operation: .unmount)
        case ["update"]:
            return AgentRequest(operation: .update)
        case ["init"]:
            return AgentRequest(operation: .initialize)
        case ["init", "--prompt", "native"]:
            return AgentRequest(operation: .initializeNative)
        case ["init", "--prompt", "native", "--no-open"]:
            return AgentRequest(operation: .initializeSetup)
        case ["touchid", "enable", "--prompt", "native"]:
            return AgentRequest(operation: .touchIDEnable)
        case ["touchid", "disable"]:
            return AgentRequest(operation: .touchIDDisable)
        case ["passwd", "--prompt", "native"]:
            return AgentRequest(operation: .changePassphrase)
        default:
            break
        }

        if arguments.count == 2 {
            let path = arguments[1]
            switch arguments[0] {
            case "encrypt":
                return AgentRequest(operation: .encrypt, path: path)
            case "ignore":
                return AgentRequest(operation: .ignore, path: path)
            case "unignore":
                return AgentRequest(operation: .unignore, path: path)
            default:
                break
            }
        }
        if arguments.count == 5,
           arguments[0] == "config",
           arguments[1] == "--unlock-for",
           arguments[3] == "--unlock-scope" {
            return AgentRequest(
                operation: .configureUnlock,
                duration: arguments[2],
                scope: arguments[4]
            )
        }
        if arguments.count == 5,
           Array(arguments[0..<4]) == [
               "unprotect", "--yes", "--prompt", "native",
           ] {
            return AgentRequest(
                operation: .unprotect,
                path: arguments[4]
            )
        }
        if arguments.count == 6,
           Array(arguments[0..<5]) == [
               "unprotect", "--yes", "--prompt", "native", "--",
           ] {
            return AgentRequest(
                operation: .unprotect,
                path: arguments[5]
            )
        }
        if arguments.count == 3,
           arguments[0] == "recovery",
           arguments[1] == "restore" {
            return AgentRequest(
                operation: .recoveryRestore,
                path: arguments[2]
            )
        }
        if arguments.count == 4,
           arguments[0] == "recovery",
           arguments[1] == "purge",
           arguments[2] == "--yes" {
            return AgentRequest(
                operation: .recoveryPurge,
                path: arguments[3]
            )
        }
        if arguments.count == 6,
           Array(arguments[0..<5]) == [
               "backup", "create", "--prompt", "native",
               "--restart-service",
           ] {
            return AgentRequest(
                operation: .backupCreate,
                path: arguments[5]
            )
        }
        if arguments.count == 5,
           Array(arguments[0..<4]) == [
               "backup", "verify", "--prompt", "native",
           ] {
            return AgentRequest(
                operation: .backupVerify,
                path: arguments[4]
            )
        }
        if arguments.count == 7,
           Array(arguments[0..<5]) == [
               "backup", "restore", "--prompt", "native", "--vault",
           ] {
            return AgentRequest(
                operation: .backupRestore,
                path: arguments[6],
                destination: arguments[5],
                activate: false
            )
        }
        if arguments.count == 8,
           Array(arguments[0..<5]) == [
               "backup", "restore", "--prompt", "native", "--vault",
           ],
           arguments[6] == "--activate" {
            return AgentRequest(
                operation: .backupRestore,
                path: arguments[7],
                destination: arguments[5],
                activate: true
            )
        }
        throw PassFSCommandError(
            detail: "This operation is not available through the PassFS control agent."
        )
    }

    private static func connectToControlAgent(
        _ path: String
    ) throws -> Int32 {
        let pathBytes = Array(path.utf8)
        let sample = sockaddr_un()
        guard pathBytes.count < MemoryLayout.size(ofValue: sample.sun_path)
        else {
            throw PassFSCommandError(
                detail: "The PassFS control socket path is too long."
            )
        }

        let deadline = Date().addingTimeInterval(5)
        var lastError = ENOENT
        repeat {
            let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            if descriptor < 0 {
                lastError = errno
                break
            }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &address.sun_path) { buffer in
                buffer.initializeMemory(as: UInt8.self, repeating: 0)
                buffer.copyBytes(from: pathBytes)
            }
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(
                        descriptor,
                        $0,
                        socklen_t(MemoryLayout<sockaddr_un>.size)
                    )
                }
            }
            if result == 0 {
                return descriptor
            }
            lastError = errno
            Darwin.close(descriptor)
            if lastError != ENOENT && lastError != ECONNREFUSED {
                break
            }
            usleep(50_000)
        } while Date() < deadline
        throw PassFSCommandError(
            detail: "Could not connect to the PassFS control agent: \(String(cString: strerror(lastError)))"
        )
    }

    private static func writeAll(
        _ data: Data,
        to descriptor: Int32
    ) throws {
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw PassFSCommandError(
                        detail: "Could not send a command to PassFS: \(String(cString: strerror(errno)))"
                    )
                }
                offset += count
            }
        }
    }

    private static func readAll(from descriptor: Int32) throws -> Data {
        let maximumSize = 16 * 1024 * 1024
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { return result }
            if count < 0 {
                if errno == EINTR { continue }
                throw PassFSCommandError(
                    detail: "Could not read the PassFS response: \(String(cString: strerror(errno)))"
                )
            }
            guard result.count + count <= maximumSize else {
                throw PassFSCommandError(
                    detail: "The PassFS response is too large."
                )
            }
            result.append(contentsOf: buffer.prefix(count))
        }
    }

    static func fsKitFilesystemMounted() -> Bool {
        (try? loadSnapshot(includeScan: false).mounted) ?? false
    }

    static func gatekeeperAssessment() -> (
        accepted: Bool,
        detail: String
    ) {
        do {
            let record = try JSONDecoder().decode(
                GatekeeperRecord.self,
                from: Data(try run(["__gatekeeper-assessment"]).utf8)
            )
            return (record.accepted, record.detail)
        } catch {
            return (
                false,
                "unable to run Gatekeeper assessment: \(error.localizedDescription)"
            )
        }
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
                record: $0,
                protected: false,
                ignored: false
            )
        }
        let ignored = snapshot.ignored.map {
            makeFile(
                record: $0,
                protected: false,
                ignored: true
            )
        }
        let protected = snapshot.protected.map {
            makeFile(
                record: $0,
                protected: true,
                ignored: false
            )
        }
        let recovery = snapshot.recovery.map { record in
            PassFSFile(
                path: record.path,
                title: URL(fileURLWithPath: record.path).lastPathComponent,
                project: record.project,
                size: Int64(clamping: record.size),
                lastOpened: Date(
                    timeIntervalSince1970:
                        Double(record.observedUnixNano) / 1_000_000_000
                ),
                preview: record.state == "conflict"
                    ? localized("Conflicting file replaced the protected link")
                    : localized("Protected link was deleted"),
                protected: true,
                ignored: false
            )
        }
        let newestFirst: (PassFSFile, PassFSFile) -> Bool = {
            $0.lastOpened > $1.lastOpened
        }
        return PassFSSnapshot(
            unprotected: unprotected?.sorted(by: newestFirst),
            protected: protected.sorted(by: newestFirst),
            recovery: recovery.sorted(by: newestFirst),
            ignored: ignored.sorted(by: newestFirst),
            touchID: snapshot.touchID,
            unlockMinutes: max(
                0,
                Int(snapshot.unlockDurationNanoseconds / 60_000_000_000)
            ),
            unlockScope: snapshot.unlockScope,
            initialized: snapshot.initialized,
            mounted: snapshot.mounted,
            availableUpdate: snapshot.availableUpdate
        )
    }

    private static func makeFile(
        record: UIFileRecord,
        protected: Bool,
        ignored: Bool
    ) -> PassFSFile {
        let url = URL(fileURLWithPath: record.path)
        let lastOpened = record.lastOpenedUnixNano > 0
            ? Date(
                timeIntervalSince1970:
                    Double(record.lastOpenedUnixNano) / 1_000_000_000
            )
            : .distantPast
        return PassFSFile(
            path: record.path,
            title: url.lastPathComponent,
            project: record.project,
            size: record.size,
            lastOpened: lastOpened,
            preview: protected
                ? localized("Encrypted by PassFS")
                : ignored
                    ? localized("Ignored by the secret scanner")
                    : record.preview ?? localized("Secret-bearing file"),
            protected: protected,
            ignored: ignored
        )
    }
}

private struct PassFSCommandError: LocalizedError {
    let detail: String
    var errorDescription: String? {
        detail.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
