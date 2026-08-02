import Foundation
import ServiceManagement

private let agentPlistName = "com.menxit.passfs.control-agent.plist"

private enum Command: String {
    case register
    case unregister
    case status
}

private func statusName(_ status: SMAppService.Status) -> String {
    switch status {
    case .notRegistered:
        return "not-registered"
    case .enabled:
        return "enabled"
    case .requiresApproval:
        return "requires-approval"
    case .notFound:
        return "not-found"
    @unknown default:
        return "unknown-\(status.rawValue)"
    }
}

private func register(_ service: SMAppService) throws {
    let retryDelays: [TimeInterval] = [0.25, 0.75, 1.5]
    for attempt in 0...retryDelays.count {
        do {
            try service.register()
            return
        } catch let error as NSError {
            guard error.domain == "SMAppServiceErrorDomain",
                  error.code == 1,
                  attempt < retryDelays.count else {
                throw error
            }
            Thread.sleep(forTimeInterval: retryDelays[attempt])
        }
    }
}

guard CommandLine.arguments.count == 2,
      let command = Command(rawValue: CommandLine.arguments[1]) else {
    FileHandle.standardError.write(
        Data("usage: passfs-control-service register|unregister|status\n".utf8)
    )
    exit(2)
}

let service = SMAppService.agent(plistName: agentPlistName)

do {
    switch command {
    case .register:
        switch service.status {
        case .notRegistered, .notFound:
            try register(service)
        case .enabled, .requiresApproval:
            break
        @unknown default:
            break
        }
    case .unregister:
        switch service.status {
        case .enabled, .requiresApproval:
            try service.unregister()
        case .notRegistered, .notFound:
            break
        @unknown default:
            break
        }
    case .status:
        break
    }
    print(statusName(service.status))
} catch {
    FileHandle.standardError.write(
        Data("passfs-control-service: \(error.localizedDescription)\n".utf8)
    )
    exit(1)
}
