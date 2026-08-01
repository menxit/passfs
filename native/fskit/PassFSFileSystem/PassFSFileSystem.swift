import Foundation
import FSKit
import OSLog

extension Logger {
    static let passfs = Logger(
        subsystem: "com.menxit.passfs.filesystem",
        category: "FSKit"
    )
}

@objc
final class PassFSFileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
    private var resource: FSPathURLResource?
    private var volume: PassFSVolume?

    func probeResource(
        resource: FSResource,
        replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        guard let pathResource = resource as? FSPathURLResource else {
            Logger.passfs.error("Probe rejected an unsupported resource")
            replyHandler(nil, POSIXError(.ENODEV))
            return
        }
        guard pathResource.url.startAccessingSecurityScopedResource() else {
            replyHandler(nil, POSIXError(.EACCES))
            return
        }
        defer { pathResource.url.stopAccessingSecurityScopedResource() }
        guard let containerUUID = passFSVolumeUUID(at: pathResource.url) else {
            Logger.passfs.error("Probe rejected a vault with an invalid identifier")
            replyHandler(nil, POSIXError(.EINVAL))
            return
        }
        let identifier = FSContainerIdentifier(
            uuid: containerUUID
        )
        Logger.passfs.info(
            "Probe accepted resource; container=\(containerUUID.uuidString, privacy: .public)"
        )
        replyHandler(
            .usable(
                name: "passfs",
                containerID: identifier
            ),
            nil
        )
    }

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        Logger.passfs.info("Loading passfs resource")
        guard self.resource == nil, volume == nil else {
            Logger.passfs.error("Load rejected because a resource is already active")
            replyHandler(nil, POSIXError(.EBUSY))
            return
        }
        guard let pathResource = resource as? FSPathURLResource else {
            Logger.passfs.error("Load rejected an unsupported resource")
            replyHandler(nil, POSIXError(.EINVAL))
            return
        }
        for option in options.taskOptions where option == "-f" {
            Logger.passfs.error("Force loading is unsupported")
            replyHandler(nil, POSIXError(.ENOTSUP))
            return
        }
        guard pathResource.url.startAccessingSecurityScopedResource() else {
            Logger.passfs.error("Unable to access the security-scoped resource")
            replyHandler(nil, POSIXError(.EACCES))
            return
        }
        do {
            let configuration = try passFSConfiguration(options)
            let bridge = try PassFSBridge(
                vaultPath: pathResource.url.path,
                maximumFileSize: configuration.maximumFileSize,
                unlockDurationNanoseconds: configuration.unlockDurationNanoseconds,
                authorizationMode: configuration.authorizationMode ?? UInt32(
                    PASSFS_AUTHORIZATION_TOUCH_ID
                )
            )
            let volume = try PassFSVolume(
                bridge: bridge,
                volumeUUID: bridge.volumeUUID
            )
            self.resource = pathResource
            self.volume = volume
            containerStatus = .ready
            Logger.passfs.info(
                "Resource ready; volume=\(bridge.volumeUUID.uuidString, privacy: .public); unlockDurationNs=\(configuration.unlockDurationNanoseconds, privacy: .public)"
            )
            replyHandler(volume, nil)
        } catch {
            pathResource.url.stopAccessingSecurityScopedResource()
            Logger.passfs.error("Unable to load passfs: \(error.localizedDescription)")
            replyHandler(nil, error)
        }
    }

    func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        Logger.passfs.info("Unloading passfs resource")
        guard let pathResource = resource as? FSPathURLResource,
              let loadedResource = self.resource,
              loadedResource.url == pathResource.url else {
            Logger.passfs.error("Unload rejected an inactive resource")
            replyHandler(POSIXError(.EINVAL))
            return
        }
        volume?.shutdown()
        volume = nil
        self.resource = nil
        loadedResource.url.stopAccessingSecurityScopedResource()
        Logger.passfs.info("Passfs resource unloaded")
        replyHandler(nil)
    }
}

private struct PassFSPublicConfiguration: Decodable {
    let volumeId: String
}

private func passFSVolumeUUID(at vault: URL) -> UUID? {
    let configuration = vault
        .appendingPathComponent(".passfs", isDirectory: true)
        .appendingPathComponent("config.json", isDirectory: false)
    guard let data = try? Data(contentsOf: configuration),
          let publicConfiguration = try? JSONDecoder().decode(
              PassFSPublicConfiguration.self,
              from: data
          ) else {
        return nil
    }
    let identifier = publicConfiguration.volumeId
    guard identifier.count == 32,
          identifier.allSatisfy({ $0.isHexDigit }) else {
        return nil
    }
    let parts = [8, 4, 4, 4, 12]
    var offset = identifier.startIndex
    var components: [String] = []
    for length in parts {
        guard let end = identifier.index(
            offset,
            offsetBy: length,
            limitedBy: identifier.endIndex
        ) else {
            return nil
        }
        components.append(String(identifier[offset..<end]))
        offset = end
    }
    return UUID(uuidString: components.joined(separator: "-"))
}

struct PassFSConfiguration {
    var maximumFileSize: Int64 = 16 * 1024 * 1024
    var unlockDurationNanoseconds: Int64 = 0
    var authorizationMode: UInt32?
}

func passFSConfiguration(
    _ taskOptions: FSTaskOptions
) throws -> PassFSConfiguration {
    var configuration = PassFSConfiguration()
    var values: [String] = []
    var index = 0
    while index < taskOptions.taskOptions.count {
        let option = taskOptions.taskOptions[index]
        if option == "-o", index + 1 < taskOptions.taskOptions.count {
            index += 1
            values.append(contentsOf: taskOptions.taskOptions[index].split(
                separator: ","
            ).map(String.init))
        } else if option.hasPrefix("-o"), option.count > 2 {
            values.append(contentsOf: option.dropFirst(2).split(
                separator: ","
            ).map(String.init))
        }
        index += 1
    }

    for value in values {
        let parts = value.split(separator: "=", maxSplits: 1).map(String.init)
        switch parts.first {
        case "max-file-size":
            guard parts.count == 2,
                  let size = Int64(parts[1]),
                  size > 0 else {
                throw POSIXError(.EINVAL)
            }
            configuration.maximumFileSize = size
        case "unlock-duration-ns":
            guard parts.count == 2,
                  let duration = Int64(parts[1]),
                  duration >= 0 else {
                throw POSIXError(.EINVAL)
            }
            configuration.unlockDurationNanoseconds = duration
        case "authorization":
            guard parts.count == 2 else {
                throw POSIXError(.EINVAL)
            }
            switch parts[1] {
            case "touchid":
                configuration.authorizationMode = UInt32(
                    PASSFS_AUTHORIZATION_TOUCH_ID
                )
            case "passphrase":
                configuration.authorizationMode = UInt32(
                    PASSFS_AUTHORIZATION_PASSPHRASE
                )
            default:
                throw POSIXError(.EINVAL)
            }
        case "debug", "nobrowse", "rw":
            break
        case "ro", "rdonly":
            throw POSIXError(.EROFS)
        case .none:
            break
        default:
            throw POSIXError(.EINVAL)
        }
    }
    return configuration
}
