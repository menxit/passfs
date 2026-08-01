import Darwin
import Foundation

struct BridgeDirectoryEntry: Decodable {
    let name: String
    let attributes: BridgeAttributes
}

struct BridgeAttributes: Decodable {
    let itemType: UInt32
    let mode: UInt32
    let uid: UInt32
    let gid: UInt32
    let linkCount: UInt32
    let inode: UInt64
    let parentInode: UInt64
    let size: UInt64
    let blocks: UInt64
    let accessTimeNanoseconds: Int64
    let changeTimeNanoseconds: Int64
    let modifyTimeNanoseconds: Int64
    let birthTimeNanoseconds: Int64

    init(_ attributes: passfs_attributes) {
        itemType = attributes.item_type
        mode = attributes.mode
        uid = attributes.uid
        gid = attributes.gid
        linkCount = attributes.link_count
        inode = attributes.inode
        parentInode = attributes.parent_inode
        size = attributes.size
        blocks = attributes.blocks
        accessTimeNanoseconds = attributes.access_time_ns
        changeTimeNanoseconds = attributes.change_time_ns
        modifyTimeNanoseconds = attributes.modify_time_ns
        birthTimeNanoseconds = attributes.birth_time_ns
    }
}

func bridgePOSIXError(_ code: Int32) -> POSIXError {
    POSIXError(POSIXError.Code(rawValue: code) ?? .EIO)
}

func throwBridgeError(_ code: Int32) throws {
    guard code == 0 else {
        throw bridgePOSIXError(code)
    }
}

private func bridgeFailure(
    _ message: UnsafeMutablePointer<CChar>?,
    fallback: String,
    code: Int32
) -> NSError {
    defer {
        if let message {
            passfs_bridge_free(message)
        }
    }
    return NSError(
        domain: "com.menxit.passfs.fskit",
        code: Int(code),
        userInfo: [
            NSLocalizedDescriptionKey: message.map { String(cString: $0) }
                ?? fallback,
        ]
    )
}

final class PassFSBridge {
    private(set) var identifier: UInt64
    let volumeUUID: UUID

    init(
        vaultPath: String,
        maximumFileSize: Int64 = 16 * 1024 * 1024,
        unlockDurationNanoseconds: Int64 = 0,
        unlockScope: UInt32 = UInt32(PASSFS_UNLOCK_ONCE),
        authorizationMode: UInt32 = UInt32(PASSFS_AUTHORIZATION_TOUCH_ID)
    ) throws {
        var errorMessage: UnsafeMutablePointer<CChar>?
        identifier = vaultPath.withCString { path in
            passfs_bridge_open_file_system(
                path,
                maximumFileSize,
                unlockDurationNanoseconds,
                unlockScope,
                authorizationMode,
                &errorMessage
            )
        }
        guard identifier != 0 else {
            throw bridgeFailure(
                errorMessage,
                fallback: "Unable to load the passfs volume",
                code: EIO
            )
        }
        guard let volumeID = passfs_bridge_volume_id(identifier) else {
            _ = passfs_bridge_close_file_system(identifier)
            identifier = 0
            throw NSError(
                domain: "com.menxit.passfs.fskit",
                code: Int(EINVAL),
                userInfo: [
                    NSLocalizedDescriptionKey: "The passfs vault has an invalid volume identifier"
                ]
            )
        }
        defer { passfs_bridge_free(volumeID) }
        guard let parsedUUID = UUID(uuidString: String(cString: volumeID)) else {
            _ = passfs_bridge_close_file_system(identifier)
            identifier = 0
            throw NSError(
                domain: "com.menxit.passfs.fskit",
                code: Int(EINVAL),
                userInfo: [
                    NSLocalizedDescriptionKey: "The passfs vault has an invalid volume identifier"
                ]
            )
        }
        volumeUUID = parsedUUID
        if let errorMessage {
            passfs_bridge_free(errorMessage)
        }
    }

    deinit {
        close()
    }

    func close() {
        guard identifier != 0 else {
            return
        }
        _ = passfs_bridge_close_file_system(identifier)
        identifier = 0
    }

    func configure(
        maximumFileSize: Int64,
        unlockDurationNanoseconds: Int64,
        unlockScope: UInt32,
        authorizationMode: UInt32?
    ) throws {
        var errorMessage: UnsafeMutablePointer<CChar>?
        let code = passfs_bridge_configure_file_system(
            identifier,
            maximumFileSize,
            unlockDurationNanoseconds,
            unlockScope,
            authorizationMode ?? UInt32(
                PASSFS_AUTHORIZATION_UNCHANGED
            ),
            &errorMessage
        )
        guard code == 0 else {
            throw bridgeFailure(
                errorMessage,
                fallback: "Unable to configure the passfs volume",
                code: code
            )
        }
        if let errorMessage {
            passfs_bridge_free(errorMessage)
        }
    }

    func lookup(path: String) throws -> BridgeAttributes {
        var attributes = passfs_attributes()
        let code = path.withCString {
            passfs_bridge_lookup(identifier, $0, &attributes)
        }
        try throwBridgeError(code)
        return BridgeAttributes(attributes)
    }

    func readDirectory(path: String) throws -> [BridgeDirectoryEntry] {
        var bytes: UnsafeMutableRawPointer?
        var length = 0
        let code = path.withCString {
            passfs_bridge_read_directory(identifier, $0, &bytes, &length)
        }
        try throwBridgeError(code)
        guard length != 0, let bytes else {
            return []
        }
        defer {
            passfs_bridge_free(bytes)
        }
        return try JSONDecoder().decode(
            [BridgeDirectoryEntry].self,
            from: Data(bytes: bytes, count: length)
        )
    }

    func open(path: String, flags: UInt32) throws -> PassFSBridgeHandle {
        var errorCode: Int32 = 0
        let handle = path.withCString {
            passfs_bridge_open(identifier, $0, flags, &errorCode)
        }
        guard handle != 0 else {
            throw bridgePOSIXError(errorCode == 0 ? EIO : errorCode)
        }
        return PassFSBridgeHandle(identifier: handle)
    }

    func create(
        parent: String,
        name: String,
        mode: UInt32
    ) throws -> (
        attributes: BridgeAttributes,
        handle: PassFSBridgeHandle
    ) {
        var attributes = passfs_attributes()
        var handleIdentifier: UInt64 = 0
        let code = parent.withCString { parentPointer in
            name.withCString { namePointer in
                passfs_bridge_create(
                    identifier,
                    parentPointer,
                    namePointer,
                    mode,
                    &attributes,
                    &handleIdentifier
                )
            }
        }
        try throwBridgeError(code)
        guard handleIdentifier != 0 else {
            throw bridgePOSIXError(EIO)
        }
        return (
            BridgeAttributes(attributes),
            PassFSBridgeHandle(identifier: handleIdentifier)
        )
    }

    func makeDirectory(
        parent: String,
        name: String,
        mode: UInt32
    ) throws -> BridgeAttributes {
        var attributes = passfs_attributes()
        let code = parent.withCString { parentPointer in
            name.withCString { namePointer in
                passfs_bridge_make_directory(
                    identifier,
                    parentPointer,
                    namePointer,
                    mode,
                    &attributes
                )
            }
        }
        try throwBridgeError(code)
        return BridgeAttributes(attributes)
    }

    func remove(parent: String, name: String, directory: Bool) throws {
        let code = parent.withCString { parentPointer in
            name.withCString { namePointer in
                if directory {
                    return passfs_bridge_remove_directory(
                        identifier,
                        parentPointer,
                        namePointer
                    )
                }
                return passfs_bridge_unlink(
                    identifier,
                    parentPointer,
                    namePointer
                )
            }
        }
        try throwBridgeError(code)
    }

    func rename(
        oldParent: String,
        oldName: String,
        newParent: String,
        newName: String
    ) throws {
        let code = oldParent.withCString { oldParentPointer in
            oldName.withCString { oldNamePointer in
                newParent.withCString { newParentPointer in
                    newName.withCString { newNamePointer in
                        passfs_bridge_rename(
                            identifier,
                            oldParentPointer,
                            oldNamePointer,
                            newParentPointer,
                            newNamePointer,
                            0
                        )
                    }
                }
            }
        }
        try throwBridgeError(code)
    }

    func setAttributes(
        path: String,
        handle: UInt64,
        requested: inout passfs_set_attributes
    ) throws -> BridgeAttributes {
        var attributes = passfs_attributes()
        let code = path.withCString {
            passfs_bridge_set_attributes(
                identifier,
                $0,
                handle,
                &requested,
                &attributes
            )
        }
        try throwBridgeError(code)
        return BridgeAttributes(attributes)
    }

    func statistics() throws -> passfs_statistics {
        var statistics = passfs_statistics()
        try throwBridgeError(
            passfs_bridge_statistics(identifier, &statistics)
        )
        return statistics
    }
}

final class PassFSBridgeHandle {
    private(set) var identifier: UInt64

    init(identifier: UInt64) {
        self.identifier = identifier
    }

    deinit {
        close()
    }

    func close() {
        guard identifier != 0 else {
            return
        }
        _ = passfs_bridge_close(identifier)
        identifier = 0
    }

    func flush() throws {
        try throwBridgeError(passfs_bridge_flush(identifier))
    }

    func attributes() throws -> BridgeAttributes {
        var attributes = passfs_attributes()
        try throwBridgeError(
            passfs_bridge_handle_attributes(identifier, &attributes)
        )
        return BridgeAttributes(attributes)
    }

    func read(
        into destination: UnsafeMutableRawBufferPointer,
        offset: Int64
    ) throws -> Int {
        var errorCode: Int32 = 0
        let count = passfs_bridge_read(
            identifier,
            destination.baseAddress,
            destination.count,
            offset,
            &errorCode
        )
        guard count >= 0, count <= Int64(destination.count) else {
            throw bridgePOSIXError(errorCode == 0 ? EIO : errorCode)
        }
        return Int(count)
    }

    func write(data: Data, offset: Int64) throws -> Int {
        var errorCode: Int32 = 0
        let count = data.withUnsafeBytes {
            passfs_bridge_write(
                identifier,
                $0.baseAddress,
                $0.count,
                offset,
                &errorCode
            )
        }
        guard count >= 0, count <= Int64(data.count) else {
            throw bridgePOSIXError(errorCode == 0 ? EIO : errorCode)
        }
        return Int(count)
    }
}
