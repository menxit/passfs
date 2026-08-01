import Darwin
import Foundation
import FSKit

final class PassFSVolume: FSVolume,
                          FSVolume.ReadWriteOperations,
                          FSVolume.OpenCloseOperations {
    let bridge: PassFSBridge
    let rootItem: PassFSItem

    private let cacheLock = NSLock()
    private var itemCache: [UInt64: PassFSItem] = [:]
    private var stopped = false

    init(
        bridge: PassFSBridge,
        volumeUUID: UUID
    ) throws {
        self.bridge = bridge
        let rootAttributes = try bridge.lookup(path: "")
        rootItem = PassFSItem(path: "", attributes: rootAttributes)
        super.init(
            volumeID: FSVolume.Identifier(uuid: volumeUUID),
            volumeName: FSFileName(string: "passfs")
        )
        itemCache[rootAttributes.inode] = rootItem
    }

    deinit {
        shutdown()
    }

    func shutdown() {
        cacheLock.lock()
        guard !stopped else {
            cacheLock.unlock()
            return
        }
        stopped = true
        let items = Array(itemCache.values)
        itemCache.removeAll()
        cacheLock.unlock()
        for item in items {
            try? item.close()
        }
        bridge.close()
    }

    func configure(_ configuration: PassFSConfiguration) throws {
        try bridge.configure(
            maximumFileSize: configuration.maximumFileSize,
            unlockDurationNanoseconds: configuration.unlockDurationNanoseconds,
            authorizationMode: configuration.authorizationMode
        )
    }

    func item(path: String, attributes: BridgeAttributes) -> PassFSItem {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let cached = itemCache[attributes.inode],
           cached.itemType == fsItemType(attributes.itemType) {
            cached.move(to: path, parentInode: attributes.parentInode)
            return cached
        }
        let item = PassFSItem(path: path, attributes: attributes)
        itemCache[attributes.inode] = item
        return item
    }

    func removeFromCache(_ item: PassFSItem) {
        cacheLock.lock()
        if itemCache[item.inode] === item {
            itemCache.removeValue(forKey: item.inode)
        }
        cacheLock.unlock()
    }

    func updateCachedPaths(
        from oldPath: String,
        to newPath: String,
        newParentInode: UInt64
    ) {
        cacheLock.lock()
        let cachedItems = Array(itemCache.values)
        cacheLock.unlock()
        let prefix = oldPath.isEmpty ? "" : oldPath + "/"
        for item in cachedItems {
            let path = item.currentPath()
            if path == oldPath {
                item.move(to: newPath, parentInode: newParentInode)
            } else if !prefix.isEmpty && path.hasPrefix(prefix) {
                let suffix = String(path.dropFirst(prefix.count))
                item.move(to: newPath + "/" + suffix)
            }
        }
    }

    var maximumLinkCount: Int { 1 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumXattrSizeInBits: Int { 13 }

    func openItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem else {
            replyHandler(POSIXError(.EINVAL))
            return
        }
        do {
            try item.open(bridge: bridge, modes: modes)
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func closeItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem else {
            replyHandler(POSIXError(.EINVAL))
            return
        }
        do {
            try item.close(keeping: modes)
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func read(
        from item: FSItem,
        at offset: off_t,
        length: Int,
        into buffer: FSMutableFileDataBuffer,
        replyHandler: @escaping (Int, (any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem,
              item.itemType == .file,
              offset >= 0,
              length >= 0 else {
            replyHandler(0, POSIXError(.EINVAL))
            return
        }
        do {
            var count = 0
            try item.withHandle(
                bridge: bridge,
                flags: UInt32(O_RDONLY)
            ) { handle in
                try buffer.withUnsafeMutableBytes { bytes in
                    let requested = min(length, bytes.count)
                    let destination = UnsafeMutableRawBufferPointer(
                        start: bytes.baseAddress,
                        count: requested
                    )
                    count = try handle.read(
                        into: destination,
                        offset: Int64(offset)
                    )
                }
            }
            replyHandler(count, nil)
        } catch {
            replyHandler(0, error)
        }
    }

    func write(
        contents: Data,
        to item: FSItem,
        at offset: off_t,
        replyHandler: @escaping (Int, (any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem,
              item.itemType == .file,
              offset >= 0 else {
            replyHandler(0, POSIXError(.EINVAL))
            return
        }
        do {
            let count = try item.withHandle(
                bridge: bridge,
                flags: UInt32(O_RDWR)
            ) {
                try $0.write(data: contents, offset: Int64(offset))
            }
            replyHandler(count, nil)
        } catch {
            replyHandler(0, error)
        }
    }
}

func joinedPath(_ parent: String, _ name: String) -> String {
    parent.isEmpty ? name : parent + "/" + name
}

func timespecFromNanoseconds(_ nanoseconds: Int64) -> timespec {
    let billion: Int64 = 1_000_000_000
    return timespec(
        tv_sec: Int(nanoseconds / billion),
        tv_nsec: Int(nanoseconds % billion)
    )
}

func nanosecondsFromTimespec(_ value: timespec) -> Int64 {
    Int64(value.tv_sec) * 1_000_000_000 + Int64(value.tv_nsec)
}
