import Darwin
import Foundation
import FSKit

final class PassFSItem: FSItem {
    let inode: UInt64
    let itemType: FSItem.ItemType

    private let lock = NSLock()
    private(set) var path: String
    private var openHandle: PassFSBridgeHandle?
    private var openModes: FSVolume.OpenModes = []

    init(path: String, attributes: BridgeAttributes) {
        self.path = path
        inode = attributes.inode
        itemType = fsItemType(attributes.itemType)
        super.init()
    }

    func move(to path: String) {
        lock.lock()
        self.path = path
        lock.unlock()
    }

    func currentPath() -> String {
        lock.lock()
        defer { lock.unlock() }
        return path
    }

    func handleIdentifier() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return openHandle?.identifier ?? 0
    }

    func adopt(
        handle: PassFSBridgeHandle,
        modes: FSVolume.OpenModes
    ) {
        lock.lock()
        let existing = openHandle
        openHandle = handle
        openModes = modes
        lock.unlock()
        existing?.close()
    }

    func withHandle<T>(
        bridge: PassFSBridge,
        flags: UInt32,
        _ body: (PassFSBridgeHandle) throws -> T
    ) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        if let existing = openHandle {
            return try body(existing)
        }
        let temporary = try bridge.open(path: path, flags: flags)
        defer { temporary.close() }
        return try body(temporary)
    }

    func open(bridge: PassFSBridge, modes: FSVolume.OpenModes) throws {
        guard itemType == .file else {
            return
        }
        lock.lock()
        defer { lock.unlock() }
        let existing = openHandle
        let existingModes = openModes
        if existing != nil,
           !modes.contains(.write) || existingModes.contains(.write) {
            openModes.formUnion(modes)
            return
        }
        openHandle = nil
        openModes = []

        existing?.close()
        let flags = modes.contains(.write)
            ? UInt32(O_RDWR)
            : UInt32(O_RDONLY)
        openHandle = try bridge.open(path: path, flags: flags)
        openModes = modes
    }

    func close(keeping modes: FSVolume.OpenModes = []) throws {
        lock.lock()
        guard modes.isEmpty else {
            openModes = modes
            lock.unlock()
            return
        }
        let handle = openHandle
        openHandle = nil
        openModes = []
        lock.unlock()
        if let handle {
            try handle.flush()
            handle.close()
        }
    }
}

func fsItemType(_ type: UInt32) -> FSItem.ItemType {
    switch type {
    case UInt32(PASSFS_ITEM_DIRECTORY):
        return .directory
    case UInt32(PASSFS_ITEM_SYMLINK):
        return .symlink
    default:
        return .file
    }
}
