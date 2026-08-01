import Darwin
import Foundation
import FSKit

extension PassFSVolume: FSVolume.Operations {
    var volumeStatistics: FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: "passfs")
        guard let statistics = try? bridge.statistics() else {
            return result
        }
        result.blockSize = Int(statistics.block_size)
        result.ioSize = Int(statistics.io_size)
        result.totalBlocks = statistics.total_blocks
        result.availableBlocks = statistics.available_blocks
        result.freeBlocks = statistics.free_blocks
        result.usedBlocks = statistics.total_blocks - statistics.free_blocks
        result.totalFiles = statistics.total_files
        result.freeFiles = statistics.free_files
        return result
    }

    func activate(
        options: FSTaskOptions,
        replyHandler: @escaping (FSItem?, (any Error)?) -> Void
    ) {
        do {
            let configuration = try passFSConfiguration(options)
            try configure(configuration)
            Logger.passfs.info(
                "Activating passfs volume; maximumFileSize=\(configuration.maximumFileSize, privacy: .public); unlockDurationNs=\(configuration.unlockDurationNanoseconds, privacy: .public)"
            )
            replyHandler(rootItem, nil)
        } catch {
            Logger.passfs.error(
                "Unable to configure passfs activation: \(error.localizedDescription)"
            )
            replyHandler(nil, error)
        }
    }

    func deactivate(
        options: FSDeactivateOptions = [],
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        Logger.passfs.info("Deactivating passfs volume")
        shutdown()
        replyHandler(nil)
    }

    func mount(
        options: FSTaskOptions,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        Logger.passfs.info("Mounting passfs volume")
        replyHandler(nil)
    }

    func unmount(replyHandler: @escaping () -> Void) {
        Logger.passfs.info("Unmounting passfs volume")
        shutdown()
        replyHandler()
    }

    func synchronize(
        flags: FSSyncFlags,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        replyHandler(nil)
    }

    func getAttributes(
        _ desiredAttributes: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler: @escaping (FSItem.Attributes?, (any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem else {
            replyHandler(nil, POSIXError(.EINVAL))
            return
        }
        do {
            let attributes: BridgeAttributes
            if item.handleIdentifier() != 0 {
                attributes = try item.withHandle(
                    bridge: bridge,
                    flags: UInt32(O_RDONLY)
                ) {
                    try $0.attributes()
                }
            } else {
                attributes = try bridge.lookup(path: item.currentPath())
            }
            replyHandler(
                fsAttributes(
                    attributes,
                    item: item,
                    desired: desiredAttributes
                ),
                nil
            )
        } catch {
            replyHandler(nil, error)
        }
    }

    func setAttributes(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem,
        replyHandler: @escaping (FSItem.Attributes?, (any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem else {
            replyHandler(nil, POSIXError(.EINVAL))
            return
        }
        var requested = bridgeSetAttributes(newAttributes)
        do {
            let attributes = try bridge.setAttributes(
                path: item.currentPath(),
                handle: item.handleIdentifier(),
                requested: &requested
            )
            let wanted = FSItem.GetAttributesRequest()
            wanted.wantedAttributes = [
                .uid, .gid, .mode, .size, .allocSize, .type,
                .fileID, .parentID, .linkCount, .accessTime, .birthTime,
                .modifyTime, .changeTime, .supportsLimitedXAttrs
            ]
            replyHandler(
                fsAttributes(attributes, item: item, desired: wanted),
                nil
            )
        } catch {
            replyHandler(nil, error)
        }
    }

    func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler: @escaping (
            FSItem?,
            FSFileName?,
            (any Error)?
        ) -> Void
    ) {
        guard let directory = directory as? PassFSItem,
              directory.itemType == .directory,
              let name = name.string else {
            replyHandler(nil, nil, POSIXError(.EINVAL))
            return
        }
        let path = joinedPath(directory.currentPath(), name)
        do {
            let attributes = try bridge.lookup(path: path)
            replyHandler(
                item(path: path, attributes: attributes),
                FSFileName(string: name),
                nil
            )
        } catch {
            replyHandler(nil, nil, error)
        }
    }

    func reclaimItem(
        _ item: FSItem,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem else {
            replyHandler(POSIXError(.EINVAL))
            return
        }
        do {
            try item.close()
            removeFromCache(item)
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func readSymbolicLink(
        _ item: FSItem,
        replyHandler: @escaping (FSFileName?, (any Error)?) -> Void
    ) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        replyHandler: @escaping (
            FSItem?,
            FSFileName?,
            (any Error)?
        ) -> Void
    ) {
        guard let directory = directory as? PassFSItem,
              directory.itemType == .directory,
              let name = name.string else {
            replyHandler(nil, nil, POSIXError(.EINVAL))
            return
        }
        let mode: UInt32
        if newAttributes.isValid(.mode) {
            mode = newAttributes.mode
        } else {
            mode = type == .directory ? 0o700 : 0o600
        }
        do {
            let attributes: BridgeAttributes
            var createdHandle: PassFSBridgeHandle?
            switch type {
            case .file:
                let created = try bridge.create(
                    parent: directory.currentPath(),
                    name: name,
                    mode: mode
                )
                attributes = created.attributes
                createdHandle = created.handle
            case .directory:
                attributes = try bridge.makeDirectory(
                    parent: directory.currentPath(),
                    name: name,
                    mode: mode
                )
            default:
                replyHandler(nil, nil, POSIXError(.ENOTSUP))
                return
            }
            let path = joinedPath(directory.currentPath(), name)
            let newItem = item(path: path, attributes: attributes)
            if let createdHandle {
                newItem.adopt(
                    handle: createdHandle,
                    modes: [.read, .write]
                )
            }
            replyHandler(newItem, FSFileName(string: name), nil)
        } catch {
            replyHandler(nil, nil, error)
        }
    }

    func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName,
        replyHandler: @escaping (
            FSItem?,
            FSFileName?,
            (any Error)?
        ) -> Void
    ) {
        replyHandler(nil, nil, POSIXError(.ENOTSUP))
    }

    func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler: @escaping (FSFileName?, (any Error)?) -> Void
    ) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem,
              let directory = directory as? PassFSItem,
              let name = name.string else {
            replyHandler(POSIXError(.EINVAL))
            return
        }
        do {
            try bridge.remove(
                parent: directory.currentPath(),
                name: name,
                directory: item.itemType == .directory
            )
            removeFromCache(item)
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?,
        replyHandler: @escaping (FSFileName?, (any Error)?) -> Void
    ) {
        guard let item = item as? PassFSItem,
              let sourceDirectory = sourceDirectory as? PassFSItem,
              let destinationDirectory = destinationDirectory as? PassFSItem,
              let sourceName = sourceName.string,
              let destinationName = destinationName.string else {
            replyHandler(nil, POSIXError(.EINVAL))
            return
        }
        let oldPath = item.currentPath()
        let newPath = joinedPath(
            destinationDirectory.currentPath(),
            destinationName
        )
        do {
            try bridge.rename(
                oldParent: sourceDirectory.currentPath(),
                oldName: sourceName,
                newParent: destinationDirectory.currentPath(),
                newName: destinationName
            )
            if let overItem = overItem as? PassFSItem,
               overItem !== item {
                removeFromCache(overItem)
            }
            updateCachedPaths(
                from: oldPath,
                to: newPath,
                newParentInode: destinationDirectory.inode
            )
            replyHandler(FSFileName(string: destinationName), nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes requestedAttributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker,
        replyHandler: @escaping (
            FSDirectoryVerifier,
            (any Error)?
        ) -> Void
    ) {
        guard let directory = directory as? PassFSItem,
              directory.itemType == .directory else {
            replyHandler(FSDirectoryVerifier(0), POSIXError(.ENOTDIR))
            return
        }
        do {
            let entries = try bridge.readDirectory(
                path: directory.currentPath()
            )
            let start = Int(cookie.rawValue)
            guard start >= 0, start <= entries.count else {
                replyHandler(
                    FSDirectoryVerifier(0),
                    POSIXError(.EINVAL)
                )
                return
            }
            for index in start..<entries.count {
                let entry = entries[index]
                var attributes: FSItem.Attributes?
                if let requestedAttributes {
                    let path = joinedPath(
                        directory.currentPath(),
                        entry.name
                    )
                    let item = self.item(
                        path: path,
                        attributes: entry.attributes
                    )
                    attributes = fsAttributes(
                        entry.attributes,
                        item: item,
                        desired: requestedAttributes
                    )
                }
                let packed = packer.packEntry(
                    name: FSFileName(string: entry.name),
                    itemType: fsItemType(entry.attributes.itemType),
                    itemID: FSItem.Identifier(rawValue: entry.attributes.inode)
                        ?? .invalid,
                    nextCookie: FSDirectoryCookie(UInt64(index + 1)),
                    attributes: attributes
                )
                if !packed {
                    break
                }
            }
            replyHandler(FSDirectoryVerifier(1), nil)
        } catch {
            replyHandler(FSDirectoryVerifier(0), error)
        }
    }

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let capabilities = FSVolume.SupportedCapabilities()
        capabilities.supportsSymbolicLinks = false
        capabilities.supportsHardLinks = false
        capabilities.supportsHiddenFiles = true
        capabilities.supportsPersistentObjectIDs = true
        capabilities.supports64BitObjectIDs = true
        capabilities.supports2TBFiles = false
        capabilities.supportsFastStatFS = true
        capabilities.doesNotSupportImmutableFiles = true
        capabilities.caseFormat = .insensitiveCasePreserving
        return capabilities
    }
}

private func bridgeSetAttributes(
    _ source: FSItem.SetAttributesRequest
) -> passfs_set_attributes {
    var destination = passfs_set_attributes()
    if source.isValid(.size) {
        destination.valid |= UInt32(PASSFS_SET_SIZE)
        destination.size = source.size
    }
    if source.isValid(.mode) {
        destination.valid |= UInt32(PASSFS_SET_MODE)
        destination.mode = source.mode
    }
    if source.isValid(.uid) {
        destination.valid |= UInt32(PASSFS_SET_UID)
        destination.uid = source.uid
    }
    if source.isValid(.gid) {
        destination.valid |= UInt32(PASSFS_SET_GID)
        destination.gid = source.gid
    }
    if source.isValid(.accessTime) {
        destination.valid |= UInt32(PASSFS_SET_ACCESS_TIME)
        destination.access_time_ns = nanosecondsFromTimespec(
            source.accessTime
        )
    }
    if source.isValid(.modifyTime) {
        destination.valid |= UInt32(PASSFS_SET_MODIFY_TIME)
        destination.modify_time_ns = nanosecondsFromTimespec(
            source.modifyTime
        )
    }
    return destination
}

private func fsAttributes(
    _ source: BridgeAttributes,
    item: PassFSItem,
    desired: FSItem.GetAttributesRequest
) -> FSItem.Attributes {
    let attributes = FSItem.Attributes()
    if desired.isAttributeWanted(.uid) {
        attributes.uid = source.uid
    }
    if desired.isAttributeWanted(.gid) {
        attributes.gid = source.gid
    }
    if desired.isAttributeWanted(.mode) {
        attributes.mode = source.mode
    }
    if desired.isAttributeWanted(.linkCount) {
        attributes.linkCount = source.linkCount
    }
    if desired.isAttributeWanted(.flags) {
        attributes.flags = 0
    }
    if desired.isAttributeWanted(.size) {
        attributes.size = source.size
    }
    if desired.isAttributeWanted(.allocSize) {
        attributes.allocSize = source.blocks * 512
    }
    if desired.isAttributeWanted(.fileID) {
        attributes.fileID = FSItem.Identifier(rawValue: source.inode)
            ?? .invalid
    }
    if desired.isAttributeWanted(.parentID) {
        let parentInode = source.parentInode == 0
            ? item.parentInode()
            : source.parentInode
        attributes.parentID = FSItem.Identifier(rawValue: parentInode)
            ?? .invalid
    }
    if desired.isAttributeWanted(.type) {
        attributes.type = item.itemType
    }
    if desired.isAttributeWanted(.supportsLimitedXAttrs) {
        attributes.supportsLimitedXAttrs = false
    }
    if desired.isAttributeWanted(.accessTime) {
        attributes.accessTime = timespecFromNanoseconds(
            source.accessTimeNanoseconds
        )
    }
    if desired.isAttributeWanted(.changeTime) {
        attributes.changeTime = timespecFromNanoseconds(
            source.changeTimeNanoseconds
        )
    }
    if desired.isAttributeWanted(.modifyTime) {
        attributes.modifyTime = timespecFromNanoseconds(
            source.modifyTimeNanoseconds
        )
    }
    if desired.isAttributeWanted(.birthTime) {
        attributes.birthTime = timespecFromNanoseconds(
            source.birthTimeNanoseconds
        )
    }
    return attributes
}
