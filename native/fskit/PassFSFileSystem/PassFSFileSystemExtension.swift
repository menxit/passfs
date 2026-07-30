import ExtensionFoundation
import Foundation
import FSKit

@main
struct PassFSFileSystemExtension: UnaryFileSystemExtension {
    typealias FileSystem = FSUnaryFileSystem & FSUnaryFileSystemOperations

    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        PassFSFileSystem()
    }
}
