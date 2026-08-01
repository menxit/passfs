//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../native/fskit
#define PASSFS_BRIDGE_CGO_TYPES_ONLY 1
#include <stdlib.h>
#include "PassFSBridge.h"
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"passfs/internal/fsapi"
	"passfs/internal/passfs"
)

const maximumCGoBytesLength = uint64(1<<31 - 1)

type mountedFileSystem struct {
	mu                sync.Mutex
	volume            *passfs.Volume
	fileSystem        fsapi.FileSystem
	vault             string
	authorizationMode uint32
	sleepMonitor      *passfs.SystemSleepMonitor
}

//export passfs_bridge_volume_id
func passfs_bridge_volume_id(identifier C.uint64_t) *C.char {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return nil
	}
	decoded, err := hex.DecodeString(fileSystem.volume.VolumeID())
	if err != nil || len(decoded) != 16 {
		return nil
	}
	return C.CString(fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		decoded[0:4],
		decoded[4:6],
		decoded[6:8],
		decoded[8:10],
		decoded[10:16],
	))
}

type ownedHandle struct {
	fileSystem uint64
	handle     fsapi.Handle
}

type bridgeState struct {
	sync.Mutex
	next        uint64
	fileSystems map[uint64]*mountedFileSystem
	handles     map[uint64]ownedHandle
}

var bridgeRegistry = bridgeState{
	next:        1,
	fileSystems: make(map[uint64]*mountedFileSystem),
	handles:     make(map[uint64]ownedHandle),
}

func (registry *bridgeState) nextIdentifierLocked() uint64 {
	identifier := registry.next
	registry.next++
	if registry.next == 0 {
		registry.next = 1
	}
	return identifier
}

func bridgeFileSystem(identifier uint64) (*mountedFileSystem, bool) {
	bridgeRegistry.Lock()
	defer bridgeRegistry.Unlock()
	fileSystem, ok := bridgeRegistry.fileSystems[identifier]
	return fileSystem, ok
}

func bridgeHandle(identifier uint64) (fsapi.Handle, bool) {
	bridgeRegistry.Lock()
	defer bridgeRegistry.Unlock()
	owned, ok := bridgeRegistry.handles[identifier]
	return owned.handle, ok
}

func bridgeOwnedHandle(identifier uint64) (ownedHandle, bool) {
	bridgeRegistry.Lock()
	defer bridgeRegistry.Unlock()
	owned, ok := bridgeRegistry.handles[identifier]
	return owned, ok
}

func registerBridgeHandle(
	fileSystem uint64,
	handle fsapi.Handle,
) uint64 {
	bridgeRegistry.Lock()
	defer bridgeRegistry.Unlock()
	identifier := bridgeRegistry.nextIdentifierLocked()
	bridgeRegistry.handles[identifier] = ownedHandle{
		fileSystem: fileSystem,
		handle:     handle,
	}
	return identifier
}

func takeBridgeHandle(identifier uint64) (ownedHandle, bool) {
	bridgeRegistry.Lock()
	defer bridgeRegistry.Unlock()
	owned, ok := bridgeRegistry.handles[identifier]
	if ok {
		delete(bridgeRegistry.handles, identifier)
	}
	return owned, ok
}

func storeBridgeError(destination **C.char, err error) {
	if destination == nil || err == nil {
		return
	}
	*destination = C.CString(err.Error())
}

func bridgeContext() context.Context {
	return context.Background()
}

func bridgeErrno(errno syscall.Errno) C.int {
	return C.int(errno)
}

func cString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

func fillAttributes(destination *C.passfs_attributes, source fsapi.Attributes) {
	if destination == nil {
		return
	}
	destination.item_type = bridgeItemType(source.Type)
	destination.mode = C.uint32_t(source.Mode)
	destination.uid = C.uint32_t(source.UID)
	destination.gid = C.uint32_t(source.GID)
	destination.link_count = C.uint32_t(source.LinkCount)
	destination.reserved = 0
	destination.inode = C.uint64_t(source.Inode)
	destination.parent_inode = C.uint64_t(source.ParentInode)
	destination.size = C.uint64_t(source.Size)
	destination.blocks = C.uint64_t(source.Blocks)
	destination.access_time_ns = C.int64_t(source.AccessTime.UnixNano())
	destination.change_time_ns = C.int64_t(source.ChangeTime.UnixNano())
	destination.modify_time_ns = C.int64_t(source.ModifyTime.UnixNano())
	destination.birth_time_ns = C.int64_t(source.BirthTime.UnixNano())
}

func bridgeItemType(source fsapi.ItemType) C.uint32_t {
	switch source {
	case fsapi.TypeFile:
		return C.PASSFS_ITEM_FILE
	case fsapi.TypeDirectory:
		return C.PASSFS_ITEM_DIRECTORY
	case fsapi.TypeSymlink:
		return C.PASSFS_ITEM_SYMLINK
	default:
		return C.PASSFS_ITEM_UNKNOWN
	}
}

func requestedAttributes(source *C.passfs_set_attributes) fsapi.SetAttributes {
	var destination fsapi.SetAttributes
	if source == nil {
		return destination
	}
	valid := uint32(source.valid)
	if valid&C.PASSFS_SET_SIZE != 0 {
		value := uint64(source.size)
		destination.Size = &value
	}
	if valid&C.PASSFS_SET_MODE != 0 {
		value := uint32(source.mode)
		destination.Mode = &value
	}
	if valid&C.PASSFS_SET_UID != 0 {
		value := uint32(source.uid)
		destination.UID = &value
	}
	if valid&C.PASSFS_SET_GID != 0 {
		value := uint32(source.gid)
		destination.GID = &value
	}
	if valid&C.PASSFS_SET_ACCESS_TIME != 0 {
		value := time.Unix(0, int64(source.access_time_ns))
		destination.AccessTime = &value
	}
	if valid&C.PASSFS_SET_MODIFY_TIME != 0 {
		value := time.Unix(0, int64(source.modify_time_ns))
		destination.ModifyTime = &value
	}
	return destination
}

//export passfs_bridge_open_file_system
func passfs_bridge_open_file_system(
	vaultPath *C.char,
	maximumFileSize C.int64_t,
	unlockDuration C.int64_t,
	authorizationMode C.uint32_t,
	errorMessage **C.char,
) C.uint64_t {
	vault := cString(vaultPath)
	if vault == "" {
		storeBridgeError(errorMessage, errors.New("vault path is required"))
		return 0
	}
	mode := uint32(authorizationMode)
	prompter, err := newFSKitPrompter(vault, mode)
	if err != nil {
		storeBridgeError(errorMessage, fmt.Errorf("initialize FSKit authorization: %w", err))
		return 0
	}
	volume, err := passfs.LoadVolume(
		vault,
		prompter,
		int64(maximumFileSize),
		time.Duration(unlockDuration),
	)
	if err != nil {
		storeBridgeError(errorMessage, err)
		return 0
	}
	sleepMonitor, err := passfs.NewSystemSleepMonitor(volume)
	if err != nil {
		volume.Lock()
		storeBridgeError(
			errorMessage,
			fmt.Errorf("monitor system sleep: %w", err),
		)
		return 0
	}
	bridgeRegistry.Lock()
	identifier := bridgeRegistry.nextIdentifierLocked()
	bridgeRegistry.fileSystems[identifier] = &mountedFileSystem{
		volume:            volume,
		fileSystem:        passfs.NewFileSystem(volume),
		vault:             vault,
		authorizationMode: mode,
		sleepMonitor:      sleepMonitor,
	}
	bridgeRegistry.Unlock()
	return C.uint64_t(identifier)
}

//export passfs_bridge_configure_file_system
func passfs_bridge_configure_file_system(
	identifier C.uint64_t,
	maximumFileSize C.int64_t,
	unlockDuration C.int64_t,
	authorizationMode C.uint32_t,
	errorMessage **C.char,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	fileSystem.mu.Lock()
	defer fileSystem.mu.Unlock()
	mode := uint32(authorizationMode)
	var prompter passfs.Prompter
	var err error
	if mode != uint32(C.PASSFS_AUTHORIZATION_UNCHANGED) &&
		mode != fileSystem.authorizationMode {
		prompter, err = newFSKitPrompter(fileSystem.vault, mode)
		if err != nil {
			storeBridgeError(errorMessage, err)
			return C.int(syscall.EINVAL)
		}
	}
	if err := fileSystem.volume.Configure(
		int64(maximumFileSize),
		time.Duration(unlockDuration),
	); err != nil {
		storeBridgeError(errorMessage, err)
		return C.int(syscall.EINVAL)
	}
	if prompter != nil {
		if err := fileSystem.volume.ConfigurePrompter(prompter); err != nil {
			storeBridgeError(errorMessage, err)
			return C.int(syscall.EINVAL)
		}
		fileSystem.authorizationMode = mode
	}
	return 0
}

func newFSKitPrompter(vault string, authorizationMode uint32) (passfs.Prompter, error) {
	switch authorizationMode {
	case uint32(C.PASSFS_AUTHORIZATION_TOUCH_ID):
		return passfs.NewTouchIDPrompter(vault)
	case uint32(C.PASSFS_AUTHORIZATION_PASSPHRASE):
		return passfs.NewFSKitPassphrasePrompter(vault)
	default:
		return nil, errors.New("unsupported FSKit authorization mode")
	}
}

//export passfs_bridge_close_file_system
func passfs_bridge_close_file_system(identifier C.uint64_t) C.int {
	id := uint64(identifier)
	bridgeRegistry.Lock()
	fileSystem, ok := bridgeRegistry.fileSystems[id]
	if !ok {
		bridgeRegistry.Unlock()
		return C.int(syscall.EBADF)
	}
	delete(bridgeRegistry.fileSystems, id)
	var handles []fsapi.Handle
	for handleID, owned := range bridgeRegistry.handles {
		if owned.fileSystem == id {
			handles = append(handles, owned.handle)
			delete(bridgeRegistry.handles, handleID)
		}
	}
	bridgeRegistry.Unlock()
	_ = fileSystem.sleepMonitor.Close()
	for _, handle := range handles {
		_ = handle.Close(context.Background())
	}
	_ = fileSystem.volume.FlushAccessTimes()
	fileSystem.volume.Lock()
	return 0
}

//export passfs_bridge_lookup
func passfs_bridge_lookup(
	identifier C.uint64_t,
	path *C.char,
	attributes *C.passfs_attributes,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	entry, errno := fileSystem.fileSystem.Lookup(bridgeContext(), cString(path))
	if errno == 0 {
		fillAttributes(attributes, entry.Attributes)
	}
	return bridgeErrno(errno)
}

type bridgeDirectoryEntry struct {
	Name       string               `json:"name"`
	Attributes bridgeJSONAttributes `json:"attributes"`
}

type bridgeJSONAttributes struct {
	ItemType              uint32 `json:"itemType"`
	Mode                  uint32 `json:"mode"`
	UID                   uint32 `json:"uid"`
	GID                   uint32 `json:"gid"`
	LinkCount             uint32 `json:"linkCount"`
	Inode                 uint64 `json:"inode"`
	ParentInode           uint64 `json:"parentInode"`
	Size                  uint64 `json:"size"`
	Blocks                uint64 `json:"blocks"`
	AccessTimeNanoseconds int64  `json:"accessTimeNanoseconds"`
	ChangeTimeNanoseconds int64  `json:"changeTimeNanoseconds"`
	ModifyTimeNanoseconds int64  `json:"modifyTimeNanoseconds"`
	BirthTimeNanoseconds  int64  `json:"birthTimeNanoseconds"`
}

func encodeBridgeAttributes(source fsapi.Attributes) bridgeJSONAttributes {
	return bridgeJSONAttributes{
		ItemType:              uint32(bridgeItemType(source.Type)),
		Mode:                  source.Mode,
		UID:                   source.UID,
		GID:                   source.GID,
		LinkCount:             source.LinkCount,
		Inode:                 source.Inode,
		ParentInode:           source.ParentInode,
		Size:                  source.Size,
		Blocks:                source.Blocks,
		AccessTimeNanoseconds: source.AccessTime.UnixNano(),
		ChangeTimeNanoseconds: source.ChangeTime.UnixNano(),
		ModifyTimeNanoseconds: source.ModifyTime.UnixNano(),
		BirthTimeNanoseconds:  source.BirthTime.UnixNano(),
	}
}

//export passfs_bridge_read_directory
func passfs_bridge_read_directory(
	identifier C.uint64_t,
	path *C.char,
	jsonBytes *unsafe.Pointer,
	jsonLength *C.size_t,
) C.int {
	if jsonBytes == nil || jsonLength == nil {
		return C.int(syscall.EINVAL)
	}
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	entries, errno := fileSystem.fileSystem.ReadDirectory(
		bridgeContext(),
		cString(path),
	)
	if errno != 0 {
		return bridgeErrno(errno)
	}
	encodedEntries := make([]bridgeDirectoryEntry, 0, len(entries))
	for _, entry := range entries {
		encodedEntries = append(encodedEntries, bridgeDirectoryEntry{
			Name:       entry.Name,
			Attributes: encodeBridgeAttributes(entry.Attributes),
		})
	}
	encoded, err := json.Marshal(encodedEntries)
	if err != nil {
		return C.int(syscall.EIO)
	}
	if len(encoded) == 0 {
		*jsonBytes = nil
		*jsonLength = 0
		return 0
	}
	bytes := C.CBytes(encoded)
	if bytes == nil {
		return C.int(syscall.ENOMEM)
	}
	*jsonBytes = bytes
	*jsonLength = C.size_t(len(encoded))
	return 0
}

//export passfs_bridge_open
func passfs_bridge_open(
	identifier C.uint64_t,
	path *C.char,
	flags C.uint32_t,
	errorCode *C.int,
) C.uint64_t {
	fileSystemID := uint64(identifier)
	fileSystem, ok := bridgeFileSystem(fileSystemID)
	if !ok {
		if errorCode != nil {
			*errorCode = C.int(syscall.EBADF)
		}
		return 0
	}
	handle, errno := fileSystem.fileSystem.Open(
		bridgeContext(),
		cString(path),
		uint32(flags),
	)
	if errno != 0 {
		if errorCode != nil {
			*errorCode = bridgeErrno(errno)
		}
		return 0
	}
	handleID := registerBridgeHandle(fileSystemID, handle)
	if errorCode != nil {
		*errorCode = 0
	}
	return C.uint64_t(handleID)
}

//export passfs_bridge_create
func passfs_bridge_create(
	identifier C.uint64_t,
	parent *C.char,
	name *C.char,
	mode C.uint32_t,
	attributes *C.passfs_attributes,
	handleIdentifier *C.uint64_t,
) C.int {
	if handleIdentifier == nil {
		return C.int(syscall.EINVAL)
	}
	*handleIdentifier = 0
	fileSystemID := uint64(identifier)
	fileSystem, ok := bridgeFileSystem(fileSystemID)
	if !ok {
		return C.int(syscall.EBADF)
	}
	entry, handle, errno := fileSystem.fileSystem.Create(
		bridgeContext(),
		cString(parent),
		cString(name),
		syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR,
		uint32(mode),
	)
	if errno != 0 {
		return bridgeErrno(errno)
	}
	handleID := registerBridgeHandle(fileSystemID, handle)
	fillAttributes(attributes, entry.Attributes)
	*handleIdentifier = C.uint64_t(handleID)
	return 0
}

//export passfs_bridge_make_directory
func passfs_bridge_make_directory(
	identifier C.uint64_t,
	parent *C.char,
	name *C.char,
	mode C.uint32_t,
	attributes *C.passfs_attributes,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	entry, errno := fileSystem.fileSystem.MakeDirectory(
		bridgeContext(),
		cString(parent),
		cString(name),
		uint32(mode),
	)
	if errno == 0 {
		fillAttributes(attributes, entry.Attributes)
	}
	return bridgeErrno(errno)
}

//export passfs_bridge_unlink
func passfs_bridge_unlink(
	identifier C.uint64_t,
	parent *C.char,
	name *C.char,
) C.int {
	return removeBridgeEntry(identifier, parent, name, false)
}

//export passfs_bridge_remove_directory
func passfs_bridge_remove_directory(
	identifier C.uint64_t,
	parent *C.char,
	name *C.char,
) C.int {
	return removeBridgeEntry(identifier, parent, name, true)
}

func removeBridgeEntry(
	identifier C.uint64_t,
	parent *C.char,
	name *C.char,
	directory bool,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	ctx := bridgeContext()
	parentPath, entryName := cString(parent), cString(name)
	if directory {
		return bridgeErrno(
			fileSystem.fileSystem.RemoveDirectory(ctx, parentPath, entryName),
		)
	}
	return bridgeErrno(fileSystem.fileSystem.Unlink(ctx, parentPath, entryName))
}

//export passfs_bridge_rename
func passfs_bridge_rename(
	identifier C.uint64_t,
	oldParent *C.char,
	oldName *C.char,
	newParent *C.char,
	newName *C.char,
	flags C.uint32_t,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	return bridgeErrno(fileSystem.fileSystem.Rename(
		bridgeContext(),
		cString(oldParent),
		cString(oldName),
		cString(newParent),
		cString(newName),
		uint32(flags),
	))
}

//export passfs_bridge_set_attributes
func passfs_bridge_set_attributes(
	identifier C.uint64_t,
	path *C.char,
	handleIdentifier C.uint64_t,
	requested *C.passfs_set_attributes,
	attributes *C.passfs_attributes,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	var handle fsapi.Handle
	if handleIdentifier != 0 {
		owned, handleOK := bridgeOwnedHandle(uint64(handleIdentifier))
		if !handleOK || owned.fileSystem != uint64(identifier) {
			return C.int(syscall.EBADF)
		}
		handle = owned.handle
	}
	result, errno := fileSystem.fileSystem.SetAttributes(
		bridgeContext(),
		cString(path),
		handle,
		requestedAttributes(requested),
	)
	if errno == 0 {
		fillAttributes(attributes, result)
	}
	return bridgeErrno(errno)
}

//export passfs_bridge_read
func passfs_bridge_read(
	handleIdentifier C.uint64_t,
	destination unsafe.Pointer,
	length C.size_t,
	offset C.int64_t,
	errorCode *C.int,
) C.int64_t {
	handle, ok := bridgeHandle(uint64(handleIdentifier))
	if !ok {
		if errorCode != nil {
			*errorCode = C.int(syscall.EBADF)
		}
		return -1
	}
	if uint64(length) > uint64(^uint(0)>>1) ||
		(length != 0 && destination == nil) {
		if errorCode != nil {
			*errorCode = C.int(syscall.EINVAL)
		}
		return -1
	}
	buffer := unsafe.Slice((*byte)(destination), int(length))
	count, errno := handle.Read(bridgeContext(), buffer, int64(offset))
	if errorCode != nil {
		*errorCode = bridgeErrno(errno)
	}
	if errno != 0 {
		return -1
	}
	return C.int64_t(count)
}

//export passfs_bridge_write
func passfs_bridge_write(
	handleIdentifier C.uint64_t,
	source unsafe.Pointer,
	length C.size_t,
	offset C.int64_t,
	errorCode *C.int,
) C.int64_t {
	handle, ok := bridgeHandle(uint64(handleIdentifier))
	if !ok {
		if errorCode != nil {
			*errorCode = C.int(syscall.EBADF)
		}
		return -1
	}
	if uint64(length) > maximumCGoBytesLength ||
		(length != 0 && source == nil) {
		if errorCode != nil {
			*errorCode = C.int(syscall.EINVAL)
		}
		return -1
	}
	buffer := C.GoBytes(source, C.int(length))
	count, errno := handle.Write(bridgeContext(), buffer, int64(offset))
	if errorCode != nil {
		*errorCode = bridgeErrno(errno)
	}
	if errno != 0 {
		return -1
	}
	return C.int64_t(count)
}

//export passfs_bridge_flush
func passfs_bridge_flush(handleIdentifier C.uint64_t) C.int {
	handle, ok := bridgeHandle(uint64(handleIdentifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	return bridgeErrno(handle.Flush(bridgeContext()))
}

//export passfs_bridge_close
func passfs_bridge_close(handleIdentifier C.uint64_t) C.int {
	owned, ok := takeBridgeHandle(uint64(handleIdentifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	return bridgeErrno(owned.handle.Close(bridgeContext()))
}

//export passfs_bridge_handle_attributes
func passfs_bridge_handle_attributes(
	handleIdentifier C.uint64_t,
	attributes *C.passfs_attributes,
) C.int {
	handle, ok := bridgeHandle(uint64(handleIdentifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	result, errno := handle.Attributes(bridgeContext())
	if errno == 0 {
		fillAttributes(attributes, result)
	}
	return bridgeErrno(errno)
}

//export passfs_bridge_statistics
func passfs_bridge_statistics(
	identifier C.uint64_t,
	statistics *C.passfs_statistics,
) C.int {
	fileSystem, ok := bridgeFileSystem(uint64(identifier))
	if !ok {
		return C.int(syscall.EBADF)
	}
	result, errno := fileSystem.fileSystem.Statistics(bridgeContext())
	if errno != 0 {
		return bridgeErrno(errno)
	}
	if statistics == nil {
		return C.int(syscall.EINVAL)
	}
	statistics.block_size = C.uint64_t(result.BlockSize)
	statistics.io_size = C.uint64_t(result.IOSize)
	statistics.total_blocks = C.uint64_t(result.TotalBlocks)
	statistics.available_blocks = C.uint64_t(result.AvailableBlocks)
	statistics.free_blocks = C.uint64_t(result.FreeBlocks)
	statistics.total_files = C.uint64_t(result.TotalFiles)
	statistics.free_files = C.uint64_t(result.FreeFiles)
	return 0
}

//export passfs_bridge_free
func passfs_bridge_free(pointer unsafe.Pointer) {
	C.free(pointer)
}

func main() {}
