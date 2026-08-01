#ifndef PASSFS_BRIDGE_H
#define PASSFS_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PASSFS_ITEM_UNKNOWN = 0,
    PASSFS_ITEM_FILE = 1,
    PASSFS_ITEM_DIRECTORY = 2,
    PASSFS_ITEM_SYMLINK = 3
};

enum {
    PASSFS_SET_SIZE = 1u << 0,
    PASSFS_SET_MODE = 1u << 1,
    PASSFS_SET_UID = 1u << 2,
    PASSFS_SET_GID = 1u << 3,
    PASSFS_SET_ACCESS_TIME = 1u << 4,
    PASSFS_SET_MODIFY_TIME = 1u << 5
};

enum {
    PASSFS_AUTHORIZATION_UNCHANGED = 0,
    PASSFS_AUTHORIZATION_TOUCH_ID = 1,
    PASSFS_AUTHORIZATION_PASSPHRASE = 2
};

typedef struct passfs_attributes {
    uint32_t item_type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t link_count;
    uint32_t reserved;
    uint64_t inode;
    uint64_t parent_inode;
    uint64_t size;
    uint64_t blocks;
    int64_t access_time_ns;
    int64_t change_time_ns;
    int64_t modify_time_ns;
    int64_t birth_time_ns;
} passfs_attributes;

typedef struct passfs_set_attributes {
    uint32_t valid;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    int64_t access_time_ns;
    int64_t modify_time_ns;
} passfs_set_attributes;

typedef struct passfs_statistics {
    uint64_t block_size;
    uint64_t io_size;
    uint64_t total_blocks;
    uint64_t available_blocks;
    uint64_t free_blocks;
    uint64_t total_files;
    uint64_t free_files;
} passfs_statistics;

#ifndef PASSFS_BRIDGE_CGO_TYPES_ONLY

uint64_t passfs_bridge_open_file_system(
    const char *vault_path,
    int64_t maximum_file_size,
    int64_t unlock_duration_ns,
    uint32_t authorization_mode,
    char **error_message
);

char *passfs_bridge_volume_id(uint64_t file_system);

int passfs_bridge_configure_file_system(
    uint64_t file_system,
    int64_t maximum_file_size,
    int64_t unlock_duration_ns,
    uint32_t authorization_mode,
    char **error_message
);

int passfs_bridge_close_file_system(uint64_t file_system);

int passfs_bridge_lookup(
    uint64_t file_system,
    const char *path,
    passfs_attributes *attributes
);

int passfs_bridge_read_directory(
    uint64_t file_system,
    const char *path,
    void **json_bytes,
    size_t *json_length
);

uint64_t passfs_bridge_open(
    uint64_t file_system,
    const char *path,
    uint32_t flags,
    int *error_code
);

int passfs_bridge_create(
    uint64_t file_system,
    const char *parent,
    const char *name,
    uint32_t mode,
    passfs_attributes *attributes,
    uint64_t *handle
);

int passfs_bridge_make_directory(
    uint64_t file_system,
    const char *parent,
    const char *name,
    uint32_t mode,
    passfs_attributes *attributes
);

int passfs_bridge_unlink(
    uint64_t file_system,
    const char *parent,
    const char *name
);

int passfs_bridge_remove_directory(
    uint64_t file_system,
    const char *parent,
    const char *name
);

int passfs_bridge_rename(
    uint64_t file_system,
    const char *old_parent,
    const char *old_name,
    const char *new_parent,
    const char *new_name,
    uint32_t flags
);

int passfs_bridge_set_attributes(
    uint64_t file_system,
    const char *path,
    uint64_t handle,
    const passfs_set_attributes *requested,
    passfs_attributes *attributes
);

int64_t passfs_bridge_read(
    uint64_t handle,
    void *destination,
    size_t length,
    int64_t offset,
    int *error_code
);

int64_t passfs_bridge_write(
    uint64_t handle,
    const void *source,
    size_t length,
    int64_t offset,
    int *error_code
);

int passfs_bridge_flush(uint64_t handle);
int passfs_bridge_close(uint64_t handle);

int passfs_bridge_handle_attributes(
    uint64_t handle,
    passfs_attributes *attributes
);

int passfs_bridge_statistics(
    uint64_t file_system,
    passfs_statistics *statistics
);

void passfs_bridge_free(void *pointer);

#endif

#ifdef __cplusplus
}
#endif

#endif
