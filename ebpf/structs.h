/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _MAPS_H_
#define _MAPS_H_

// event_type - Defines the type of file system event
enum event_type
{
    EVENT_OPEN,
    EVENT_MKDIR,
    EVENT_LINK,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_RMDIR,
    EVENT_MODIFY,
    EVENT_SETATTR,
};

// fs_event_t - File system event structure
struct fs_event_t
{
    struct process_ctx_t process_data;
    int flags;
    int mode;
    u32 src_path_key;
    u32 target_path_key;
    u64 src_inode;
    u32 src_path_length;
    int src_mount_id;
    u64 target_inode;
    u32 target_path_length;
    int target_mount_id;
    int retval;
    u32 event;
};

// fs_events - Perf buffer used to send file system events back to user space
struct bpf_map_def SEC("maps/fs_events") fs_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_cache_t - Dentry cache structure used to cache context between kprobes entry and return
struct dentry_cache_t
{
    struct fs_event_t fs_event;
    struct inode *src_dir;
    struct dentry *src_dentry;
    struct inode *target_dir;
    struct dentry *target_dentry;
    u32 cursor;
};

// dentry_cache - Dentry cache map used to store dentry cache structures between 2 eBPF programs
struct bpf_map_def SEC("maps/dentry_cache") dentry_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 1000,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_cache_builder - Dentry cache builder map used to reduce the amount of data on the stack
struct bpf_map_def SEC("maps/dentry_cache_builder") dentry_cache_builder = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 16,
    .pinning = PIN_NONE,
    .namespace = "",
};

// path_key_t - Structure used as the key to store path_fragment_t structures
struct path_key_t {
    unsigned long ino;
    u32 mount_id;
    u32 padding;
};

// path_fragment_t - Structure used to store path leaf during the path resolution process
struct path_fragment_t
{
    struct path_key_t parent;
    char name[NAME_MAX];
};

// path_fragments - Map used to store path fragments. The user space program will recover the fragments from this map.
struct bpf_map_def SEC("maps/path_fragments") path_fragments = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct path_key_t),
    .value_size = sizeof(struct path_fragment_t),
    .max_entries = 10000,
    .pinning = PIN_NONE,
    .namespace = "",
};

// PATH_BUFFER_SIZE - Size of the eBPF buffer used to build a file system event.
// Make sure that there is a n for which PATH_BUFFER = 2**n + NAME_MAX
// n must be chosen so that MAX_PATH + MAX_PATH / 2 < 2**n
// 2**13 + NAME_MAX = 8192 + 255 = 8447
#define PATH_BUFFER_SIZE 8447

struct fs_event_wrapper_t {
    struct fs_event_t evt;
    char buff[PATH_BUFFER_SIZE];
};

struct bpf_map_def SEC("maps/paths_builder") paths_builder = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct fs_event_wrapper_t),
    .max_entries = 32770,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cached_inodes") cached_inodes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = 10000,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/inodes_filter") inodes_filter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = 10111,
    .pinning = PIN_NONE,
    .namespace = "",
};

// SINGLE_FRAGMENTS_SIZE - See the comment about PATH_BUFFER_SIZE. The same condition applies, however those map values
// will only hold one path at a time. Therefore we can choose: 2**12 + NAME_MAX = 4096 + 255 = 4351
#define SINGLE_FRAGMENTS_SIZE 4351

// single_fragment_t - Structure used to store single fragments during the path resolution process
struct single_fragment_t
{
    char name[SINGLE_FRAGMENTS_SIZE];
};

// path_fragments - Map used to store path fragments. The user space program will recover the fragments from this map.
struct bpf_map_def SEC("maps/single_fragments") single_fragments = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct single_fragment_t),
    .max_entries = 10000,
    .pinning = PIN_NONE,
    .namespace = "",
};

#endif
