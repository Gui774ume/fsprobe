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
#ifndef _FILTER_H_
#define _FILTER_H_

#define FILTER_SRC     1 << 1
#define FILTER_TARGET  1 << 2

__attribute__((always_inline)) static int filter_src(struct dentry_cache_t *data_cache)
{
    // Look for the inode in the cached_inodes map
    if (bpf_map_lookup_elem(&inodes_filter, &data_cache->fs_event.src_inode) == NULL) {
        // Look for the parent inode
        struct dentry *d_parent;
        bpf_probe_read(&d_parent, sizeof(d_parent), &data_cache->src_dentry->d_parent);
        u32 ino = get_dentry_ino(d_parent);
        if (bpf_map_lookup_elem(&inodes_filter, &ino) == NULL) {
            return 0;
        }
    }
    return 1;
}

__attribute__((always_inline)) static int filter_target(struct dentry_cache_t *data_cache)
{
    // Look for the inode in the cached_inodes map
    if (bpf_map_lookup_elem(&inodes_filter, &data_cache->fs_event.target_inode) == NULL) {
        // Look for the parent inode
        struct dentry *d_parent;
        bpf_probe_read(&d_parent, sizeof(d_parent), &data_cache->target_dentry->d_parent);
        u32 ino = get_dentry_ino(d_parent);
        if (bpf_map_lookup_elem(&inodes_filter, &ino) == NULL) {
            return 0;
        }
    }
    return 1;
}

__attribute__((always_inline)) static int filter(struct dentry_cache_t *data_cache, u8 flag)
{
    u64 inode_filtering_mode = load_inode_filtering_mode();
    if (inode_filtering_mode == 0) {
        return 1;
    }
    if ((flag & FILTER_SRC) == FILTER_SRC) {
        if (!filter_src(data_cache)) {
            return 0;
        }
    }
    if ((flag & FILTER_TARGET) == FILTER_TARGET) {
        if (!filter_target(data_cache)) {
            return 0;
        }
    }
    return 1;
}

#endif
