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
#ifndef _LINK_H_
#define _LINK_H_

// trace_link - Traces a file system link event.
// @ctx: registers context
// @old_dentry: pointer to the dentry structure of the source file
// @new_dir: pointer to the inode structure of the destination directory
// @new_dentry: pointer to the dentry structure of the destination file
__attribute__((always_inline)) static int trace_link(struct pt_regs *ctx, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    // Reset pathname keys (could mess up resolution if there was some leftover data)
    data_cache->fs_event.src_path_key = 0;
    data_cache->fs_event.target_path_key = 0;
    data_cache->cursor = 0;
    // Add process data
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    // Probe type
    data_cache->fs_event.event = EVENT_LINK;

    // Add old inode data
    data_cache->fs_event.src_inode = get_dentry_ino(old_dentry);
    // Generate a fake key for the old inode as the inode will be reused
    data_cache->fs_event.src_path_key = bpf_get_prandom_u32();
    // Add old mount ID
    struct inode *old_inode = get_dentry_inode(old_dentry);
    data_cache->fs_event.src_mount_id = get_inode_mount_id(old_inode);

    // Dentry data
    data_cache->src_dentry = old_dentry;
    data_cache->target_dir = new_dir;
    data_cache->target_dentry = new_dentry;

    // Filter
    if (filter(data_cache, FILTER_SRC) || filter(data_cache, FILTER_TARGET)) {
        // Resolve source
        resolve_paths(ctx, data_cache, RESOLVE_SRC);
        // cache data
        bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    }

    return 0;
}

// trace_link_ret - Traces the return of a file system link event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_link_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    data_cache->fs_event.retval = PT_REGS_RC(ctx);

    // Add target inode data
    data_cache->fs_event.target_inode = get_dentry_ino(data_cache->target_dentry);
    // Add target mount ID
    data_cache->fs_event.target_mount_id = get_inode_mount_id(data_cache->target_dir);

    // Resolve Paths
    resolve_paths(ctx, data_cache, RESOLVE_TARGET | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
