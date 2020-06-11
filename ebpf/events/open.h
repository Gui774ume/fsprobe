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
#ifndef _OPEN_H_
#define _OPEN_H_

// trace_open - Traces a file system open event.
// @ctx: registers context
// @path: pointer to the file path structure
__attribute__((always_inline)) static int trace_open(struct pt_regs *ctx, struct path *path)
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
    data_cache->fs_event.event = EVENT_OPEN;

    // Add inode data
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &path->dentry);
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    // Mount ID
    struct vfsmount *mnt;
    bpf_probe_read(&mnt, sizeof(struct vfsmount *), &path->mnt);
    bpf_probe_read(&data_cache->fs_event.src_mount_id, sizeof(int), (void *)mnt + 252);

    // Dentry data
    data_cache->src_dentry = dentry;

    // Filter
    if (!filter(data_cache, FILTER_SRC))
        return 0;

    // Send to cache
    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_open_ret - Traces the return of a file system open event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_open_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    data_cache->fs_event.retval = PT_REGS_RC(ctx);

    // Resolve paths
    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    load_dentry_resolution_mode();
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
