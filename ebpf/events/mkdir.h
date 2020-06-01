#ifndef _MKDIR_H_
#define _MKDIR_H_

// trace_mkdir - Traces a file system mkdir event.
// @ctx: registers context
// @dir: pointer to the inode of the containing directory
// @dentry: pointer to the dentry structure of the new directory
// @mode: mode of the mkdir call
__attribute__((always_inline)) static int trace_mkdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);
    // Probe type
    data_cache.fs_event.event = EVENT_MKDIR;

    // Add mode
    data_cache.fs_event.mode = (int)mode;

    // Mount ID
    data_cache.fs_event.src_mount_id = get_inode_mount_id(dir);

    // Filter
    if (!filter(&data_cache.fs_event.process_data))
        return 0;

    // Send to cache dentry
    data_cache.src_dentry = dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
    return 0;
}

// trace_mkdir_ret - Traces the return of a file system mkdir event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_mkdir_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    struct fs_event_t fs_event = data_cache->fs_event;
    fs_event.retval = PT_REGS_RC(ctx);

    // Add inode data
    fs_event.src_inode = get_dentry_ino(data_cache->src_dentry);

    // Resolve paths
    resolve_paths(ctx, data_cache, &fs_event, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
