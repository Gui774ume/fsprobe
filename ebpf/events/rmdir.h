#ifndef _RMDIR_H_
#define _RMDIR_H_

// trace_rmdir - Traces a file system rmdir event.
// @ctx: registers context
// @dir: pointer to the directory that contains the directory to delete
// @dentry: pointer to the dentry of the directory to delete
__attribute__((always_inline)) static int trace_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);
    // Probe type
    data_cache.fs_event.event = EVENT_RMDIR;

    // Add inode data
    data_cache.fs_event.src_inode = get_dentry_ino(dentry);
    // Add mount ID
    data_cache.fs_event.src_mount_id = get_inode_mount_id(dir);

    // Filter
    if (!filter(&data_cache.fs_event.process_data))
        return 0;

    // Send to cache
    data_cache.src_dentry = dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
    return 0;
}

// trace_rmdir_ret - Traces the return of a file system rmdir event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_rmdir_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    struct fs_event_t fs_event = data_cache->fs_event;
    fs_event.retval = PT_REGS_RC(ctx);

    // Resolve paths
    resolve_paths(ctx, data_cache, &fs_event, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
