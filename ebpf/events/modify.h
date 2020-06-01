#ifndef _MODIFY_H_
#define _MODIFY_H_

// trace_modify - Traces a file modification event.
// @ctx: registers context
// @dentry: pointer to the dentry of the file
__attribute__((always_inline)) static int trace_modify(struct pt_regs *ctx, struct dentry *dentry, __u32 mask)
{
    // We only care about file modification (id est FS_MODIFY)
    if (mask != 2)
    {
        return 0;
    }
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);
    // Probe type
    data_cache.fs_event.event = EVENT_MODIFY;

    // Add inode data
    data_cache.fs_event.src_inode = get_dentry_ino(dentry);
    // Add mount ID
    struct inode *inode = get_dentry_inode(dentry);
    data_cache.fs_event.src_mount_id = get_inode_mount_id(inode);

    // Filter
    if (!filter(&data_cache.fs_event.process_data))
        return 0;

    // Send to cache
    data_cache.src_dentry = dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
    return 0;
}

// trace_modify_ret - Traces the return of a file modification event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_modify_ret(struct pt_regs *ctx)
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
