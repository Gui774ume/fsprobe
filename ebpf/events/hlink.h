#ifndef _HLINK_H_
#define _HLINK_H_

// trace_link - Traces a file system link event.
// @ctx: registers context
// @old_dentry: pointer to the dentry structure of the source file
// @new_dir: pointer to the inode structure of the destination directory
// @new_dentry: pointer to the dentry structure of the destination file
__attribute__((always_inline)) static int trace_link(struct pt_regs *ctx, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);
    // Probe type
    data_cache.fs_event.event = EVENT_HLINK;

    // Add old inode data
    data_cache.fs_event.src_inode = get_dentry_ino(old_dentry);
    // Add old mount ID
    struct inode *old_inode = get_dentry_inode(old_dentry);
    data_cache.fs_event.src_mount_id = get_inode_mount_id(old_inode);

    // Filter
    if (!filter(&data_cache.fs_event.process_data))
        return 0;

    // Send to cache
    data_cache.src_dentry = old_dentry;
    data_cache.target_dir = new_dir;
    data_cache.target_dentry = new_dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
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
    struct fs_event_t fs_event = data_cache->fs_event;
    fs_event.retval = PT_REGS_RC(ctx);

    // Add target inode data
    fs_event.target_inode = get_dentry_ino(data_cache->target_dentry);
    // Add target mount ID
    fs_event.target_mount_id = get_inode_mount_id(data_cache->target_dir);

    // Resolve Paths
    resolve_paths(ctx, data_cache, &fs_event, RESOLVE_SRC | RESOLVE_TARGET | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
