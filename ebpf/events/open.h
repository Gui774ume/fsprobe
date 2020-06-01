#ifndef _OPEN_H_
#define _OPEN_H_

// trace_open - Traces a file system open event.
// @ctx: registers context
// @path: pointer to the file path structure
__attribute__((always_inline)) static int trace_open(struct pt_regs *ctx, struct path *path)
{
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);
    // Probe type
    data_cache.fs_event.event = EVENT_OPEN;

    // Add inode data
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &path->dentry);
    data_cache.fs_event.src_inode = get_dentry_ino(dentry);
    // Mount ID
    struct vfsmount *mnt;
    bpf_probe_read(&mnt, sizeof(struct vfsmount *), &path->mnt);
    bpf_probe_read(&data_cache.fs_event.src_mount_id, sizeof(int), (void *)mnt + 252);

    // Filter
    if (!filter(&data_cache.fs_event.process_data))
        return 0;

    // Cache event
    data_cache.src_dentry = dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
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
    // eBPF doesn't allow copying data from a map to a per buffer, we need a copy of the fs_event in the stack
    struct fs_event_t fs_event = data_cache->fs_event;
    fs_event.retval = PT_REGS_RC(ctx);

    // Resolve paths
    resolve_paths(ctx, data_cache, &fs_event, RESOLVE_SRC | EMIT_EVENT);
    load_dentry_resolution_mode();
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
