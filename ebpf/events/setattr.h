#ifndef _SETATTR_H_
#define _SETATTR_H_

// trace_security_inode_setattr - Traces a file system setattr event.
// @ctx: registers context
// @dentry: pointer to the dentry of the file
// @attr: pointer to the iattr structure explaining what happened to the file
__attribute__((always_inline)) static int trace_setattr(struct pt_regs *ctx, struct dentry *dentry, struct iattr *attr)
{
    struct dentry_cache_t data_cache = {};
    // Probe type
    data_cache.fs_event.event = EVENT_SETATTR;

    // Process data
    u64 key = fill_process_data(&data_cache.fs_event.process_data);

    // SetAttr data
    bpf_probe_read(&data_cache.fs_event.flags, sizeof(attr->ia_valid), &attr->ia_valid);
    bpf_probe_read(&data_cache.fs_event.mode, sizeof(attr->ia_mode), &attr->ia_mode);

    // Add inode data
    data_cache.fs_event.src_inode = get_dentry_ino(dentry);
    // Add mount ID
    struct inode *inode = get_dentry_inode(dentry);
    data_cache.fs_event.src_mount_id = get_inode_mount_id(inode);

    // Cache event
    data_cache.src_dentry = dentry;
    bpf_map_update_elem(&dentry_cache, &key, &data_cache, BPF_ANY);
    return 0;
}

// trace_setattr_ret - Traces the return of a file system setattr event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_setattr_ret(struct pt_regs *ctx)
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
