#ifndef _DENTRY_H_
#define _DENTRY_H_

#define DENTRY_RESOLUTION_FRAGMENTS         0
#define DENTRY_RESOLUTION_SINGLE_FRAGMENT   1
#define DENTRY_RESOLUTION_PERF_BUFFER       2

#define RESOLVE_SRC    1 << 0
#define RESOLVE_TARGET 1 << 1
#define EMIT_EVENT     1 << 2

// get_inode_ino - Returns the inode number of an inode structure
__attribute__((always_inline)) unsigned long get_inode_ino(struct inode *inode)
{
    unsigned long ino;
    bpf_probe_read(&ino, sizeof(inode), &inode->i_ino);
    return ino;
}

// write_inode_ino - Writes the inode number of an inode structure
__attribute__((always_inline)) void write_inode_ino(struct inode *inode, long *ino)
{
    bpf_probe_read(ino, sizeof(inode), &inode->i_ino);
}

// get_inode_mount_id - Returns the mount id of an inode structure
__attribute__((always_inline)) int get_inode_mount_id(struct inode *dir)
{
    // Mount ID
    int mount_id;
    struct super_block *spb;
    bpf_probe_read(&spb, sizeof(spb), &dir->i_sb);

    struct list_head s_mounts;
    bpf_probe_read(&s_mounts, sizeof(s_mounts), &spb->s_mounts);

    bpf_probe_read(&mount_id, sizeof(int), (void *)s_mounts.next + 172);
    // bpf_probe_read(&mount_id, sizeof(int), &((struct mount *) s_mounts.next)->mnt_id);

    return mount_id;
}

// get_dentry_inode - Returns the inode structure designated by the provided dentry
__attribute__((always_inline)) struct inode *get_dentry_inode(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);
    return d_inode;
}

// write_dentry_inode - Writes the inode structure designated by the provided dentry
__attribute__((always_inline)) void write_dentry_inode(struct dentry *dentry, struct inode **d_inode)
{
    bpf_probe_read(d_inode, sizeof(d_inode), &dentry->d_inode);
}

// get_inode_dev - Returns the device number to which the provided inode belongs
__attribute__((always_inline)) dev_t get_inode_dev(struct inode *inode) {
    dev_t dev;
    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

// get_dentry_dev - Returns the device number to which the provided dentry belongs
__attribute__((always_inline)) dev_t get_dentry_dev(struct dentry *dentry) {
    dev_t dev;
    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &dentry->d_sb);
    bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

// get_inode_mountpoint - Returns a pointer to the dentry of the mountpoint to which the provided inode belongs
__attribute__((always_inline)) struct dentry *get_inode_mountpoint(struct inode *dir) {
    // Mount ID
    struct dentry *mountpoint = NULL;
    struct super_block *spb;
    bpf_probe_read(&spb, sizeof(spb), &dir->i_sb);

    struct list_head s_mounts;
    bpf_probe_read(&s_mounts, sizeof(s_mounts), &spb->s_mounts);

    // bpf_probe_read(&mountpoint, sizeof(mountpoint), (void *) s_mounts.next - offsetof(struct mount, mnt_instance) + offsetof(struct mount, mnt_mountpoint));
    bpf_probe_read(&mountpoint, sizeof(mountpoint), (void *) s_mounts.next - 88);

    return mountpoint;
}

// get_dentry_ino - Returns the inode number of the inode designated by the provided dentry
__attribute__((always_inline)) unsigned long get_dentry_ino(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);
    return get_inode_ino(d_inode);
}

// get_file_inode - Returns the inode of the provided file
__attribute__((always_inline)) struct inode *get_file_inode(struct file *file)
{
    struct inode *f_inode;
    bpf_probe_read(&f_inode, sizeof(f_inode), &file->f_inode);
    return f_inode;
}

// get_file_dentry - Returns the dentry of the provided file
__attribute__((always_inline)) struct dentry *get_file_dentry(struct file *file)
{
    struct dentry *f_dentry;
    bpf_probe_read(&f_dentry, sizeof(f_dentry), &file->f_path.dentry);
    return f_dentry;
}

#define PATH_BUILDER_MAX_DEPTH 75

// build_path - Builds the entire path of the provided dentry at the "cursor" offset in the path_builder buffer.
// @path_builder: pointer to the fs event wrapper that contains an initialized path builder buffer
// @cursor: pointer to the position in the buffer where the path should be written
// @dentry: pointer to the dentry to resolve
__attribute__((always_inline)) static u32 build_path(struct fs_event_wrapper_t *path_builder, u32 *cursor, struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    u32 copied = 0;
    u32 path_len = 0;
    u32 offset = 0;

    #pragma unroll
    for (int i = 0; i < PATH_BUILDER_MAX_DEPTH; i++)
    {
        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        // Exit if the path buffer is already full
        if (*cursor >= (PATH_BUFFER_SIZE - 1))
            return path_len;

        // Because of some code optimisation from llvm, the bounds verification fails if *cursor (or offset = *cursor) is
        // used in the bpf_probe_read_str, expression below. To bypass this, copy the value of cursor manually.
        bpf_probe_read(&offset, sizeof(u32), cursor);
        //  & (PATH_BUFFER_SIZE - NAME_MAX - 1) is required by the verifier. It ensures that we will never start copying a path
        // that could be as big as NAME_MAX at an index that is in the last NAME_MAX positions in the buffer.
        copied = bpf_probe_read_str(&path_builder->buff[offset & (PATH_BUFFER_SIZE - NAME_MAX - 1)], NAME_MAX, (void *) qstr.name);
        // & NAME_MAX is required by the verifier. It ensures that we will always add to the cursor a positive value,
        // that is below NAME_MAX (the maximum theoretical value, see the previous line).
        *cursor += (copied & NAME_MAX);
        path_len += copied;
        if (get_dentry_ino(dentry) == get_dentry_ino(d_parent))
        {
           return path_len;
        }
        dentry = d_parent;
    }
    return path_len;
}

#define DENTRY_MAX_DEPTH 75

// resolve_dentry_fragments - Resolves a dentry into multiple fragments, one per parent of the initial dentry.
// Each fragment is saved in a linked list inside the path_fragments hashmap.
// @dentry: pointer to the initial dentry to resolve
// pathname_key: first key of the fragments linked list in the path_fragment hashmap
__attribute__((always_inline)) static int resolve_dentry_fragments(struct dentry *dentry, struct path_key_t *key)
{
    struct path_fragment_t map_value = {};
    struct path_key_t next_key = {};
    next_key = *key;
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *inode_tmp;

    #pragma unroll
    for (int i = 0; i < DENTRY_MAX_DEPTH; i++)
    {
        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&map_value.name, sizeof(map_value.name), (void*) qstr.name);
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
        *key = next_key;
        if (dentry == d_parent) {
            next_key.ino = 0;
        } else {
            write_dentry_inode(d_parent, &inode_tmp);
            write_inode_ino(inode_tmp, &next_key.ino);
        }
        if (map_value.name[0] == '/' || map_value.name[0] == 0) {
            next_key.ino = 0;
        }

        map_value.parent = next_key;

        if (bpf_map_lookup_elem(&path_fragments, key) == NULL) {
            bpf_map_update_elem(&path_fragments, key, &map_value, BPF_ANY);
        } else {
            return i + 1;
        }

        dentry = d_parent;
        if (next_key.ino == 0)
            return i + 1;
    }

    if (next_key.ino != 0) {
        map_value.name[0] = map_value.name[0];
        map_value.parent.mount_id = 0;
        map_value.parent.ino = 0;
        bpf_map_update_elem(&path_fragments, &next_key, &map_value, BPF_ANY);
    }

    return DENTRY_MAX_DEPTH;
}

// resolve_perf_buffer - Resolves the paths of an event using the perf buffer method. This method resolves the paths directly in the buffer
// of the event that will be sent to user space. Therefore, the event sent back to user space has a variable size depending on the paths.
// @ctx: pointer to the registers context structure used to send the perf event.
// @cache: pointer to the dentry_cache_t structure that contains the source and target dentry to resolve
// @fs_event: pointer to an fs_event structure on the stack of the eBPF program that will be used to send the perf event
// flag: defines what dentry should be resolved.
__attribute__((always_inline)) static u32 resolve_perf_buffer(struct pt_regs *ctx, struct dentry_cache_t *cache, struct fs_event_t *fs_event, u8 flag) {
    u32 cpu = bpf_get_smp_processor_id();
    // Prepare the paths buffer
    struct fs_event_wrapper_t *path_builder = bpf_map_lookup_elem(&paths_builder, &cpu);
    if (!path_builder)
        return 0;
    u32 cursor = 0;
    u32 path_len = 0;
    // Resolve paths
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        path_len = build_path(path_builder, &cursor, cache->src_dentry);
        fs_event->src_path_length = path_len;
    }
    if ((flag & RESOLVE_TARGET) == RESOLVE_TARGET) {
        path_len = build_path(path_builder, &cursor, cache->target_dentry);
        fs_event->target_path_length = path_len;
    }
    if ((flag & EMIT_EVENT) == EMIT_EVENT) {
        // & (PATH_BUFFER_SIZE - NAME_MAX - 1) is required by the verifier. It ensures that we will copy more than (or equal to)
        // 0 bytes, and at most PATH_BUFFER_SIZE - NAME_MAX - 1 < PATH_BUFFER_SIZE.
        bpf_probe_read(&path_builder->evt, sizeof(*fs_event), fs_event);
        bpf_perf_event_output(ctx, &fs_events, cpu, path_builder, sizeof(struct fs_event_t) + (cursor & (PATH_BUFFER_SIZE - NAME_MAX - 1)));
    }
    return cursor;
}

// resolve_fragments - Resolves the paths of an event using the multiple fragments method. This method creates an entry in a hashmap for each
// parent of the paths that need to be resolved.
// @ctx: pointer to the registers context structure used to send the perf event.
// @cache: pointer to the dentry_cache_t structure that contains the source and target dentry to resolve
// @fs_event: pointer to an fs_event structure on the stack of the eBPF program that will be used to send the perf event
// flag: defines what dentry should be resolved.
__attribute__((always_inline)) static u32 resolve_fragments(struct pt_regs *ctx, struct dentry_cache_t *cache, struct fs_event_t *fs_event, u8 flag) {
    struct path_key_t key = {};
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        key.ino = get_dentry_ino(cache->src_dentry);
        key.mount_id = cache->fs_event.src_mount_id;
        resolve_dentry_fragments(cache->src_dentry, &key);
    }
    if ((flag & RESOLVE_TARGET) == RESOLVE_TARGET) {
        key.ino = get_dentry_ino(cache->target_dentry);
        key.mount_id = cache->fs_event.target_mount_id;
        resolve_dentry_fragments(cache->target_dentry, &key);
    }
    if ((flag & EMIT_EVENT) == EMIT_EVENT) {
        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &fs_events, cpu, fs_event, sizeof(*fs_event));
    }
    return 0;
}

// resolve_single_fragment - Resolves the paths of an event using the single fragment method. This method resolves the each path in
// one entry of the single_fragments hashmap. The key used to refer to each entry is a random number sent back to user space
// through the fs_events perf event buffer.
// @ctx: pointer to the registers context structure used to send the perf event.
// @cache: pointer to the dentry_cache_t structure that contains the source and target dentry to resolve
// @fs_event: pointer to an fs_event structure on the stack of the eBPF program that will be used to send the perf event
// flag: defines what dentry should be resolved.
__attribute__((always_inline)) static u32 resolve_single_fragment(struct pt_regs *ctx, struct dentry_cache_t *cache, struct fs_event_t *fs_event, u8 flag) {
    u32 cpu = bpf_get_smp_processor_id();
    // Prepare the paths buffer
    struct fs_event_wrapper_t *path_builder = bpf_map_lookup_elem(&paths_builder, &cpu);
    if (!path_builder)
        return 0;
    u32 cursor = 0;
    u32 path_len = 0;
    // Resolve paths
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        path_len = build_path(path_builder, &cursor, cache->src_dentry);
        fs_event->src_path_key = bpf_get_prandom_u32();
        fs_event->src_path_length = path_len;
        // Save fragment
        bpf_map_update_elem(&single_fragments, &fs_event->src_path_key, path_builder->buff, BPF_ANY);
    }
    if ((flag & RESOLVE_TARGET) == RESOLVE_TARGET) {
        path_len = build_path(path_builder, &cursor, cache->target_dentry);
        fs_event->target_path_key = bpf_get_prandom_u32();
        fs_event->target_path_length = path_len;
        // Save fragment
        bpf_map_update_elem(&single_fragments, &fs_event->target_path_key, path_builder->buff, BPF_ANY);
    }
    if ((flag & EMIT_EVENT) == EMIT_EVENT) {
        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &fs_events, cpu, fs_event, sizeof(*fs_event));
    }
    return cursor;
}

// resolve_paths - Resolves the requested paths according to the resolution mode.
// @ctx: pointer to the registers context structure used to send the perf event.
// @cache: pointer to the dentry_cache_t structure that contains the source and target dentry to resolve
// @fs_event: pointer to an fs_event structure on the stack of the eBPF program that will be used to send the perf event
// flag: defines what dentry should be resolved.
__attribute__((always_inline)) static int resolve_paths(struct pt_regs *ctx, struct dentry_cache_t *cache, struct fs_event_t *fs_event, u8 flag) {
    u32 ret = 0;
    u64 resolution_mode = load_dentry_resolution_mode();
    if (resolution_mode == DENTRY_RESOLUTION_FRAGMENTS)
    {
        ret = resolve_fragments(ctx, cache, fs_event, flag);
    }
    if (resolution_mode == DENTRY_RESOLUTION_SINGLE_FRAGMENT)
    {
        ret = resolve_single_fragment(ctx, cache, fs_event, flag);
    }
    if (resolution_mode == DENTRY_RESOLUTION_PERF_BUFFER)
    {
        ret = resolve_perf_buffer(ctx, cache, fs_event, flag);
    }
    return ret;
}

#endif
