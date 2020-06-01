#include "main.h"

// Hook points definition
// ----------------------
// Below is the list of all the kernel hook points used by FSProbe.

// OPEN

SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return trace_open(ctx, path);
}

SEC("kretprobe/vfs_open")
int kretprobe_vfs_open(struct pt_regs *ctx)
{
    return trace_open_ret(ctx);
}

// MKDIR

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    umode_t mode = (umode_t)PT_REGS_PARM3(ctx);
    return trace_mkdir(ctx, dir, dentry, mode);
}

SEC("kretprobe/vfs_mkdir")
int kretprobe_vfs_mkdir(struct pt_regs *ctx)
{
    return trace_mkdir_ret(ctx);
}

// UNLINK

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    return trace_unlink(ctx, dir, dentry);
}

SEC("kretprobe/vfs_unlink")
int kretprobe_vfs_unlink(struct pt_regs *ctx)
{
    return trace_unlink_ret(ctx);
}

// RMDIR

SEC("kprobe/vfs_rmdir")
int kprobe_vfs_rmdir(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    return trace_rmdir(ctx, dir, dentry);
}

SEC("kretprobe/vfs_rmdir")
int kretprobe_vfs_rmdir(struct pt_regs *ctx)
{
    return trace_rmdir_ret(ctx);
}

// HLINK

SEC("kprobe/vfs_link")
int kprobe_vfs_link(struct pt_regs *ctx)
{
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct inode *new_dir = (struct inode *)PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    return trace_link(ctx, old_dentry, new_dir, new_dentry);
}

SEC("kretprobe/vfs_link")
int kretprobe_vfs_link(struct pt_regs *ctx)
{
    return trace_link_ret(ctx);
}

// RENAME

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx)
{
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    struct inode *new_dir = (struct inode *)PT_REGS_PARM3(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM4(ctx);
    return trace_rename(ctx, old_dentry, new_dir, new_dentry);
}

SEC("kretprobe/vfs_rename")
int kretprobe_vfs_rename(struct pt_regs *ctx)
{
    return trace_rename_ret(ctx);
}

// MODIFY

SEC("kprobe/__fsnotify_parent")
int kprobe_fsnotify_parent(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    __u32 mask = (__u32)PT_REGS_PARM3(ctx);
    return trace_modify(ctx, dentry, mask);
}

SEC("kretprobe/__fsnotify_parent")
int kretprobe_fsnotify_parent(struct pt_regs *ctx)
{
    return trace_modify_ret(ctx);
}

// SETATTR

SEC("kprobe/security_inode_setattr")
int kprobe_security_inode_setattr(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct iattr *attr = (struct iattr *)PT_REGS_PARM2(ctx);
    return trace_setattr(ctx, dentry, attr);
}

SEC("kretprobe/security_inode_setattr")
int kretprobe_security_inode_setattr(struct pt_regs *ctx)
{
    return trace_setattr_ret(ctx);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
