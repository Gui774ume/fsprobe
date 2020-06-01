#ifndef _CONST_H_
#define _CONST_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

// load_dentry_resolution_mode - Loads the dentry resolution mode
__attribute__((always_inline)) static u64 load_dentry_resolution_mode() {
    u64 dentry_resolution_mode = 0;
    LOAD_CONSTANT("dentry_resolution_mode", dentry_resolution_mode);
    return dentry_resolution_mode;
}

#endif
