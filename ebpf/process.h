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
#ifndef _PROCESS_H_
#define _PROCESS_H_

// TTY_NAME_LEN - Maximum length of the TTY name
#define TTY_NAME_LEN 16

// process_ctx_t - Contains all the process context collected for a file system event
struct process_ctx_t
{
    // Process data
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
};

// fill_process_data - Fills the provided process_ctx_t with the process context available from eBPF
__attribute__((always_inline)) static u64 fill_process_data(struct process_ctx_t *data)
{
    // Comm
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Pid & Tid
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;
    data->tid = id;

    // UID & GID
    u64 userid = bpf_get_current_uid_gid();
    data->uid = userid >> 32;
    data->gid = userid;
    return id;
}

#endif
