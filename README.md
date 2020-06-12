## FSProbe

FSProbe is a file system events notifier based on eBPF. Instead of hooking at the syscall level (like other well-known eBPF solutions: [opensnoop](https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py), [Falco](https://github.com/falcosecurity/falco), ...), FSProbe works by listening for events at the VFS level. Paths are resolved at runtime by traversing the `dentry` tree up to the mount point of the filesystem. One of the main advantages of this solution is that the paths provided by FSProbe are absolute and resolved, while a syscall based strategy would only export syscall parameters (and thus potentially attacker controlled data).

### Requirements

- golang 1.13+

If you want to rebuild the eBPF programs, make sure to h:

- This project was built on a Linux Kernel 5.3 and should be compatible with Kernels 5.0+. Support for [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) will be added shortly so that eBPF compilation won't be needed anymore.
- Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- clang & llvm (version 8.0.1)

### Getting Started

1) If you need to rebuild the eBPF programs, use the following command:

```shell script
make build-ebpf
```

2) To build FSProbe, run:

```shell script
make build
```

3) To install FSProbe (copy to /usr/bin/fsprobe) run:
```shell script
make install
```

4) FSProbe needs to run as root. Run `sudo fsprobe -h` to get help.

```shell script
# ~ ./bin/fsprobe -h
FSProbe is a file system events notifier based on eBPF

FSProbe relies on eBPF to capture file system events on dentry kernel structures.
More information about the project can be found on github: https://github.com/Gui774ume/fsprobe

Usage:
  fsprobe [paths] [flags]

Examples:
sudo fsprobe /tmp

Flags:
  -s, --chan-size int                   User space channel size (default 1000)
      --dentry-resolution-mode string   In-kernel dentry resolution mode. Can be either "fragments",
                                        "single_fragment" or "perf_buffer" (default "perf_buffer")
  -e, --event string                    Listens for specific event(s) only. This option can be specified
                                        more than once. If omitted, only "open" events are listened for.
                                        Available options: open, mkdir, link, rename, setattr, unlink,
                                        rmdir, modify (default "[]")
      --follow                          When activated, FSProbe will keep watching the files that were
                                        initially in a watched directory and were moved to a location
                                        that is not necessarily watched. In other words, files are followed
                                        even after a move (default true)
  -f, --format string                   Defines the output format.
                                        Options are: table, json, none (default "table")
  -h, --help                            help for fsprobe
  -o, --output string                   Outputs events to the provided file rather than
                                        stdout
      --paths-filtering                 When activated, FSProbe will only notify events on the paths
                                        provided to the Watch function. When deactivated, FSProbe
                                        will notify events on the entire file system (default true)
      --perf-buffer-size int            Perf ring buffer size for kernel-space to user-space
                                        communication (default 128)
  -r, --recursive                       Watches all subdirectories of any directory passed as argument.
                                        Watches will be set up recursively to an unlimited depth.
                                        Symbolic links are not traversed. Newly created subdirectories
                                        will also be watched. When this option is not provided, only
                                        the immediate children of a provided directory are watched (default true)
```

### Dentry resolution mode

FSProbe can be configured to use one of 3 different `dentry` resolution modes. A performance benchmark can be found below to understand the overhead of each solution in kernel space and user space. All three methods are implemented in [dentry.h](ebpf/dentry.h).

#### Fragments

##### Architecture

![Fragments solution architecture](documentation/fragments.png)

##### Cache

The `path_fragments` hashmap is used as an in-kernel cache. This means that the dentry resolver will not always insert a fragment if it is already present. Similarly, the dentry resolution will stop as soon as a path is found in cache.

#### Single Fragment

##### Architecture

![Fragments solution architecture](documentation/single_fragments.png)

##### Cache

Just like `path_fragments`, `single_fragments` is used as an in-kernel cache. If an inode has already been resolved it will not be resolved a second time. 

#### Perf buffer

##### Architecture

![Fragments solution architecture](documentation/perf_buffer.png)

##### Cache

This method relies on a user space cache and the `cached_inodes` eBPF hashmap to decide where the in-kernel resolution should stop. Since the `cached_inodes` map is queried on each parent of a file, the resolution can stop right in the middle, in which case the event sent back to user space will only contain the missing part. For example, on the graph below, `/etc` was in the cache but the `passwd` file was not; the event sent on the ring buffer contains the missing part of the path (`passwd`) and the inode & mount ID of the cached prefix (`{43, 27}`). In order to avoid resolving `passwd` again, a new entry in both the user space cache and the `cached_inodes` eBPF hashmap are added (see the doted lines).

#### Benchmark

### Capabilities Matrix

| Feature | [Inotify](https://www.man7.org/linux/man-pages/man7/inotify.7.html) | [FSProbe](https://github.com/Gui774ume/fsprobe) | [Opensnoop](https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py) | [Perf](http://www.brendangregg.com/perf.html) | 
| --- | --- | --- | --- | --- |
| Process context | :x: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Container context | :x: | :white_check_mark: (not implemented yet) | :white_check_mark: (not implemented) | :x: |
| Inode context | :x: | :white_check_mark: | :x: | :white_check_mark: |
| Mount point context | :x: | :white_check_mark: | :x: | :white_check_mark: |
| User / Group context | :x: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| In-kernel filtering | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Recursive | :x: | :white_check_mark: | :x: | :x: |
| Follow files after move | :x: | :white_check_mark: | :x: | :x: |
