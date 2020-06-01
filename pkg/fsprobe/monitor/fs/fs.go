package fs

import (
	"C"
	"github.com/Gui774ume/ebpf"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/sirupsen/logrus"
)

var (
	// Monitor - eBPF FIM event monitor
	Monitor = &model.Monitor{
		Name: "FileSystem",
		MapNames: []string{
			model.PathFragmentsSection,
			model.SingleFragmentsSection,
		},
		Probes: map[model.EventName][]*model.Probe{
			model.Open: []*model.Probe{
				&model.Probe{
					Name:        "open",
					SectionName: "kprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "open_ret",
					SectionName: "kretprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Mkdir: []*model.Probe{
				&model.Probe{
					Name:        "mkdir",
					SectionName: "kprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "mkdir_ret",
					SectionName: "kretprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Unlink: []*model.Probe{
				&model.Probe{
					Name:        "unlink",
					SectionName: "kprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "unlink_ret",
					SectionName: "kretprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Rmdir: []*model.Probe{
				&model.Probe{
					Name:        "rmdir",
					SectionName: "kprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "rmdir_ret",
					SectionName: "kretprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.HLink: []*model.Probe{
				&model.Probe{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "link_ret",
					SectionName: "kretprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Rename: []*model.Probe{
				&model.Probe{
					Name:        "rename",
					SectionName: "kprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "rename_ret",
					SectionName: "kretprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.Modify: []*model.Probe{
				&model.Probe{
					Name:        "modify",
					SectionName: "kprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "modify_ret",
					SectionName: "kretprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
			model.SetAttr: []*model.Probe{
				&model.Probe{
					Name:        "setattr",
					SectionName: "kprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
				&model.Probe{
					Name:        "setattr_ret",
					SectionName: "kretprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
				},
			},
		},
		PerfMaps: []*model.PerfMap{
			&model.PerfMap{
				UserSpaceBufferLen: 1000,
				PerfOutputMapName:  "fs_events",
				DataHandler:        HandleFSEvent,
			},
		},
	}
)

// HandleFSEvent - Handles a file system event
func HandleFSEvent(data []byte, monitor *model.Monitor) {
	// Prepare event
	event, err := model.ParseFSEvent(data, monitor)
	if err != nil {
		logrus.Warnf("couldn't parse FSEvent: %v", err)
		return
	}

	// Dispatch event
	monitor.Options.EventChan <- event
}

// HandleRawEvent - Handles a raw event
func HandleRawEvent(data []byte, monitor *model.Monitor) {
	tot := ""
	for elem := range data {
		if elem == 0 {
			tot += "/"
		}
		tot += string(elem)
	}
	logrus.Printf("PATH: %d\n", data)
}
