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
		Name:               "FileSystem",
		InodeFilterSection: model.InodesFilterMap,
		ResolutionModeMaps: map[model.DentryResolutionMode][]string{
			model.DentryResolutionFragments: []string{
				model.PathFragmentsMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.InodesFilterMap,
			},
			model.DentryResolutionSingleFragment: []string{
				model.SingleFragmentsMap,
				model.CachedInodesMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.PathsBuilderMap,
				model.InodesFilterMap,
			},
			model.DentryResolutionPerfBuffer: []string{
				model.CachedInodesMap,
				model.FSEventsMap,
				model.DentryCacheMap,
				model.DentryCacheBuilderMap,
				model.PathsBuilderMap,
				model.InodesFilterMap,
			},
		},
		Probes: map[model.EventName][]*model.Probe{
			model.Open: []*model.Probe{
				&model.Probe{
					Name:        "open",
					SectionName: "kprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "open_ret",
					SectionName: "kretprobe/vfs_open",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Mkdir: []*model.Probe{
				&model.Probe{
					Name:        "mkdir",
					SectionName: "kprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "mkdir_ret",
					SectionName: "kretprobe/vfs_mkdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.RecursiveModeConst,
					},
				},
			},
			model.Unlink: []*model.Probe{
				&model.Probe{
					Name:        "unlink",
					SectionName: "kprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "unlink_ret",
					SectionName: "kretprobe/vfs_unlink",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Rmdir: []*model.Probe{
				&model.Probe{
					Name:        "rmdir",
					SectionName: "kprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "rmdir_ret",
					SectionName: "kretprobe/vfs_rmdir",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Link: []*model.Probe{
				&model.Probe{
					Name:        "link",
					SectionName: "kprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "link_ret",
					SectionName: "kretprobe/vfs_link",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.Rename: []*model.Probe{
				&model.Probe{
					Name:        "rename",
					SectionName: "kprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "rename_ret",
					SectionName: "kretprobe/vfs_rename",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
						model.FollowModeConst,
					},
				},
			},
			model.Modify: []*model.Probe{
				&model.Probe{
					Name:        "modify",
					SectionName: "kprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "modify_ret",
					SectionName: "kretprobe/__fsnotify_parent",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
			model.SetAttr: []*model.Probe{
				&model.Probe{
					Name:        "setattr",
					SectionName: "kprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.InodeFilteringModeConst,
					},
				},
				&model.Probe{
					Name:        "setattr_ret",
					SectionName: "kretprobe/security_inode_setattr",
					Enabled:     false,
					Type:        ebpf.Kprobe,
					Constants: []string{
						model.DentryResolutionModeConst,
					},
				},
			},
		},
		PerfMaps: []*model.PerfMap{
			&model.PerfMap{
				UserSpaceBufferLen: 1000,
				PerfOutputMapName:  "fs_events",
				DataHandler:        HandleFSEvent,
				LostHandler:        LostFSEvent,
			},
		},
	}
)

// LostFSEvent - Handles a LostEvent
func LostFSEvent(count uint64, mapName string, monitor *model.Monitor) {
	// Dispatch event
	if monitor.Options.LostChan != nil {
		monitor.Options.LostChan <- &model.LostEvt{
			Count: count,
			Map:   mapName,
		}
	}
}

// HandleFSEvent - Handles a file system event
func HandleFSEvent(data []byte, monitor *model.Monitor) {
	// Prepare event
	event, err := model.ParseFSEvent(data, monitor)
	if err != nil {
		logrus.Warnf("couldn't parse FSEvent: %v", err)
		return
	}

	// Take cleanup actions on the cache
	switch event.EventType {
	case model.Unlink:
		switch monitor.Options.DentryResolutionMode {
		case model.DentryResolutionSingleFragment:
			if err := monitor.DentryResolver.RemoveEntry(event.SrcPathnameKey); err != nil {
				logrus.Warnf("couldn't clear cache: %v", err)
			}
		case model.DentryResolutionPerfBuffer:
			if err := monitor.DentryResolver.RemoveEntry(uint32(event.SrcInode)); err != nil {
				logrus.Warnf("couldn't clear cache: %v", err)
			}
		case model.DentryResolutionFragments:
			if err := monitor.DentryResolver.RemoveInode(event.SrcMountID, event.SrcInode); err != nil {
				logrus.Warnf("couldn't clear cache: %v", err)
			}
		}
	}

	// Dispatch event
	if monitor.Options.EventChan != nil {
		monitor.Options.EventChan <- event
	}
}
