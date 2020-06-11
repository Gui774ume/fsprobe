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
package model

import (
	"C"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/Gui774ume/fsprobe/pkg/utils"
)

type EventName string

var (
	// Open - Open event
	Open EventName = "open"
	// Mkdir - Mkdir event
	Mkdir EventName = "mkdir"
	// Link - Soft link event
	Link EventName = "link"
	// Rename - Rename event
	Rename EventName = "rename"
	// SetAttr - Attribute update event
	SetAttr EventName = "setattr"
	// Unlink - File deletion event
	Unlink EventName = "unlink"
	// Rmdir - Directory deletion event
	Rmdir EventName = "rmdir"
	// Modify - File modification event
	Modify EventName = "modify"
	// Unknown - Unknown file event
	Unknown EventName = "unknown"
)

// GetEventType - Returns the event type
func GetEventType(evtType uint32) EventName {
	switch evtType {
	case 0:
		return Open
	case 1:
		return Mkdir
	case 2:
		return Link
	case 3:
		return Rename
	case 4:
		return Unlink
	case 5:
		return Rmdir
	case 6:
		return Modify
	case 7:
		return SetAttr
	default:
		return Unknown
	}
}

// ParseFSEvent - Parses a new FSEvent using the data provided by the kernel
func ParseFSEvent(data []byte, monitor *Monitor) (*FSEvent, error) {
	evt := &FSEvent{}
	read, err := evt.UnmarshalBinary(data, monitor.FSProbe.GetBootTime())
	if err != nil {
		return nil, err
	}
	// Resolve paths
	if err := resolvePaths(data, evt, monitor, read); err != nil {
		return nil, err
	}
	return evt, nil
}

// resolvePaths - Resolves the paths of the event according to the configured method
func resolvePaths(data []byte, evt *FSEvent, monitor *Monitor, read int) error {
	var err error
	switch monitor.Options.DentryResolutionMode {
	case DentryResolutionFragments:
		inode := evt.SrcInode
		if evt.SrcPathnameKey != 0 {
			inode = uint64(evt.SrcPathnameKey)
		}
		evt.SrcFilename, err = monitor.DentryResolver.ResolveInode(evt.SrcMountID, inode)
		if err != nil {
			return errors.Wrap(err, "failed to resolve src dentry path")
		}
		switch evt.EventType {
		case Link, Rename:
			evt.TargetFilename, err = monitor.DentryResolver.ResolveInode(evt.TargetMountID, evt.TargetInode)
			if err != nil {
				return errors.Wrap(err, "failed to resolve target dentry path")
			}
		}
		if evt.EventType == Link {
			// Remove cache entry for link events
			_ = monitor.DentryResolver.RemoveInode(evt.TargetMountID, evt.TargetInode)
			_ = monitor.DentryResolver.RemoveInode(evt.TargetMountID, evt.TargetInode)
		}
		break
	case DentryResolutionSingleFragment:
		evt.SrcFilename, err = monitor.DentryResolver.ResolveKey(evt.SrcPathnameKey, evt.SrcPathnameLength)
		if err != nil {
			return errors.Wrap(err, "failed to resolve src dentry path")
		}
		switch evt.EventType {
		case Link, Rename:
			evt.TargetFilename, err = monitor.DentryResolver.ResolveKey(evt.TargetPathnameKey, evt.TargetPathnameLength)
			if err != nil {
				return errors.Wrap(err, "failed to resolve target dentry path")
			}
		}
		if evt.EventType == Link {
			// Remove cache entry for link events
			_ = monitor.DentryResolver.RemoveEntry(evt.SrcPathnameKey)
			_ = monitor.DentryResolver.RemoveEntry(evt.TargetPathnameKey)
		}
		break
	case DentryResolutionPerfBuffer:
		// Decode path from perf buffer when needed
		srcEnd := read
		if evt.SrcPathnameLength > 0 {
			srcEnd += int(evt.SrcPathnameLength)
			evt.SrcFilename = decodePath(data[read:srcEnd])
		}
		// Resolve end of path from cache when needed
		if evt.SrcPathnameKey > 0 {
			prefix, err := monitor.DentryResolver.ResolveKey(evt.SrcPathnameKey, 0)
			if err != nil {
				return errors.Wrap(err, "failed to resolve src dentry path")
			}
			evt.SrcFilename = prefix + evt.SrcFilename
		}
		// Cache resolved path when needed
		if evt.SrcPathnameLength > 0 && evt.EventType != Link {
			err = monitor.DentryResolver.AddCacheEntry(uint32(evt.SrcInode), evt.SrcFilename)
			if err != nil {
				return errors.Wrap(err, "failed to add src cached inode")
			}
		}
		switch evt.EventType {
		case Link, Rename:
			// Decode path from perf buffer when needed
			if evt.TargetPathnameLength > 0 {
				targetEnd := srcEnd + int(evt.TargetPathnameLength)
				evt.TargetFilename = decodePath(data[srcEnd:targetEnd])
			}
			// Resolve end of path from cache when needed
			if evt.TargetPathnameKey > 0 {
				prefix, err := monitor.DentryResolver.ResolveKey(evt.TargetPathnameKey, 0)
				if err != nil {
					return errors.Wrap(err, "failed to resolve target dentry path")
				}
				evt.TargetFilename = prefix + evt.TargetFilename
			}
			// Cache resolved path when needed
			if evt.TargetPathnameLength > 0 && evt.EventType != Link {
				err = monitor.DentryResolver.AddCacheEntry(uint32(evt.TargetInode), evt.TargetFilename)
				if err != nil {
					return errors.Wrap(err, "failed to add target cached inode")
				}
			}
		}
		break
	}
	return nil
}

// decodePath - Decode the raw path provided by the kernel
func decodePath(raw []byte) string {
	fragments := []string{}
	var fragment, path string
	// Isolate fragments
	for _, b := range raw {
		if b == 0 {
			// End of fragment, append to the end of the list of fragments
			if len(fragment) > 0 {
				fragments = append(fragments, fragment)
			} else {
				// stop resolution there, the rest of the buffer could be leftover from another path
				break
			}
			fragment = ""
		} else {
			fragment += string(b)
		}
	}
	// Check last fragment
	lastFrag := len(fragments) - 1
	if lastFrag < 0 {
		return ""
	}
	if fragments[lastFrag] == "/" {
		fragments = fragments[:lastFrag]
		lastFrag--
	}
	// Rebuild the entire path
	path = "/"
	for i := lastFrag; i >= 0; i-- {
		path += fragments[i] + "/"
	}
	return path[:len(path)-1]
}

// FSEvent - Raw event definition
type FSEvent struct {
	Timestamp            time.Time `json:"-"`
	Pid                  uint32    `json:"pid"`
	Tid                  uint32    `json:"tid"`
	UID                  uint32    `json:"uid"`
	GID                  uint32    `json:"gid"`
	TTYName              string    `json:"tty_name"`
	Comm                 string    `json:"comm"`
	Flags                uint32    `json:"flags,omitempty"`
	Mode                 uint32    `json:"mode,omitempty"`
	SrcInode             uint64    `json:"src_inode,omitempty"`
	SrcPathnameLength    uint32    `json:"-"`
	SrcPathnameKey       uint32    `json:"-"`
	SrcFilename          string    `json:"src_filename,omitempty"`
	SrcMountID           uint32    `json:"src_mount_id,omitempty"`
	TargetInode          uint64    `json:"target_inode,omitempty"`
	TargetPathnameLength uint32    `json:"-"`
	TargetPathnameKey    uint32    `json:"-"`
	TargetFilename       string    `json:"target_filename,omitempty"`
	TargetMountID        uint32    `json:"target_mount_id,omitempty"`
	Retval               int32     `json:"retval"`
	EventType            EventName `json:"event_type"`
}

func (e *FSEvent) UnmarshalBinary(data []byte, bootTime time.Time) (int, error) {
	if len(data) < 112 {
		return 0, errors.New("not enough data")
	}
	// Process context data
	e.Timestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	e.Pid = utils.ByteOrder.Uint32(data[8:12])
	e.Tid = utils.ByteOrder.Uint32(data[12:16])
	e.UID = utils.ByteOrder.Uint32(data[16:20])
	e.GID = utils.ByteOrder.Uint32(data[20:24])
	e.TTYName = string(bytes.Trim(data[24:40], "\x00"))
	e.Comm = string(bytes.Trim(data[40:56], "\x00"))
	// File system event data
	e.Flags = utils.ByteOrder.Uint32(data[56:60])
	e.Mode = utils.ByteOrder.Uint32(data[60:64])
	e.SrcPathnameKey = utils.ByteOrder.Uint32(data[64:68])
	e.TargetPathnameKey = utils.ByteOrder.Uint32(data[68:72])
	e.SrcInode = utils.ByteOrder.Uint64(data[72:80])
	e.SrcPathnameLength = utils.ByteOrder.Uint32(data[80:84])
	e.SrcMountID = utils.ByteOrder.Uint32(data[84:88])
	e.TargetInode = utils.ByteOrder.Uint64(data[88:96])
	e.TargetPathnameLength = utils.ByteOrder.Uint32(data[96:100])
	e.TargetMountID = utils.ByteOrder.Uint32(data[100:104])
	e.Retval = int32(utils.ByteOrder.Uint32(data[104:108]))
	e.EventType = GetEventType(utils.ByteOrder.Uint32(data[108:112]))
	return 112, nil
}

// PrintFilenames - Returns a string representation of the filenames of the event
func (fs *FSEvent) PrintFilenames() string {
	if fs.TargetFilename != "" {
		return fmt.Sprintf("%s -> %s", fs.SrcFilename, fs.TargetFilename)
	}
	return fs.SrcFilename
}

// PrintMode - Returns a string representation of the mode of the event
func (fs *FSEvent) PrintMode() string {
	switch fs.EventType {
	case Open, SetAttr:
		return fmt.Sprintf("%o", fs.Mode)
	default:
		return fmt.Sprintf("%v", fs.Mode)
	}
}

// PrintFlags - Returns a string representation of the flags of the event
func (fs *FSEvent) PrintFlags() string {
	switch fs.EventType {
	case Open:
		return strings.Join(OpenFlagsToStrings(fs.Flags), ",")
	case SetAttr:
		return strings.Join(SetAttrFlagsToString(fs.Flags), ",")
	default:
		return fmt.Sprintf("%v", fs.Flags)
	}
}
