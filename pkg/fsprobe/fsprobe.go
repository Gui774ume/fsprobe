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
package fsprobe

import (
	"bytes"
	"fmt"
	"github.com/Gui774ume/fsprobe/pkg/fsprobe/monitor"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Gui774ume/fsprobe/pkg/assets"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/Gui774ume/fsprobe/pkg/utils"

	"github.com/DataDog/gopsutil/host"
	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// FSProbe - Main File system probe structure
type FSProbe struct {
	options        *model.FSProbeOptions
	paths          []string
	wg             *sync.WaitGroup
	collection     *ebpf.Collection
	collectionSpec *ebpf.CollectionSpec
	monitors       []*model.Monitor
	bootTime       time.Time
	hostPidns      uint64
	running        bool
	runningMutex   sync.RWMutex
}

// NewFSProbeWithOptions - Creates a new FSProbe instance with the provided options
func NewFSProbeWithOptions(options model.FSProbeOptions) *FSProbe {
	// Extend RLIMIT_MEMLOCK (8) size
	err := unix.Setrlimit(8, &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
	if err != nil {
		logrus.Errorln("WARNING: Failed to adjust RLIMIT_MEMLOCK limit, loading eBPF maps might fail")
	}
	return &FSProbe{
		options: &options,
		paths:   []string{},
		wg:      &sync.WaitGroup{},
	}
}

// GetWaitGroup - Returns the wait group of fsprobe
func (fsp *FSProbe) GetWaitGroup() *sync.WaitGroup {
	return fsp.wg
}

// GetOptions - Returns the config of fsprobe
func (fsp *FSProbe) GetOptions() *model.FSProbeOptions {
	return fsp.options
}

// GetCollection - Returns the eBPF collection of fsprobe
func (fsp *FSProbe) GetCollection() *ebpf.Collection {
	return fsp.collection
}

// GetBootTime - Returns the boot time of fsprobe
func (fsp *FSProbe) GetBootTime() time.Time {
	return fsp.bootTime
}

// GetHostPidns - Returns the host pidns of fsprobe
func (fsp *FSProbe) GetHostPidns() uint64 {
	return fsp.hostPidns
}

// Watch - start watching the provided paths. This function is thread safe and can be called multiple times. If
// already running, the new paths will be added dynamically.
func (fsp *FSProbe) Watch(paths ...string) error {
	// 1) Check if FSProbe is already running
	fsp.runningMutex.RLock()
	if fsp.running {
		fsp.runningMutex.RUnlock()
	} else {
		// 1.1) setup FSProbe for the first time
		fsp.runningMutex.RUnlock()
		fsp.runningMutex.Lock()
		if err := fsp.start(); err != nil {
			return err
		}
		fsp.running = true
		fsp.runningMutex.Unlock()
	}
	// 2) Add watches for the provided paths
	if err := fsp.addWatch(paths...); err != nil {
		return err
	}
	return nil
}

// setup - runs the setup steps to start fsprobe
func (fsp *FSProbe) start() error {
	// 1) Initialize FSProbe
	if err := fsp.init(); err != nil {
		return err
	}
	// 2) Load eBPF programs
	if err := fsp.loadEBPFProgram(); err != nil {
		return err
	}
	// 3) Start monitors
	if err := fsp.startMonitors(); err != nil {
		return err
	}
	return nil
}

// init - Initializes the NetworkSecurityProbe
func (fsp *FSProbe) init() error {
	// Set a unique seed to prepare the generation of IDs
	rand.Seed(time.Now().UnixNano())
	// Get boot time
	bt, err := host.BootTime()
	if err != nil {
		return err
	}
	fsp.bootTime = time.Unix(int64(bt), 0)
	// Get host netns
	fsp.hostPidns = utils.GetPidnsFromPid(1)
	// Register monitors
	fsp.monitors = monitor.RegisterMonitors()
	return nil
}

// Stop - Stop the file system probe
func (fsp *FSProbe) Stop() error {
	// 1) Stop monitors
	for _, p := range fsp.monitors {
		if err := p.Stop(); err != nil {
			logrus.Errorf("couldn't stop monitor (Ctrl+C to abort): %v", p.GetName(), err)
		}
	}
	// 2) Close eBPF programs
	if fsp.collection != nil {
		if errs := fsp.collection.Close(); len(errs) > 0 {
			logrus.Errorf("couldn't close collection gracefully: %v", errs)
		}
	}
	// 3) Wait for all goroutine to stop
	fsp.wg.Wait()
	return nil
}

// compileEBPFProgram - Compile the eBPF programs of FSProbe using clang & llvm
func (fsp *FSProbe) compileEBPFProgram() error {
	return nil
}

// loadEBPFProgram - Loads the compiled eBPF programs
func (fsp *FSProbe) loadEBPFProgram() error {
	// Recover asset
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}
	reader := bytes.NewReader(buf)
	// Load elf CollectionSpec
	fsp.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return errors.Wrap(err, "couldn't load collection spec")
	}
	// Remove unused maps based on the selected dentry resolution method
	fsp.removeUnusedMaps()
	// Edit runtime eBPF constants
	if err := fsp.EditEBPFConstants(fsp.collectionSpec); err != nil {
		return errors.Wrap(err, "couldn't edit runtime eBPF constants")
	}
	// Load eBPF program
	fsp.collection, err = ebpf.NewCollectionWithOptions(fsp.collectionSpec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSize: 1024 * 1024 * 3}})
	if err != nil {
		return errors.Wrap(err, "couldn't load eBPF program")
	}
	return nil
}

// startMonitors - Loads and attaches the eBPF program in the kernel
func (fsp *FSProbe) startMonitors() error {
	// Init monitors
	for _, p := range fsp.monitors {
		if err := p.Init(fsp); err != nil {
			logrus.Errorf("failed to init monitor %s: %v", p.GetName(), err)
			return err
		}
	}
	// Start monitors
	for _, p := range fsp.monitors {
		if err := p.Start(); err != nil {
			logrus.Errorf("failed to start monitor %s: %v", p.GetName(), err)
			return err
		}
	}
	return nil
}

// addWatch - Updates the eBPF hashmaps to look for the provided paths
func (fsp *FSProbe) addWatch(paths ...string) error {
	// Add paths to the list of watched paths
	fsp.runningMutex.Lock()
	fsp.paths = append(fsp.paths, paths...)
	fsp.runningMutex.Unlock()
	if fsp.options.Recursive {
		// Watch all directories provided in paths recursively
		return fsp.addRecursiveWatch(paths...)
	}
	// On watch the top level directories
	return fsp.addTopLevelWatch(paths...)
}

// addTopLevelWatch - Adds watches by walking only the top level depth of directories
func (fsp *FSProbe) addTopLevelWatch(paths ...string) error {
	for _, p := range paths {
		// Check if the path is a directory
		pathInfo, err := os.Stat(p)
		if err != nil {
			return err
		}
		if pathInfo.IsDir() {
			// List the top level of the directory
			files, err := ioutil.ReadDir(p)
			if err != nil {
				return err
			}
			for _, f := range files {
				fullPath := path.Join(p, f.Name())
				statTmp, ok := f.Sys().(*syscall.Stat_t)
				if !ok && statTmp == nil {
					continue
				}
				// Add inode in cache
				fsp.watchInode(uint32(statTmp.Ino), fullPath)
			}
		}
		// Add the file (or directory itself) to the list of watched files
		pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
		if !ok && pathStat == nil {
			continue
		}
		// Add file in cache
		fsp.watchInode(uint32(pathStat.Ino), p)
	}
	return nil
}

// addRecursiveWatch - Adds watches by walking through all the provided paths recursively
func (fsp *FSProbe) addRecursiveWatch(paths ...string) error {
	var err error
	for _, path := range paths {
		err = filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
			if err != nil {
				logrus.Warnf("couldn't add watch for %s: %v", walkPath, err)
				return nil
			}
			if !fi.IsDir() {
				return nil
			}
			stat, ok := fi.Sys().(*syscall.Stat_t)
			if !ok && stat == nil {
				return nil
			}
			// Add inode in cache
			fsp.watchInode(uint32(stat.Ino), walkPath)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// watchInode - Adds an inode the in the resolver cache
func (fsp *FSProbe) watchInode(inode uint32, path string) {
	for _, m := range fsp.monitors {
		// Add inode filter
		if err := m.AddInodeFilter(inode, path); err != nil {
			logrus.Warnf("couldn't watch inode %v of path %s: %v", inode, path, err)
			continue
		}
	}
}

// EditEBPFConstants - Edit the runtime eBPF constants
func (fsp *FSProbe) EditEBPFConstants(spec *ebpf.CollectionSpec) error {
	// Edit the constants of all the probes declared in FSProbe
	for _, mon := range fsp.monitors {
		for _, probes := range mon.Probes {
			for _, probe := range probes {
				if len(probe.Constants) == 0 {
					continue
				}
				spec, ok := spec.Programs[probe.SectionName]
				if !ok {
					return fmt.Errorf("couldn't find section %s", probe.SectionName)
				}
				editor := ebpf.Edit(&spec.Instructions)
				// Edit constants
				for _, constant := range probe.Constants {
					var value uint64
					switch constant {
					case model.DentryResolutionModeConst:
						value = uint64(fsp.options.DentryResolutionMode)
					case model.InodeFilteringModeConst:
						if fsp.options.PathsFiltering {
							value = 1
						}
					case model.FollowModeConst:
						if fsp.options.FollowRenames {
							value = 1
						}
					case model.RecursiveModeConst:
						if fsp.options.Recursive {
							value = 1
						}
					default:
						return fmt.Errorf("couldn't rewrite symbol %s in program %s: unknown symbol", constant, probe.SectionName)
					}
					if err := editor.RewriteConstant(constant, value); err != nil {
						logrus.Warnf("couldn't rewrite symbol %s in program %s: %v", constant, probe.SectionName, err)
					}
				}
			}
		}
	}
	return nil
}

// removeUnusedMaps - Removes unused maps in the collectionSpec so that we use less kernel memory
func (fsp *FSProbe) removeUnusedMaps() {
	if fsp.collectionSpec == nil {
		return
	}
	toRemove := []string{}
	for name := range fsp.collectionSpec.Maps {
		used := false
		// check if the map is used in all the monitors
		for _, m := range fsp.monitors {
			rmm, ok := m.ResolutionModeMaps[fsp.options.DentryResolutionMode]
			if !ok {
				continue
			}
			for _, eMapName := range rmm {
				logrus.Debugln(eMapName)
				if name == eMapName {
					used = true
					break
				}
			}
			if used {
				break
			}
		}
		if !used {
			toRemove = append(toRemove, name)
		}
	}
	for _, name := range toRemove {
		delete(fsp.collectionSpec.Maps, name)
	}
}
