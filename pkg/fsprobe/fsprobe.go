package fsprobe

import (
	"bytes"
	"golang.org/x/sys/unix"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/Gui774ume/fsprobe/pkg/assets"
	"github.com/Gui774ume/fsprobe/pkg/fsprobe/monitor"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/Gui774ume/fsprobe/pkg/utils"

	"github.com/DataDog/gopsutil/host"
	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// FSProbe - Main File system probe structure
type FSProbe struct {
	options      *model.FSProbeOptions
	paths        []string
	wg           *sync.WaitGroup
	collection   *ebpf.Collection
	monitors     []*model.Monitor
	bootTime     time.Time
	hostPidns    uint64
	running      bool
	runningMutex sync.RWMutex
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
		if err := fsp.setup(); err != nil {
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
func (fsp *FSProbe) setup() error {
	// 1) Initialize FSProbe
	if err := fsp.init(); err != nil {
		return err
	}
	// 2) Compile eBPF programs
	if fsp.options.CompileEBPF {
		if err := fsp.compileEBPFProgram(); err != nil {
			return err
		}
	}
	// 3) Load eBPF programs
	if err := fsp.loadEBPFProgram(); err != nil {
		return err
	}
	// 4) Start monitors
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
	if errs := fsp.collection.Close(); len(errs) > 0 {
		logrus.Errorf("couldn't close collection gracefully: %v", errs)
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
	buf, err := assets.Asset("probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}
	reader := bytes.NewReader(buf)
	// Load elf CollectionSpec
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return errors.Wrap(err, "couldn't load collection spec")
	}
	// Edit runtime eBPF contstants
	if err := fsp.EditEBPFConstants(collectionSpec); err != nil {
		return errors.Wrap(err, "couldn't edit runtime eBPF constants")
	}
	// Load eBPF program
	fsp.collection, err = ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{ebpf.ProgramOptions{LogSize: 1024*1024*3}})
	if err != nil {
		return errors.Wrap(err, "couldn't load eBPF program")
	}
	return nil
}

// startMonitors - Loads and attaches the eBPF program in the kernel
func (fsp *FSProbe) startMonitors() error {
	// Register monitors
	fsp.monitors = monitor.RegisterMonitors()
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
	return nil
}

// EditEBPFConstants - Edit the runtime eBPF constants
func (fsp *FSProbe) EditEBPFConstants(spec *ebpf.CollectionSpec) error {
	// There is only one for now: dentry_resolution_mode
	dentryResolutionMode := "dentry_resolution_mode"
	for k, v := range spec.Programs {
		// Only kretprobe use the constant
		if !strings.Contains(v.SectionName, "kretprobe") {
			continue
		}
		editor := ebpf.Edit(&v.Instructions)
		if err := editor.RewriteConstant(dentryResolutionMode, uint64(fsp.options.DentryResolutionMode)); err != nil {
			logrus.Warnf("couldn't rewrite symbol %s in program %s: %v\n", dentryResolutionMode, k, err)
		}
	}
	return nil
}
