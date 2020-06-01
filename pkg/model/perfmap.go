package model

import (
	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"os"
)

// lostMetrics - Reacts on lost metrics
func lostMetrics(count uint64, mapName string, m *Monitor) {
	logrus.Warnf("%v lost %v events", mapName, count)
}

// PerfMap - Definition of a perf map, used to bring data back to user space
type PerfMap struct {
	monitor            *Monitor
	perfReader         *ebpf.PerfReader
	perfMap            *ebpf.Map
	UserSpaceBufferLen int
	PerfOutputMapName  string
	event              chan []byte
	lost               chan uint64
	stop               chan struct{}
	DataHandler        func(data []byte, m *Monitor)
	LostHandler        func(count uint64, mapName string, m *Monitor)
}

// Init - Initializes perfmap
func (pm *PerfMap) Init(m *Monitor) error {
	pm.monitor = m
	if pm.DataHandler == nil {
		return errors.New("Data handler not set")
	}
	if pm.LostHandler == nil {
		pm.LostHandler = lostMetrics
	}
	// Default userspace buffer length
	if pm.UserSpaceBufferLen == 0 {
		pm.UserSpaceBufferLen = pm.monitor.Options.UserSpaceChanSize
	}
	// Select map
	var ok bool
	pm.perfMap, ok = pm.monitor.collection.Maps[pm.PerfOutputMapName]
	if !ok || pm.perfMap == nil {
		errors.Wrapf(
			errors.New("map not found"),
			"couldn't init map %s",
			pm.PerfOutputMapName,
		)
	}
	// Init channels
	pm.stop = make(chan struct{})
	return nil
}

func (pm *PerfMap) pollStart() error {
	pageSize := os.Getpagesize()
	// Start perf map
	var err error
	pm.perfReader, err = ebpf.NewPerfReader(ebpf.PerfReaderOptions{
		Map:               pm.perfMap,
		PerCPUBuffer:      pm.monitor.Options.PerfBufferSize * pageSize,
		Watermark:         1,
		UserSpaceChanSize: pm.UserSpaceBufferLen,
	})
	if err != nil {
		return errors.Wrapf(err, "couldn't start map %s", pm.PerfOutputMapName)
	}
	go pm.listen()
	return nil
}

// listen - Listen for new events from the kernel
func (pm *PerfMap) listen() {
	pm.monitor.wg.Add(1)
	var sample *ebpf.PerfSample
	var ok bool
	var lostCount uint64
	for {
		select {
		case <-pm.stop:
			pm.monitor.wg.Done()
			return
		case sample, ok = <-pm.perfReader.Samples:
			if !ok {
				pm.monitor.wg.Done()
				return
			}
			pm.DataHandler(sample.Data, pm.monitor)
		case lostCount, ok = <-pm.perfReader.LostRecords:
			if !ok {
				pm.monitor.wg.Done()
				return
			}
			if pm.LostHandler != nil {
				pm.LostHandler(lostCount, pm.PerfOutputMapName, pm.monitor)
			}
		}
	}
}

// pollStop - Stop a perf map listener
func (m *PerfMap) pollStop() error {
	err := m.perfReader.FlushAndClose()
	close(m.stop)
	return err
}
