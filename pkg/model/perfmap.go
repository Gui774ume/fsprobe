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
	"os"

	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
)

type LostEvt struct {
	Count uint64
	Map   string
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
