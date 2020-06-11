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
	"fmt"
	"github.com/Gui774ume/fsprobe/pkg/utils"
	"sync"

	"github.com/Gui774ume/ebpf"
	"github.com/sirupsen/logrus"
)

// Monitor - Base monitor
type Monitor struct {
	wg                 *sync.WaitGroup
	collection         *ebpf.Collection
	ResolutionModeMaps map[DentryResolutionMode][]string
	DentryResolver     DentryResolver
	FSProbe            FSProbe
	InodeFilterSection string
	Name               string
	Options            *FSProbeOptions
	Probes             map[EventName][]*Probe
	PerfMaps           []*PerfMap
}

// Configure - Configures the probes using the provided options
func (m *Monitor) Configure() {
	if len(m.Options.Events) == 0 {
		// Activate everything but the modification probe
		for name, probes := range m.Probes {
			if name == Modify {
				continue
			}
			for _, p := range probes {
				p.Enabled = true
			}
		}
	} else {
		// Activate the requested events
		for _, name := range m.Options.Events {
			probes, ok := m.Probes[name]
			if !ok {
				continue
			}
			for _, p := range probes {
				p.Enabled = true
			}
		}
	}
	// Setup dentry resolver
	m.DentryResolver, _ = NewDentryResolver(m)
}

// GetName - Returns the name of the monitor
func (m *Monitor) GetName() string {
	return m.Name
}

// GetMap - Returns the map at the provided section
func (m *Monitor) GetMap(section string) *ebpf.Map {
	return m.collection.Maps[section]
}

// Init - Initializes the monitor
func (m *Monitor) Init(fs FSProbe) error {
	m.FSProbe = fs
	m.wg = fs.GetWaitGroup()
	m.Options = fs.GetOptions()
	m.collection = fs.GetCollection()
	m.Configure()
	// Init probes
	for _, probes := range m.Probes {
		for _, p := range probes {
			if err := p.Init(m); err != nil {
				return err
			}
		}
	}
	// Prepare perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.Init(m); err != nil {
			return err
		}
	}
	return nil
}

// Start - Starts the monitor
func (m *Monitor) Start() error {
	// start probes
	for _, probes := range m.Probes {
		for _, p := range probes {
			if err := p.Start(); err != nil {
				logrus.Errorf("couldn't start probe \"%s\": %v", p.Name, err)
				return err
			}
		}
	}
	// start polling perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.pollStart(); err != nil {
			return err
		}
	}
	return nil
}

// Stop - Stops the monitor
func (m *Monitor) Stop() error {
	// Stop probes
	for _, probes := range m.Probes {
		for _, p := range probes {
			if err := p.Stop(); err != nil {
				logrus.Errorf("couldn't stop probe \"%s\": %v", p.Name, err)
			}
		}
	}
	// stop polling perf maps
	for _, pm := range m.PerfMaps {
		if err := pm.pollStop(); err != nil {
			logrus.Errorf("couldn't close perf map %v gracefully: %v", pm.PerfOutputMapName, err)
		}
	}
	return nil
}

func (m *Monitor) AddInodeFilter(inode uint32, path string) error {
	// Add file in caches
	if m.DentryResolver != nil {
		if err := m.DentryResolver.AddCacheEntry(inode, path); err != nil {
			return err
		}
	}
	// Add inode filter
	filter := m.GetMap(m.InodeFilterSection)
	if filter == nil {
		return fmt.Errorf("couldn't find %v map", m.InodeFilterSection)
	}
	keyB := make([]byte, 4)
	utils.ByteOrder.PutUint32(keyB, inode)
	var valueB byte
	if err := filter.Put(keyB, valueB); err != nil {
		return err
	}
	return nil
}
