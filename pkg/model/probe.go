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
	"github.com/Gui774ume/ebpf"
)

// Probe - eBPF probe structure
type Probe struct {
	Name        string
	Enabled     bool
	monitor     *Monitor
	Type        ebpf.ProgType
	SectionName string
	// Kprobe specific parameters
	KProbeMaxActive int
	// Constants will be edited with configuration at runtime
	Constants []string
}

// Init - Initializes the probe
func (p *Probe) Init(m *Monitor) error {
	if !p.Enabled {
		return nil
	}
	p.monitor = m
	return nil
}

// Start - Starts the probe
func (p *Probe) Start() error {
	if !p.Enabled {
		return nil
	}
	collection := p.monitor.collection
	// Enable eBPF program
	switch p.Type {
	case ebpf.TracePoint:
		if err := collection.EnableTracepoint(p.SectionName); err != nil {
			return err
		}
	case ebpf.Kprobe:
		maxActive := -1
		if p.KProbeMaxActive != 0 {
			maxActive = p.KProbeMaxActive
		}
		if err := collection.EnableKprobe(p.SectionName, maxActive); err != nil {
			return err
		}
	}
	return nil
}

// Stop - Stops the probe
func (p *Probe) Stop() error {
	if !p.Enabled {
		return nil
	}
	return nil
}
