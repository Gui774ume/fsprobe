package model

import "github.com/Gui774ume/ebpf"

// Probe - eBPF probe structure
type Probe struct {
	Name        string
	Enabled     bool
	monitor     *Monitor
	Type        ebpf.ProgType
	SectionName string
	// Kprobe specific parameters
	KProbeMaxActive int
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
	// Enable eBPF program
	collection := p.monitor.collection
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
