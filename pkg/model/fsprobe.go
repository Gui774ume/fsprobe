package model

import (
	"github.com/Gui774ume/ebpf"
	"sync"
	"time"
)

type FSProbe interface {
	GetWaitGroup() *sync.WaitGroup
	GetOptions() *FSProbeOptions
	GetCollection() *ebpf.Collection
	GetBootTime() time.Time
}
