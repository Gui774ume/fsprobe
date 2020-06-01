package model

// FSProbeOptions - Filesystem probe options
type FSProbeOptions struct {
	Recursive            bool
	CompileEBPF          bool
	Events               []EventName
	PerfBufferSize       int
	UserSpaceChanSize    int
	DentryResolutionMode DentryResolutionMode
	EventChan            chan *FSEvent
}
