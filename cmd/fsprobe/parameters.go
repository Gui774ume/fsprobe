package main

import (
	"flag"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/sirupsen/logrus"
)

type eventFlags []model.EventName

func (i *eventFlags) String() string {
	return ""
}

func (i *eventFlags) Set(value string) error {
	*i = append(*i, model.EventName(value))
	return nil
}

// ParseParameters - Parse input parameters and return FSProbe options and output options
func ParseParameters() CLIOptions {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:          true,
		TimestampFormat:        "2006-01-02T15:04:05Z",
		DisableLevelTruncation: true,
	})
	options := CLIOptions{}
	// Parse FSProbe options
	flag.IntVar(
		&options.FSOptions.PerfBufferSize,
		"perf-buffer-size",
		128,
		"Perf ring buffer size for kernel-space to user-space communication")
	dentryResolution := ""
	flag.StringVar(
		&dentryResolution,
		"dentry-resolution-mode",
		"perf_buffer",
		"In kernel dentry resolution mode. Can be either \"fragments\", \"single_fragment\" or \"perf_buffer\".")
	flag.BoolVar(
		&options.FSOptions.Recursive,
		"recursive",
		false,
		"Watches all subdirectories of any directory passed as argument. Watches will be set up recursively to an unlimited depth. Symbolic links are traversed. Newly created subdirectories will also be watched")
	flag.BoolVar(
		&options.FSOptions.CompileEBPF,
		"compile-ebpf",
		false,
		"Compiles eBPF code with local kernel headers. Kernel headers are expected to be found at /lib/modules/$(uname -r)/build. If omitted, the pre-compiled eBPF program will be used. Clang & llvm are required.")
	eventFlags := eventFlags{}
	flag.Var(
		&eventFlags,
		"event",
		"Listens for specific event(s) only. This option can be specified more than once. If omitted, only OPEN events are listened for. Available options: open, mkdir, hlink, link, rename, setattr, unlink, rmdir, modify")
	flag.IntVar(
		&options.FSOptions.UserSpaceChanSize,
		"chan-size",
		1000,
		"User space channel size. Default is 1000.")
	// Parse output options
	flag.StringVar(
		&options.Format,
		"format",
		"table",
		"Defines output format. Default is table. Options are: table, json, none")
	flag.StringVar(
		&options.OutputFilePath,
		"output",
		"",
		"Outputs events to <file> rather than stdout")
	flag.Parse()
	options.FSOptions.Events = eventFlags
	options.FSOptions.DentryResolutionMode = model.ParseDentryResolutionMode(dentryResolution)
	options.Paths = flag.Args()
	return options
}
