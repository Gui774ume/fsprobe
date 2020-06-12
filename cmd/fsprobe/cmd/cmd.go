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
package cmd

import (
	"github.com/spf13/cobra"
)

// FSProbeCmd represents the base command when called without any subcommands
var FSProbeCmd = &cobra.Command{
	Use:   "fsprobe [paths]",
	Short: "A file system events notifier based on eBPF",
	Long: `FSProbe is a file system events notifier based on eBPF

FSProbe relies on eBPF to capture file system events on dentry kernel structures.
More information about the project can be found on github: https://github.com/Gui774ume/fsprobe`,
	RunE: runFSProbeCmd,
	Example: "sudo fsprobe /tmp",
}

// options - CLI options
var options CLIOptions

func init() {
	FSProbeCmd.Flags().Var(
		NewDentryResolutionModeValue(&options.FSOptions.DentryResolutionMode),
		"dentry-resolution-mode",
		`In-kernel dentry resolution mode. Can be either "fragments",
"single_fragment" or "perf_buffer"`)
	FSProbeCmd.Flags().BoolVarP(
		&options.FSOptions.Recursive,
		"recursive",
		"r",
		true,
		`Watches all subdirectories of any directory passed as argument.
Watches will be set up recursively to an unlimited depth.
Symbolic links are not traversed. Newly created subdirectories
will also be watched. When this option is not provided, only
the immediate children of a provided directory are watched`)
	FSProbeCmd.Flags().BoolVar(
		&options.FSOptions.PathsFiltering,
		"paths-filtering",
		true,
		`When activated, FSProbe will only notify events on the paths 
provided to the Watch function. When deactivated, FSProbe
will notify events on the entire file system`)
	FSProbeCmd.Flags().BoolVar(
		&options.FSOptions.FollowRenames,
		"follow",
		true,
		`When activated, FSProbe will keep watching the files that were
initially in a watched directory and were moved to a location
that is not necessarily watched. In other words, files are followed
even after a move`)
	FSProbeCmd.Flags().VarP(
		NewEventsValue(&options.FSOptions.Events),
		"event",
		"e",
		`Listens for specific event(s) only. This option can be specified
more than once. If omitted, only "open" events are listened for.
Available options: open, mkdir, link, rename, setattr, unlink,
rmdir, modify`)
	FSProbeCmd.Flags().IntVarP(
		&options.FSOptions.UserSpaceChanSize,
		"chan-size",
		"s",
		1000,
		"User space channel size")
	FSProbeCmd.Flags().IntVar(
		&options.FSOptions.PerfBufferSize,
		"perf-buffer-size",
		128,
		`Perf ring buffer size for kernel-space to user-space
communication`)
	FSProbeCmd.Flags().StringVarP(
		&options.Format,
		"format",
		"f",
		"table",
		`Defines the output format.
Options are: table, json, none`)
	FSProbeCmd.Flags().StringVarP(
		&options.OutputFilePath,
		"output",
		"o",
		"",
		`Outputs events to the provided file rather than
stdout`)
}
