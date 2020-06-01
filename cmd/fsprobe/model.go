package main

import "github.com/Gui774ume/fsprobe/pkg/model"

// CLIOptions - Command line options
type CLIOptions struct {
	Format         string
	OutputFilePath string
	Paths          []string
	FSOptions      model.FSProbeOptions
}
