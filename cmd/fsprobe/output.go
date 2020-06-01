package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Gui774ume/fsprobe/pkg/model"
)

// Output - Data output interface
type Output interface {
	Write(event *model.FSEvent) error
}

// NewOutput - Returns an output interface based on the requested format & output
func NewOutput(format string, path string) (Output, error) {
	var writer io.Writer
	var err error
	if path == "" {
		writer = os.Stdout
	} else {
		writer, err = os.Open(path)
		if err != nil {
			return nil, err
		}
	}
	switch format {
	case "json":
		return JSONOutput{output: writer}, nil
	case "none":
		return DummyOutput{}, nil
	default:
		return NewTableOutput(writer), nil
	}
}

// JSONOutput - JSON output writer
type JSONOutput struct {
	output io.Writer
}

// Write - Write the event to the output writer
func (so JSONOutput) Write(event *model.FSEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := so.output.Write(data); err != nil {
		return err
	}
	return nil
}

// TableOutput - Table output writer
type TableOutput struct {
	output io.Writer
	fmt    string
	tsFmt  string
}

func NewTableOutput(writer io.Writer) TableOutput {
	out := TableOutput{
		output: writer,
		fmt:    "%7v %7v %6v %6v %6v %6v %16v %6v %10v %6v %6v %16v %s\n",
		tsFmt:  "3:04PM",
	}
	out.PrintHeader()
	return out
}

// Write - Write the event to the output writer
func (to TableOutput) Write(event *model.FSEvent) error {
	fmt.Printf(
		to.fmt,
		event.EventType,
		event.Timestamp.Format(to.tsFmt),
		event.Pid,
		event.Tid,
		event.UID,
		event.GID,
		event.Comm,
		event.TTYName,
		event.SrcInode,
		model.ErrValueToString(event.Retval),
		event.PrintMode(),
		event.PrintFlags(),
		event.PrintFilenames(),
	)
	return nil
}

// PrintHeader - Prints table header
func (to TableOutput) PrintHeader() {
	fmt.Printf(to.fmt, "EVT", "TS", "PID", "TID", "UID", "GID", "CMD", "TTY", "INODE", "RET", "MODE", "FLAG", "PATH")
}

// DummyOutput - Dummy output for the none format
type DummyOutput struct{}

// Write - Write the event to the output writer
func (do DummyOutput) Write(event *model.FSEvent) error {
	return nil
}
