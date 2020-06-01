package main

import (
	"context"
	"fmt"
	"github.com/Gui774ume/fsprobe/pkg/fsprobe"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"sync"
)

func main() {
	// 1) Parse parameters
	params := ParseParameters()

	// 2) Create output
	output, err := NewOutput(params.Format, params.OutputFilePath)
	if err != nil {
		logrus.Fatalf("couldn't create FSEvent output: %v", err)
	}

	// 3) Setup output callback function
	evtChan := make(chan *model.FSEvent, params.FSOptions.UserSpaceChanSize)
	params.FSOptions.EventChan = evtChan
	ctx, stopCallback := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	go callback(ctx, evtChan, output, wg)

	// 4) Instantiate FSProbe
	probe := fsprobe.NewFSProbeWithOptions(params.FSOptions)

	// 5) Watch the provided paths
	if err := probe.Watch(params.Paths...); err != nil {
		logrus.Fatalf("couldn't watch the provided path: %v", err)
	}

	// 6) Wait until interrupt signal
	waitSignal()
	// Stop fsprobe
	if err := probe.Stop(); err != nil {
		logrus.Fatalf("couldn't gracefully shutdown fsprobe: %v", err)
	}
	// Stop event consumer
	stopCallback()
	wg.Wait()
}

// waitSignal - Wait until an interrupt or kill signal is sent
func waitSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}

// callback - handle a file system event
func callback(ctx context.Context, evtChan chan *model.FSEvent, output Output, wg *sync.WaitGroup) {
	wg.Add(1)
	var evt *model.FSEvent
	var ok bool
	var count int
	for {
		select {
		case <-ctx.Done():
			logrus.Printf("%v events captured", count)
			wg.Done()
			return
		case evt, ok = <-evtChan:
			if !ok {
				logrus.Printf("%v events captured", count)
				wg.Done()
				return
			}
			count++
			// Handle event
			if err := output.Write(evt); err != nil {
				logrus.Errorf("couldn't write event to output: %v", err)
			}
		}
	}
}
