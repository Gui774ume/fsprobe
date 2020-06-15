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
package tests

import (
	"github.com/Gui774ume/fsprobe/pkg/fsprobe"
	"github.com/Gui774ume/fsprobe/pkg/model"
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"syscall"
	"testing"
)

func prepareTestFile(b *testing.B) string {
	// Prepare fake file
	root := "/tmp/open/open/open/open/open/"
	if err := os.MkdirAll(root, 0777); err != nil {
		b.Fatal(err)
	}
	return path.Join(root, "open-test")
}

// benchmarkOpen - Opens a file from the paths generator and benchmark the overhead
func benchmarkOpen(b *testing.B, pg *PathsGenerator) {
	// Start benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filepath := pg.GetRandomFile()
		// Select a file in the list
		fd, err := syscall.Open(filepath, syscall.O_CREAT, 0777)
		if err != nil {
			b.Fatal(err)
		}

		if err := syscall.Close(fd); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func benchmarkFSProbe(b *testing.B, options model.FSProbeOptions, pg *PathsGenerator) {
	b.Logf("restarted %d", b.N)
	// Initialize the paths generator
	if err := pg.Init(); err != nil {
		b.Fatal(err)
	}
	// Handle lost events
	lostChan := make(chan *model.LostEvt, options.UserSpaceChanSize)
	options.LostChan = lostChan
	go pollLost(lostChan)
	// Instantiate a new probe
	probe := fsprobe.NewFSProbeWithOptions(options)

	// Start watching file opens
	if err := probe.Watch(pg.GetWatchedPaths()...); err != nil {
		b.Fatal(err)
	}

	// Open and close files to evaluate the overhead
	benchmarkOpen(b, pg)

	// Stop probe
	if err := probe.Stop(); err != nil {
		b.Error(err)
	}

	// Clean up paths generator
	if err := pg.Close(); err != nil {
		b.Fatal(err)
	}

	// Close lost events handler
	close(lostChan)
}

func pollLost(lostChan chan *model.LostEvt) {
	var evt *model.LostEvt
	var ok bool
	select {
		case evt, ok = <-lostChan:
			if !ok {
				return
			}
			logrus.Warnf("lost %v events from %v", evt.Count, evt.Map)
			break
	}
}

func BenchmarkOpen(b *testing.B) {
	pg := &PathsGenerator{
		Depth: 5,
		Breadth: 8000,
		NumOfFiles: 80000,
		NamesLength: 10,
		Root: "/tmp/fsprobe",
	}
	if err := pg.Init(); err != nil {
		b.Fatal(err)
	}
	// Open and close files to evaluate the overhead
	benchmarkOpen(b, pg)
	if err := pg.Close(); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkFSProbePerfBufferOpen(b *testing.B) {
	benchmarkFSProbe(b, model.FSProbeOptions{
		Events: []model.EventName{model.Open},
		PerfBufferSize: 4096,
		UserSpaceChanSize: 1000,
		DentryResolutionMode: model.DentryResolutionPerfBuffer,
		PathsFiltering: true,
		Recursive: true,
	}, &PathsGenerator{
		Depth: 5,
		Breadth: 8000,
		NumOfFiles: 80000,
		NamesLength: 10,
		Root: "/tmp/fsprobe",
	})
}

func BenchmarkFSProbeFragmentsOpen(b *testing.B) {
	benchmarkFSProbe(b, model.FSProbeOptions{
		Events: []model.EventName{model.Open},
		PerfBufferSize: 4096,
		UserSpaceChanSize: 1000,
		DentryResolutionMode: model.DentryResolutionFragments,
		PathsFiltering: true,
		Recursive: true,
	}, &PathsGenerator{
		Depth: 5,
		Breadth: 8000,
		NumOfFiles: 80000,
		NamesLength: 10,
		Root: "/tmp/fsprobe",
	})
}

func BenchmarkFSProbeSingleFragmentOpen(b *testing.B) {
	benchmarkFSProbe(b, model.FSProbeOptions{
		Events: []model.EventName{model.Open},
		PerfBufferSize: 4096,
		UserSpaceChanSize: 1000,
		DentryResolutionMode: model.DentryResolutionSingleFragment,
		PathsFiltering: true,
		Recursive: true,
	}, &PathsGenerator{
		Depth: 5,
		Breadth: 8000,
		NumOfFiles: 80000,
		NamesLength: 10,
		Root: "/tmp/fsprobe",
	})
}

func BenchmarkPerfBufferSize(b *testing.B) {
	options := model.FSProbeOptions{
		Events: []model.EventName{model.Open},
		UserSpaceChanSize: 1000,
		PathsFiltering: true,
		Recursive: true,
	}
	benchmarks := []struct {
		name string
		perfBufferSize int
		resolutionMode model.DentryResolutionMode
	}{
		{"Fragments8", 8, model.DentryResolutionFragments},
		{"SingleFragment8", 8, model.DentryResolutionSingleFragment},
		{"PerfBuffer8", 8, model.DentryResolutionPerfBuffer},
		{"Fragments16", 16, model.DentryResolutionFragments},
		{"SingleFragment16", 16, model.DentryResolutionSingleFragment},
		{"PerfBuffer16", 16, model.DentryResolutionPerfBuffer},
		{"Fragments32", 32, model.DentryResolutionFragments},
		{"SingleFragment32", 32, model.DentryResolutionSingleFragment},
		{"PerfBuffer32", 32, model.DentryResolutionPerfBuffer},
		{"Fragments64", 64, model.DentryResolutionFragments},
		{"SingleFragment64", 64, model.DentryResolutionSingleFragment},
		{"PerfBuffer64", 64, model.DentryResolutionPerfBuffer},
		{"Fragments128", 128, model.DentryResolutionFragments},
		{"SingleFragment128", 128, model.DentryResolutionSingleFragment},
		{"PerfBuffer128", 128, model.DentryResolutionPerfBuffer},
		{"Fragments256", 256, model.DentryResolutionFragments},
		{"SingleFragment256", 256, model.DentryResolutionSingleFragment},
		{"PerfBuffer256", 256, model.DentryResolutionPerfBuffer},
		{"Fragments512", 512, model.DentryResolutionFragments},
		{"SingleFragment512", 512, model.DentryResolutionSingleFragment},
		{"PerfBuffer512", 512, model.DentryResolutionPerfBuffer},
		{"Fragments1024", 1024, model.DentryResolutionFragments},
		{"SingleFragment1024", 1024, model.DentryResolutionSingleFragment},
		{"PerfBuffer1024", 1024, model.DentryResolutionPerfBuffer},
		{"Fragments2048", 2048, model.DentryResolutionFragments},
		{"SingleFragment2048", 2048, model.DentryResolutionSingleFragment},
		{"PerfBuffer2048", 2048, model.DentryResolutionPerfBuffer},
		{"Fragments4096", 4096, model.DentryResolutionFragments},
		{"SingleFragment4096", 4096, model.DentryResolutionSingleFragment},
		{"PerfBuffer4096", 4096, model.DentryResolutionPerfBuffer},
	}
	for _, bm := range benchmarks {
		options.PerfBufferSize = bm.perfBufferSize
		options.DentryResolutionMode = bm.resolutionMode
		b.Run(bm.name, func(b *testing.B) {
			pg := PathsGenerator{
				Depth: 60,
				Breadth: 1000,
				NumOfFiles: 60000,
				NamesLength: 10,
				Root: "/tmp/fsprobe",
			}
			benchmarkFSProbe(b, options, &pg)
		})
	}
}
