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
	"os"
	"path"
	"syscall"
	"testing"

	"github.com/Gui774ume/fsprobe/pkg/fsprobe"
	"github.com/Gui774ume/fsprobe/pkg/model"
)

// PathsGenerator - Paths generator used for the benchmark
type PathsGenerator struct {
	WatchEntireFilesystem bool
	InScope bool
	Depth int
	Breadth int
	NumOfFiles int
	NamesLength int
	Root string
	folders []string
	files []string
}

func (pg PathsGenerator) GetWatchedPaths(canWatchEntireFilesystem bool) []string {
	if pg.WatchEntireFilesystem && canWatchEntireFilesystem {
		return []string{}
	}
	return []string{pg.Root}
}

func prepareTestFile(b *testing.B) string {
	// Prepare fake file
	root := "/tmp/open/open/open/open/open/"
	if err := os.MkdirAll(root, 0777); err != nil {
		b.Fatal(err)
	}
	return path.Join(root, "open-test")
}

// Open and close files to evaluate the overhead
func openBench(b *testing.B, filepath string) {
	// Start benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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

func benchmarkFSProbe(b *testing.B, resolutionMode model.DentryResolutionMode) {
	// Instantiate a new probe
	probe := fsprobe.NewFSProbeWithOptions(model.FSProbeOptions{
		Events: []model.EventName{model.Open},
		PerfBufferSize: 2048,
		UserSpaceChanSize: 1000,
		DentryResolutionMode: resolutionMode,
		PathsFiltering: false,
		Recursive: true,
	})

	filepath := prepareTestFile(b)

	// Start watching file opens
	if err := probe.Watch("/tmp"); err != nil {
		b.Fatal(err)
	}

	// Open and close files to evaluate the overhead
	openBench(b, filepath)

	// Stop probe
	probe.Stop()
}

func BenchmarkOpen(b *testing.B) {
	filepath := prepareTestFile(b)
	// Open and close files to evaluate the overhead
	openBench(b, filepath)
}

func BenchmarkFSProbePerfBufferOpen(b *testing.B) {
	benchmarkFSProbe(b, model.DentryResolutionPerfBuffer)
}

func BenchmarkFSProbeFragmentsOpen(b *testing.B) {
	benchmarkFSProbe(b, model.DentryResolutionFragments)
}

func BenchmarkFSProbeSingleFragmentOpen(b *testing.B) {
	benchmarkFSProbe(b, model.DentryResolutionSingleFragment)
}

func BenchmarkFSNotifyOpen(b *testing.B) {

}
