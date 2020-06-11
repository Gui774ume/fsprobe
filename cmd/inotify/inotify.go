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
package main

import (
	"flag"
	"fmt"
	"github.com/Gui774ume/fsprobe/pkg/inotify"
	"log"
	"os"
	"os/signal"
)

func main() {
	watcher, err := inotify.NewRWatcher()
	if err != nil {
		log.Println(err)
	}

	flag.Parse()
	paths := flag.Args()
	for _, path := range paths {
		watcher.AddRecursive(path)
	}

	for {
		e := <-watcher.Events
		fmt.Println(e)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
}
