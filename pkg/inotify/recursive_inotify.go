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
// Package recursive_inotify implements recursive folder monitoring by wrapping the excellent inotify library
package inotify

import (
	"errors"
	"os"
	"path/filepath"
)

// RWatcher wraps inotify.Watcher. When inotify adds recursive watches, you should be able to switch your code to use inotify.Watcher
type RWatcher struct {
	Events chan Event
	Errors chan error

	done     chan struct{}
	inotify *Watcher
	isClosed bool
}

// NewRWatcher establishes a new watcher with the underlying OS and begins waiting for events.
func NewRWatcher() (*RWatcher, error) {
	fsWatch, err := NewWatcher()
	if err != nil {
		return nil, err
	}

	m := &RWatcher{}
	m.inotify = fsWatch
	m.Events = make(chan Event)
	m.Errors = make(chan error)
	m.done = make(chan struct{})

	go m.start()

	return m, nil
}

// Add starts watching the named file or directory (non-recursively).
func (m *RWatcher) Add(name string) error {
	if m.isClosed {
		return errors.New("recursive_inotify instance already closed")
	}
	return m.inotify.Add(name)
}

// AddRecursive starts watching the named directory and all sub-directories.
func (m *RWatcher) AddRecursive(name string) error {
	if m.isClosed {
		return errors.New("recursive_inotify instance already closed")
	}
	if err := m.watchRecursive(name, false); err != nil {
		return err
	}
	return nil
}

// Remove stops watching the the named file or directory (non-recursively).
func (m *RWatcher) Remove(name string) error {
	return m.inotify.Remove(name)
}

// RemoveRecursive stops watching the named directory and all sub-directories.
func (m *RWatcher) RemoveRecursive(name string) error {
	if err := m.watchRecursive(name, true); err != nil {
		return err
	}
	return nil
}

// Close removes all watches and closes the events channel.
func (m *RWatcher) Close() error {
	if m.isClosed {
		return nil
	}
	close(m.done)
	m.isClosed = true
	return nil
}

func (m *RWatcher) start() {
	for {
		select {

		case e := <-m.inotify.Events:
			s, err := os.Stat(e.Name)
			if err == nil && s != nil && s.IsDir() {
				if e.Op&Create != 0 {
					m.watchRecursive(e.Name, false)
				}
			}
			//Can't stat a deleted directory, so just pretend that it's always a directory and
			//try to remove from the watch list...  we really have no clue if it's a directory or not...
			if e.Op&Remove != 0 {
				m.inotify.Remove(e.Name)
			}
			m.Events <- e

		case e := <-m.inotify.Errors:
			m.Errors <- e

		case <-m.done:
			m.inotify.Close()
			close(m.Events)
			close(m.Errors)
			return
		}
	}
}

// watchRecursive adds all directories under the given one to the watch list.
// this is probably a very racey process. What if a file is added to a folder before we get the watch added?
func (m *RWatcher) watchRecursive(path string, unWatch bool) error {
	err := filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if unWatch {
				if err = m.inotify.Remove(walkPath); err != nil {
					return err
				}
			} else {
				if err = m.inotify.Add(walkPath); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return err
}
