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
	"fmt"

	"github.com/Gui774ume/fsprobe/pkg/model"
)

type EventsValue struct {
	events *[]model.EventName
}

func NewEventsValue(events *[]model.EventName) *EventsValue {
	return &EventsValue{
		events: events,
	}
}

func (ev *EventsValue) String() string {
	return fmt.Sprintf("%v", *ev.events)
}

func (ev *EventsValue) Set(val string) error {
	switch val {
	case "open":
		*ev.events = append(*ev.events, model.Open)
	case "mkdir":
		*ev.events = append(*ev.events, model.Mkdir)
	case "link":
		*ev.events = append(*ev.events, model.Link)
	case "rename":
		*ev.events = append(*ev.events, model.Rename)
	case "setattr":
		*ev.events = append(*ev.events, model.SetAttr)
	case "unlink":
		*ev.events = append(*ev.events, model.Unlink)
	case "rmdir":
		*ev.events = append(*ev.events, model.Rmdir)
	case "modify":
		*ev.events = append(*ev.events, model.Modify)
	default:
		return fmt.Errorf("unknown event type: %v", val)
	}
	return nil
}

func (ev *EventsValue) Type() string {
	return "string"
}

type DentryResolutionModeValue struct {
	mode *model.DentryResolutionMode
}

func NewDentryResolutionModeValue(mode *model.DentryResolutionMode) *DentryResolutionModeValue {
	// Defaults to Perf buffer resolution mode
	*mode = model.DentryResolutionPerfBuffer
	return &DentryResolutionModeValue{
		mode: mode,
	}
}

func (drm *DentryResolutionModeValue) String() string {
	switch *drm.mode {
	case model.DentryResolutionFragments:
		return "fragments"
	case model.DentryResolutionSingleFragment:
		return "single_fragment"
	default:
		return "perf_buffer"
	}
}

func (drm *DentryResolutionModeValue) Set(val string) error {
	switch val {
	case "fragments":
		*drm.mode = model.DentryResolutionFragments
	case "single_fragment":
		*drm.mode = model.DentryResolutionSingleFragment
	case "perf_buffer":
		*drm.mode = model.DentryResolutionPerfBuffer
	default:
		return fmt.Errorf("unknown dentry resolution mode: %v", val)
	}
	return nil
}

func (drm *DentryResolutionModeValue) Type() string {
	return "string"
}
