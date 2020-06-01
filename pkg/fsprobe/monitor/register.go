package monitor

import (
	"github.com/Gui774ume/fsprobe/pkg/fsprobe/monitor/fs"
	"github.com/Gui774ume/fsprobe/pkg/model"
)

// RegisterMonitors - Register monitors
func RegisterMonitors() []*model.Monitor {
	return []*model.Monitor{
		fs.Monitor,
	}
}
