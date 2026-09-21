//go:build !linux

package server

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	zlog "zotregistry.dev/zot/v2/pkg/log"
)

// applyLandlock is a no-op on platforms without Landlock.
func applyLandlock(conf *config.Config, _ string, log zlog.Logger) error {
	if conf.Landlock {
		log.Warn().Msg("landlock is only supported on Linux, sandbox not applied")
	}

	return nil
}
