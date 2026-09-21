//go:build linux

package server

import (
	"github.com/landlock-lsm/go-landlock/landlock"

	"zotregistry.dev/zot/v2/pkg/api/config"
	zlog "zotregistry.dev/zot/v2/pkg/log"
)

// applyLandlock confines the process to the filesystem paths zot needs at
// runtime. It uses Landlock ABI v5 semantics through BestEffort, so on kernels
// with an older ABI the rules downgrade silently and on kernels without
// Landlock the call is a no-op; both cases are logged. Once applied, the
// restriction is irreversible, so this runs only after the controller and
// storage are initialized.
func applyLandlock(conf *config.Config, configPath string, log zlog.Logger) error {
	if !conf.Landlock {
		return nil
	}

	paths := collectLandlockPaths(conf, configPath)

	rules := []landlock.Rule{
		landlock.RODirs(systemRODirs...).IgnoreIfMissing(),
		landlock.RODirs(paths.roDirs...).IgnoreIfMissing(),
		landlock.RWDirs(paths.rwDirs...).IgnoreIfMissing(),
		landlock.ROFiles(paths.roFiles...).IgnoreIfMissing(),
		landlock.RWFiles(paths.rwFiles...).IgnoreIfMissing(),
		landlock.RWFiles("/dev/null"),
	}

	if err := landlock.V5.BestEffort().RestrictPaths(rules...); err != nil {
		return err
	}

	log.Info().Msg("landlock filesystem sandbox enabled")

	return nil
}
