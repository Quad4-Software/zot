package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"zotregistry.dev/zot/v2/pkg/api/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

// landlockPaths groups the filesystem paths zot needs at runtime by the access
// they require. collectLandlockPaths builds it from the loaded configuration so
// the Landlock sandbox can grant exactly these paths and deny everything else.
type landlockPaths struct {
	roDirs  []string
	rwDirs  []string
	roFiles []string
	rwFiles []string
}

// systemRODirs are read-only grants the Go runtime and zot's dependencies need:
// DNS and user resolution, CA bundles for outbound TLS (sync, OIDC, LDAP),
// timezone data and shared library paths for cgo builds.
var systemRODirs = []string{"/etc", "/proc", "/sys", "/dev", "/usr", "/lib", "/lib64"}

func addUnique(list []string, paths ...string) []string {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}

		if !slices.Contains(list, p) {
			list = append(list, p)
		}
	}

	return list
}

// parentDirRO grants read access to the directory holding a file that zot may
// watch or rotate (config file, credential files re-read on reload).
func (p *landlockPaths) addROFile(paths ...string) {
	p.roFiles = addUnique(p.roFiles, paths...)
}

func (p *landlockPaths) addRODir(paths ...string) {
	p.roDirs = addUnique(p.roDirs, paths...)
}

func (p *landlockPaths) addRWFile(paths ...string) {
	p.rwFiles = addUnique(p.rwFiles, paths...)
}

func (p *landlockPaths) addRWDir(paths ...string) {
	p.rwDirs = addUnique(p.rwDirs, paths...)
}

// collectLandlockPaths returns every configured path zot reads from or writes
// to, grouped by required access. Paths that do not exist are still listed;
// callers are expected to attach IgnoreIfMissing so optional files (TLS certs,
// credential files only present in some deployments) do not break startup.
func collectLandlockPaths(conf *config.Config, configPath string) landlockPaths {
	p := landlockPaths{}

	p.addRWDir(conf.Storage.RootDirectory)

	for _, subPath := range conf.Storage.SubPaths {
		p.addRWDir(subPath.RootDirectory)
	}

	p.addROFile(configPath)

	if conf.Log != nil {
		p.addRWFile(conf.Log.Output, conf.Log.Audit)
	}

	httpConf := conf.HTTP
	if httpConf.TLS != nil {
		p.addROFile(httpConf.TLS.Cert, httpConf.TLS.Key, httpConf.TLS.CACert)
	}

	if auth := httpConf.Auth; auth != nil {
		p.addROFile(auth.HTPasswd.Path, auth.SessionKeysFile)

		if auth.Bearer != nil {
			p.addROFile(auth.Bearer.Cert)

			for _, oidcConf := range auth.Bearer.OIDC {
				p.addROFile(oidcConf.CertificateAuthorityFile)
			}
		}

		if ldap := auth.LDAP; ldap != nil {
			p.addROFile(ldap.CredentialsFile, ldap.CACert)
		}

		if auth.OpenID != nil {
			for _, provider := range auth.OpenID.Providers {
				p.addROFile(provider.CredentialsFile, provider.KeyPath)
			}
		}
	}

	if cluster := conf.Cluster; cluster != nil && cluster.TLS != nil {
		p.addROFile(cluster.TLS.Cert, cluster.TLS.Key, cluster.TLS.CACert)
	}

	p.addExtensionPaths(conf)

	p.addRegistryAuthFiles()

	// temp space for multipart handling and libraries that use os.TempDir
	p.addRWDir(os.TempDir())

	return p
}

// addRegistryAuthFiles grants read access to existing docker/containers
// credential files. Sync and the trivy CVE scanner use containers/image
// auth resolution which stats these locations; denying an existing file
// fails downloads outright, while a missing file is handled gracefully.
func (p *landlockPaths) addRegistryAuthFiles() {
	candidates := []string{}

	for _, env := range []struct{ key, rel string }{
		{"DOCKER_CONFIG", "config.json"},
		{"XDG_RUNTIME_DIR", "containers/auth.json"},
		{"XDG_CONFIG_HOME", "containers/auth.json"},
	} {
		if dir := os.Getenv(env.key); dir != "" {
			candidates = append(candidates, filepath.Join(dir, env.rel))
		}
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".docker", "config.json"),
			filepath.Join(home, ".config", "containers", "auth.json"),
		)
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			p.addROFile(candidate)
		}
	}
}

func (p *landlockPaths) addExtensionPaths(conf *config.Config) {
	ext := conf.CopyExtensionsConfig()
	if ext == nil {
		return
	}

	if ext.Sync != nil {
		p.addROFile(ext.Sync.CredentialsFile)
		p.addRWDir(ext.Sync.DownloadDir)

		for _, registry := range ext.Sync.Registries {
			p.addRODir(registry.CertDir)
			p.addOAuth2HelperPaths(registry.Oauth2CredentialHelper)
		}
	}

	if ext.Search != nil && ext.Search.CVE != nil && ext.Search.CVE.Trivy != nil {
		p.addROFile(ext.Search.CVE.Trivy.IgnoreFile)
	}

	if ext.Events != nil {
		for i := range ext.Events.Sinks {
			sink := &ext.Events.Sinks[i]

			if sink.Credentials != nil && sink.File != nil {
				p.addRWFile(*sink.File)
			}

			if sink.TLSConfig != nil {
				p.addROFile(sink.TLSConfig.CACertFile, sink.TLSConfig.CertFile, sink.TLSConfig.KeyFile)
			}
		}
	}
}

// addOAuth2HelperPaths grants read access to the files referenced by a sync
// oauth2 credential helper: the assertion or signing file, the client secret
// file, and the private key file named inside the signing file.
func (p *landlockPaths) addOAuth2HelperPaths(raw map[string]any) {
	if raw == nil {
		return
	}

	helper, err := syncconf.OAuth2HelperConfigFromMap(raw)
	if err != nil || helper == nil {
		return
	}

	p.addROFile(helper.AssertionFile, helper.SigningFile, helper.ClientSecretFile)

	if helper.SigningFile == "" {
		return
	}

	// the signing file points at a separate PEM key mounted next to it
	var signingConf struct {
		PrivateKeyFile string `json:"privateKeyFile"`
	}

	content, err := os.ReadFile(helper.SigningFile)
	if err != nil {
		return
	}

	if err := json.Unmarshal(content, &signingConf); err == nil {
		p.addROFile(signingConf.PrivateKeyFile)
	}
}
