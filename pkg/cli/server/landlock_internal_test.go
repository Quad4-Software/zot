//go:build sync

package server //nolint:testpackage // white-box tests for unexported landlock path collection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

func TestCollectLandlockPaths(t *testing.T) {
	Convey("collects storage roots as writable dirs", t, func() {
		conf := config.New()
		conf.Storage.RootDirectory = "/var/lib/zot"
		conf.Storage.SubPaths = map[string]config.StorageConfig{
			"/a": {RootDirectory: "/var/lib/zot-a"},
		}

		paths := collectLandlockPaths(conf, "/etc/zot/config.json")

		So(paths.rwDirs, ShouldContain, "/var/lib/zot")
		So(paths.rwDirs, ShouldContain, "/var/lib/zot-a")
		So(paths.roFiles, ShouldContain, "/etc/zot/config.json")
	})

	Convey("collects auth and tls files as read-only", t, func() {
		conf := config.New()
		conf.Storage.RootDirectory = t.TempDir()
		conf.HTTP.TLS = &config.TLSConfig{Cert: "/certs/tls.crt", Key: "/certs/tls.key", CACert: "/certs/ca.crt"}
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd:        config.AuthHTPasswd{Path: "/etc/zot/htpasswd"},
			SessionKeysFile: "/etc/zot/session.json",
			LDAP:            &config.LDAPConfig{CredentialsFile: "/etc/zot/ldap.json", CACert: "/certs/ldap-ca.crt"},
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {CredentialsFile: "/etc/zot/oidc.json", KeyPath: "/etc/zot/oidc.key"},
				},
			},
			Bearer: &config.BearerConfig{
				Cert: "/certs/bearer.crt",
				OIDC: config.BearerOIDCConfigs{
					{CertificateAuthorityFile: "/certs/oidc-ca.crt"},
				},
			},
		}

		paths := collectLandlockPaths(conf, "")

		for _, file := range []string{
			"/certs/tls.crt", "/certs/tls.key", "/certs/ca.crt",
			"/etc/zot/htpasswd", "/etc/zot/session.json",
			"/etc/zot/ldap.json", "/certs/ldap-ca.crt",
			"/etc/zot/oidc.json", "/etc/zot/oidc.key",
			"/certs/bearer.crt", "/certs/oidc-ca.crt",
		} {
			So(paths.roFiles, ShouldContain, file)
		}
	})

	Convey("collects log outputs as writable files", t, func() {
		conf := config.New()
		conf.Storage.RootDirectory = t.TempDir()
		conf.Log = &config.LogConfig{Output: "/var/log/zot.log", Audit: "/var/log/zot-audit.log"}

		paths := collectLandlockPaths(conf, "")

		So(paths.rwFiles, ShouldContain, "/var/log/zot.log")
		So(paths.rwFiles, ShouldContain, "/var/log/zot-audit.log")
	})

	Convey("collects sync paths and oauth2 helper files", t, func() {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "signing.key")
		signingFile := filepath.Join(dir, "signing.json")

		So(os.WriteFile(keyFile, []byte("pem"), 0o600), ShouldBeNil)

		content, err := json.Marshal(map[string]any{"privateKeyFile": keyFile})
		So(err, ShouldBeNil)
		So(os.WriteFile(signingFile, content, 0o600), ShouldBeNil)

		conf := config.New()
		conf.Storage.RootDirectory = t.TempDir()
		conf.Extensions = &extconf.ExtensionConfig{
			Sync: &syncconf.Config{
				CredentialsFile: "/etc/zot/sync-creds.json",
				DownloadDir:     "/var/lib/zot-sync",
				Registries: []syncconf.RegistryConfig{
					{
						CertDir: "/etc/zot/certs",
						Oauth2CredentialHelper: map[string]any{
							"tokenUrl":    "https://sts.example.com/token",
							"signingFile": signingFile,
						},
					},
				},
			},
		}

		paths := collectLandlockPaths(conf, "")

		So(paths.roFiles, ShouldContain, "/etc/zot/sync-creds.json")
		So(paths.roFiles, ShouldContain, signingFile)
		So(paths.roFiles, ShouldContain, keyFile)
		So(paths.roDirs, ShouldContain, "/etc/zot/certs")
		So(paths.rwDirs, ShouldContain, "/var/lib/zot-sync")
	})

	Convey("dedupes and normalizes paths", t, func() {
		conf := config.New()
		conf.Storage.RootDirectory = "/var/lib/zot"
		conf.HTTP.TLS = &config.TLSConfig{Cert: "/certs/../certs/tls.crt"}

		paths := collectLandlockPaths(conf, "")

		count := 0
		for _, dir := range paths.rwDirs {
			if dir == "/var/lib/zot" {
				count++
			}
		}

		So(paths.roFiles, ShouldContain, "/certs/tls.crt")
		So(count, ShouldEqual, 1)
	})
}
