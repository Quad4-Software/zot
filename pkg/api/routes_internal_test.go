package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	docker "github.com/distribution/distribution/v3/manifest/schema2"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestParseRangeHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		size    int64
		want    []httpRange
		wantErr bool
	}{
		{
			name:   "open ended range",
			header: "bytes=0-",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "range end is capped to size",
			header: "bytes=0-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "suffix range",
			header: "bytes=-3",
			size:   10,
			want:   []httpRange{{start: 7, end: 9}},
		},
		{
			name:   "oversized suffix range returns whole blob",
			header: "bytes=-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "ranges are sorted",
			header: "bytes=7-8, 0-1",
			size:   10,
			want: []httpRange{
				{start: 0, end: 1},
				{start: 7, end: 8},
			},
		},
		{
			name:   "overlapping and adjacent ranges are coalesced",
			header: "bytes=0-2,3-4,6-8,7-9",
			size:   10,
			want: []httpRange{
				{start: 0, end: 4},
				{start: 6, end: 9},
			},
		},
		{name: "zero size", header: "bytes=0-", wantErr: true},
		{name: "wrong unit", header: "byte=0-1", size: 10, wantErr: true},
		{name: "empty range set", header: "bytes=", size: 10, wantErr: true},
		{name: "empty range spec", header: "bytes=0-1,", size: 10, wantErr: true},
		{name: "zero suffix", header: "bytes=-0", size: 10, wantErr: true},
		{name: "bad suffix", header: "bytes=-x", size: 10, wantErr: true},
		{name: "bad start", header: "bytes=x-1", size: 10, wantErr: true},
		{name: "bad end", header: "bytes=1-x", size: 10, wantErr: true},
		{name: "inverted range", header: "bytes=2-1", size: 10, wantErr: true},
		{name: "range starts at size", header: "bytes=10-", size: 10, wantErr: true},
		{name: "range without dash", header: "bytes=0", size: 10, wantErr: true},
		{
			name:    "too many ranges",
			header:  "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", maxRangeSpecCount+1), ","),
			size:    10,
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRangeHeader(test.header, test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected parse error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("expected ranges %v, got %v", test.want, got)
			}
		})
	}
}

func TestNormalizeBlobRedirectURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "preserves signed url bytes unchanged",
			rawURL:  "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantURL: "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantOK:  true,
		},
		{
			name:    "allows http scheme",
			rawURL:  "http://storage.example.com/blob",
			wantURL: "http://storage.example.com/blob",
			wantOK:  true,
		},
		{
			name:   "rejects disallowed scheme",
			rawURL: "javascript:alert(1)",
			wantOK: false,
		},
		{
			name:   "rejects parse failure",
			rawURL: "https://storage.example.com/%zz",
			wantOK: false,
		},
		{
			name:   "rejects missing host",
			rawURL: "https:///blob",
			wantOK: false,
		},
		{
			name:   "rejects crlf injection",
			rawURL: "https://storage.example.com/blob?sig=abc\r\nX-Test: y",
			wantOK: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOK := normalizeBlobRedirectURL(test.rawURL)
			if gotOK != test.wantOK {
				t.Fatalf("expected ok=%v, got %v", test.wantOK, gotOK)
			}

			if gotURL != test.wantURL {
				t.Fatalf("expected url %q, got %q", test.wantURL, gotURL)
			}
		})
	}
}

func TestIsBlobRedirectEnabled(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						RedirectBlobURL: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/a": {
							RedirectBlobURL: true,
						},
					},
				},
			},
			StoreController: storage.StoreController{
				SubStore: map[string]storageTypes.ImageStore{
					"/a": nil,
				},
			},
		},
	}

	if !routeHandler.isBlobRedirectEnabled("a/repo") {
		t.Fatal("expected redirect to be enabled for /a subpath repo")
	}

	// Default storage remains disabled even when a specific subpath enables redirect.
	if routeHandler.isBlobRedirectEnabled("b/repo") {
		t.Fatal("expected redirect to be disabled for default storage")
	}
}

func TestCanMountTraditionalBearer(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	imgStore := mocks.MockedImageStore{
		GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
			return []string{"src/repo"}, nil
		},
	}
	digest := godigest.FromString("bearer-mount-test")

	req := httptest.NewRequest(http.MethodPost, "/v2/dest/blobs/uploads/", nil)
	acCtrlr := NewAccessController(conf)

	configUser := reqCtx.NewUserAccessControl()
	configUser.SetUsername("alice")
	acCtrlr.updateUserAccessControl(req, configUser)
	acCtrlr.attachPermissionEvaluator(req, configUser)

	ok, err := canMount(configUser, imgStore, digest, "dest")
	require.NoError(t, err)
	require.True(t, ok)

	emptyConfigUser := reqCtx.NewUserAccessControl()
	acCtrlr.attachPermissionEvaluator(req, emptyConfigUser)

	ok, err = canMount(emptyConfigUser, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)

	destOnlyBearer := UserAccessControlFromBearerAccess([]ResourceAccess{
		{Type: "repository", Name: "dest", Actions: []string{"push"}},
	})
	ok, err = canMount(destOnlyBearer, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)

	authorizedBearer := UserAccessControlFromBearerAccess([]ResourceAccess{
		{Type: "repository", Name: "dest", Actions: []string{"push"}},
		{Type: "repository", Name: "src/repo", Actions: []string{"pull"}},
	})
	ok, err = canMount(authorizedBearer, imgStore, digest, "dest")
	require.NoError(t, err)
	require.True(t, ok)

	catalogBearer := UserAccessControlFromBearerAccess([]ResourceAccess{
		{Type: "repository", Name: "dest", Actions: []string{"push"}},
		{Type: "repository", Name: "", Actions: []string{"pull"}},
	})
	ok, err = canMount(catalogBearer, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)

	wildcardBearer := UserAccessControlFromBearerAccess([]ResourceAccess{
		{Type: "repository", Name: "dest", Actions: []string{"push"}},
		{Type: "repository", Name: "**", Actions: []string{"pull"}},
	})
	ok, err = canMount(wildcardBearer, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCanMountDedupeCandidatesError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	candidatesErr := errors.New("candidates failed")
	imgStore := mocks.MockedImageStore{
		GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
			return nil, candidatesErr
		},
	}

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername("alice")
	req := httptest.NewRequest(http.MethodPost, "/v2/dest/blobs/uploads/", nil)
	acCtrlr := NewAccessController(conf)
	acCtrlr.attachPermissionEvaluator(req, userAc)

	ok, err := canMount(userAc, imgStore, godigest.FromString("candidates-err"), "dest")
	require.ErrorIs(t, err, candidatesErr)
	require.False(t, ok)
}

func TestShouldCheckMountSourceAccess(t *testing.T) {
	t.Parallel()

	t.Run("config authz always checks regardless of scoped permissions", func(t *testing.T) {
		t.Parallel()

		require.True(t, shouldCheckMountSourceAccess(
			&config.AccessControlConfig{},
			reqCtx.NewUserAccessControl(),
		))
	})

	t.Run("no config authz: catalog-only bearer skips mount source check", func(t *testing.T) {
		t.Parallel()

		catalogOnly := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "", Actions: []string{"pull"}},
		})
		require.False(t, catalogOnly.HasScopedPermissions())
		require.False(t, shouldCheckMountSourceAccess(nil, catalogOnly))
	})

	t.Run("no config authz: scoped bearer enables mount source check", func(t *testing.T) {
		t.Parallel()

		scoped := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "dest", Actions: []string{"push"}},
		})
		require.True(t, scoped.HasScopedPermissions())
		require.True(t, shouldCheckMountSourceAccess(nil, scoped))
	})
}

func TestUserMayMountBlobGate(t *testing.T) {
	t.Parallel()

	digest := godigest.FromString("user-may-mount-gate")

	t.Run("catalog-only bearer skips canMount and allows remount", func(t *testing.T) {
		t.Parallel()

		// Traditional bearer without AccessControl: catalog-only tokens must not
		// install empty glob maps, so hydrate remount is not gated on source pull.
		conf := config.New()
		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}

		userAc := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "", Actions: []string{"pull"}},
		})
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		candidatesCalled := false
		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				candidatesCalled = true

				return nil, errors.New("should not be consulted")
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.True(t, ok)
		require.False(t, candidatesCalled)
	})

	t.Run("scoped bearer without source pull denies remount", func(t *testing.T) {
		t.Parallel()

		conf := config.New()
		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}

		userAc := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "dest", Actions: []string{"push"}},
		})
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		candidatesCalled := false
		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				candidatesCalled = true

				return []string{"src/repo"}, nil
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.False(t, ok)
		require.True(t, candidatesCalled)
	})

	t.Run("scoped bearer with dest pull only denies remount", func(t *testing.T) {
		t.Parallel()

		conf := config.New()
		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}

		userAc := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "dest", Actions: []string{"pull"}},
		})
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				return []string{"src/repo"}, nil
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("scoped bearer with dest pull and push but no src pull denies remount", func(t *testing.T) {
		t.Parallel()

		conf := config.New()
		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}

		userAc := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "dest", Actions: []string{"pull", "push"}},
		})
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				return []string{"src/repo"}, nil
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("scoped bearer with source pull allows remount", func(t *testing.T) {
		t.Parallel()

		conf := config.New()
		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}

		userAc := UserAccessControlFromBearerAccess([]ResourceAccess{
			{Type: "repository", Name: "dest", Actions: []string{"push"}},
			{Type: "repository", Name: "src/repo", Actions: []string{"pull"}},
		})
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				return []string{"src/repo"}, nil
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("config authz always consults canMount", func(t *testing.T) {
		t.Parallel()

		conf := config.New()
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users: []string{"alice"},
							Actions: []string{
								constants.ReadPermission,
								constants.CreatePermission,
							},
						},
					},
				},
			},
		}

		rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("alice")
		acCtrlr := NewAccessController(conf)
		acCtrlr.updateUserAccessControl(req, userAc)
		acCtrlr.attachPermissionEvaluator(req, userAc)
		userAc.SaveOnRequest(req)

		candidatesCalled := false
		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				candidatesCalled = true

				return []string{"src/repo"}, nil
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.True(t, ok)
		require.True(t, candidatesCalled)
	})
}

func TestUserMayMountBlobErrorPaths(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}
	digest := godigest.FromString("user-may-mount-err")

	t.Run("bad user access control type", func(t *testing.T) {
		t.Parallel()

		ctx := context.WithValue(context.Background(), reqCtx.GetContextKey(), "not-a-user-ac")
		req := httptest.NewRequestWithContext(ctx, http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)

		ok, err := rh.userMayMountBlob(req, mocks.MockedImageStore{}, digest, "dest")
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("canMount candidates error is denied", func(t *testing.T) {
		t.Parallel()

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("alice")
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		candidatesErr := errors.New("candidates failed")
		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				return nil, candidatesErr
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestResolveBlobPresenceUserMayMountError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.Storage.HydrateBlobOnRead = true
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	rh := &RouteHandler{
		c: &Controller{
			Config:          conf,
			Log:             log.NewTestLogger(),
			StoreController: storage.StoreController{},
		},
	}

	digest := godigest.FromString("resolve-presence-err")
	ctx := context.WithValue(context.Background(), reqCtx.GetContextKey(), "not-a-user-ac")
	req := httptest.NewRequestWithContext(ctx, http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)

	ok, size, err := rh.resolveBlobPresence(req, mocks.MockedImageStore{}, "dest", digest)
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, int64(-1), size)
}

func TestRejectUnsignedManifest(t *testing.T) {
	t.Parallel()

	defaultVal := true

	conf := &config.Config{}
	conf.Extensions = &extconf.ExtensionConfig{
		Trust: &extconf.ImageTrustConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			Cosign:     true,
			SignedOnly: true,
		},
	}

	rh := &RouteHandler{
		c: &Controller{
			Config: conf,
			Log:    log.NewTestLogger(),
			// no signatures recorded: any deployable manifest push creating a
			// tag must be rejected
			MetaDB: mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{Signatures: map[mTypes.ImageDigest]mTypes.ManifestSignatures{}}, nil
				},
			},
		},
	}

	imageManifest := func(configMediaType string, withSubject bool) []byte {
		manifest := map[string]interface{}{
			"schemaVersion": 2,
			"mediaType":     ispec.MediaTypeImageManifest,
			"config": map[string]interface{}{
				"mediaType": configMediaType,
				"digest":    godigest.FromString("config").String(),
				"size":      2,
			},
			"layers": []interface{}{},
		}

		if withSubject {
			manifest["subject"] = map[string]interface{}{
				"mediaType": ispec.MediaTypeImageManifest,
				"digest":    godigest.FromString("subject").String(),
				"size":      42,
			}
		}

		raw, err := json.Marshal(manifest)
		require.NoError(t, err)

		return raw
	}

	hex64 := strings.Repeat("a", 64)

	cases := []struct {
		name        string
		reference   string
		mediaType   string
		body        []byte
		createsTags bool
		want        bool
	}{
		// deployable image manifests pushed under a tag are enforced
		{"tagged image manifest", "1.0", ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, false), false, true},
		// a fake subject does not exempt a runnable image manifest
		{"image manifest with fake subject", "1.0", ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, true), false, true},
		{"image manifest with docker config and fake subject", "1.0", ispec.MediaTypeImageManifest,
			imageManifest(docker.MediaTypeImageConfig, true), false, true},
		// referrer-style artifacts stay exempt so sign/attest flows work
		{"non-image config artifact", "1.0", ispec.MediaTypeImageManifest,
			imageManifest("application/vnd.in-toto+json", true), false, false},
		{"empty config artifact", "1.0", ispec.MediaTypeImageManifest,
			imageManifest("", true), false, false},
		// indexes are always deployable
		{"index under tag", "1.0", ispec.MediaTypeImageIndex,
			[]byte(`{"schemaVersion":2,"manifests":[]}`), false, true},
		// digest pushes that create no tag stay allowed for sign-then-tag
		{"digest push no tag", "sha256:" + hex64, ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, false), false, false},
		// digest pushes carrying tag= create tags and are enforced
		{"digest push with tag param", "sha256:" + hex64, ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, false), true, true},
		// only exact cosign tag patterns are exempt
		{"exact cosign sig tag", "sha256-" + hex64 + ".sig", ispec.MediaTypeImageManifest,
			imageManifest("application/vnd.dev.cosign.simplesigning.v1+json", false), false, false},
		{"exact cosign sbom tag", "sha256-" + hex64 + ".sbom", ispec.MediaTypeImageManifest,
			imageManifest("application/vnd.in-toto+json", false), false, false},
		{"short-hex sig tag", "sha256-dead.sig", ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, false), false, true},
		{"prefixed sig tag", "v1-sha256-" + hex64 + ".sig", ispec.MediaTypeImageManifest,
			imageManifest(ispec.MediaTypeImageConfig, false), false, true},
		{"uppercase hex sig tag", "sha256-" + strings.Repeat("A", 64) + ".sig",
			ispec.MediaTypeImageManifest, imageManifest(ispec.MediaTypeImageConfig, false), false, true},
		// exact referrers fallback tag is exempt, lookalikes are not
		{"referrers fallback tag", "sha256-" + hex64, ispec.MediaTypeImageIndex,
			[]byte(`{"schemaVersion":2,"manifests":[]}`), false, false},
		{"referrers lookalike tag", "sha256-" + hex64 + "zz", ispec.MediaTypeImageIndex,
			[]byte(`{"schemaVersion":2,"manifests":[]}`), false, true},
		// unparseable bodies fail closed
		{"malformed manifest json", "1.0", ispec.MediaTypeImageManifest,
			[]byte(`{"schemaVersion":`), false, true},
		// non-manifest media types are not gated here
		{"non-manifest media type", "1.0", "application/vnd.oci.artifact.v1+json",
			[]byte(`{}`), false, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := rh.rejectUnsignedManifest(context.Background(), "repo", tc.reference,
				tc.mediaType, tc.body, tc.createsTags)
			require.Equal(t, tc.want, got)
		})
	}
}
