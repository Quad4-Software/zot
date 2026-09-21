//go:build mgmt

package extensions

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func TestAuthMarshalJSONNilHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{APIKey: true})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.True(t, decoded["apikey"].(bool))
	assert.NotContains(t, decoded, "htpasswd")
}

func TestAuthMarshalJSONLDAPOnly(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		LDAP: &struct {
			Address string `json:"address,omitempty" mapstructure:"address"`
		}{Address: "ldap.example.com"},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "ldap")

	htpasswd, ok := decoded["htpasswd"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, htpasswd)
}

func TestAuthMarshalJSONBearerOnlyEmptyHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		HTPasswd: &HTPasswd{},
		Bearer: &BearerConfig{
			Realm:   "https://auth.example.com/token",
			Service: "zot",
		},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "htpasswd")
	assert.NotContains(t, decoded, "ldap")

	bearer, ok := decoded["bearer"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://auth.example.com/token", bearer["realm"])
	assert.Equal(t, "zot", bearer["service"])
}

func TestAuthMarshalJSONOpenIDOnlyEmptyHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		HTPasswd: &HTPasswd{},
		OpenID: &OpenIDConfig{
			Providers: map[string]OpenIDProviderConfig{
				"oidc": {Name: "Example"},
			},
		},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "htpasswd")

	openid, ok := decoded["openid"].(map[string]any)
	require.True(t, ok)
	providers, ok := openid["providers"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, providers, "oidc")
}

func TestHandleRunGCNoAuthzAccepted(t *testing.T) {
	// without accessControl configured, authzInfo is nil and every request is
	// admin under zot's default-permit semantics
	mgmt := &Mgmt{Conf: &config.Config{}, Log: log.NewLogger("debug", "")}

	req := httptest.NewRequest(http.MethodPost, "/v2/_zot/ext/mgmt/gc", nil)
	recorder := httptest.NewRecorder()

	mgmt.HandleRunGC(recorder, req)
	assert.Equal(t, http.StatusAccepted, recorder.Code)
}

func TestHandleRunGCAnonymousNotAdmin(t *testing.T) {
	t.Parallel()

	mgmt := &Mgmt{Conf: &config.Config{}, Log: log.NewLogger("debug", "")}

	req := httptest.NewRequest(http.MethodPost, "/v2/_zot/ext/mgmt/gc", nil)

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetIsAdmin(false)
	userAc.SaveOnRequest(req)

	recorder := httptest.NewRecorder()
	mgmt.HandleRunGC(recorder, req)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestHandleRunGCAdminAccepted(t *testing.T) {
	mgmt := &Mgmt{
		Conf:            &config.Config{},
		StoreController: storage.StoreController{},
		Log:             log.NewLogger("debug", ""),
	}

	req := httptest.NewRequest(http.MethodPost, "/v2/_zot/ext/mgmt/gc", nil)

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetIsAdmin(true)
	userAc.SaveOnRequest(req)

	recorder := httptest.NewRecorder()
	mgmt.HandleRunGC(recorder, req)
	assert.Equal(t, http.StatusAccepted, recorder.Code)
}
