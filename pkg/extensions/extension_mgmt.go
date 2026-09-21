//go:build mgmt

package extensions

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/storage"
	gc "zotregistry.dev/zot/v2/pkg/storage/gc"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type HTPasswd struct {
	Path string `json:"path,omitempty"`
}

type BearerConfig struct {
	Realm   string `json:"realm,omitempty"`
	Service string `json:"service,omitempty"`
}

type OpenIDProviderConfig struct {
	Name string `json:"name,omitempty" mapstructure:"name"`
}

type OpenIDConfig struct {
	Providers map[string]OpenIDProviderConfig `json:"providers,omitempty" mapstructure:"providers"`
}

type Auth struct {
	HTPasswd *HTPasswd     `json:"htpasswd,omitempty" mapstructure:"htpasswd"`
	Bearer   *BearerConfig `json:"bearer,omitempty"   mapstructure:"bearer"`
	LDAP     *struct {
		Address string `json:"address,omitempty" mapstructure:"address"`
	} `json:"ldap,omitempty"                 mapstructure:"ldap"`
	OpenID               *OpenIDConfig `json:"openid,omitempty"               mapstructure:"openid"`
	APIKey               bool          `json:"apikey,omitempty"               mapstructure:"apikey"`
	AllowAnonymousAccess bool          `json:"allowAnonymousAccess,omitempty" mapstructure:"allowAnonymousAccess"`
}

type RetentionPolicySummary struct {
	Repositories    []string `json:"repositories"`
	DeleteReferrers bool     `json:"deleteReferrers"`
	DeleteUntagged  bool     `json:"deleteUntagged"`
	KeepTags        int      `json:"keepTags"`
}

// StorageSummary exposes the GC and retention-related parts of the storage
// config. It is populated manually in HandleGetConfig; UnmarshalJSON is a
// no-op so MarshalThroughStruct ignores the source storage block.
type StorageSummary struct {
	GC         bool                     `json:"gc"`
	GCInterval string                   `json:"gcInterval,omitempty"`
	Dedupe     bool                     `json:"dedupe"`
	Retention  []RetentionPolicySummary `json:"retention,omitempty"`
}

func (s *StorageSummary) UnmarshalJSON([]byte) error {
	return nil
}

type StrippedConfig struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	Commit          string `json:"commit"          mapstructure:"commit"`
	ReleaseTag      string `json:"releaseTag"      mapstructure:"releaseTag"`
	BinaryType      string `json:"binaryType"      mapstructure:"binaryType"`

	HTTP struct {
		Auth *Auth `json:"auth,omitempty" mapstructure:"auth"`
	} `json:"http" mapstructure:"http"`

	Storage StorageSummary `json:"storage"`
}

func IsBuiltWithMGMTExtension() bool {
	return true
}

func (auth Auth) MarshalJSON() ([]byte, error) {
	type localAuth Auth

	if auth.Bearer == nil && auth.LDAP == nil &&
		(auth.HTPasswd == nil || auth.HTPasswd.Path == "") &&
		(auth.OpenID == nil || len(auth.OpenID.Providers) == 0) {
		auth.HTPasswd = nil
		auth.OpenID = nil

		return json.Marshal(localAuth(auth))
	}

	// HTPasswd is a value on AuthConfig, so MarshalThroughStruct always yields a
	// non-nil pointer. Only advertise basic auth when LDAP is set or a path exists.
	if auth.LDAP != nil || (auth.HTPasswd != nil && auth.HTPasswd.Path != "") {
		auth.HTPasswd = &HTPasswd{}
	} else {
		auth.HTPasswd = nil
	}

	if auth.OpenID != nil && len(auth.OpenID.Providers) == 0 {
		auth.OpenID = nil
	}

	auth.LDAP = nil

	return json.Marshal(localAuth(auth))
}

func SetupMgmtRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, audit *log.Logger, metrics monitoring.MetricServer, log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsSearchEnabled() {
		log.Info().Msg("skip enabling the mgmt route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up mgmt routes")

	mgmt := &Mgmt{
		Conf:            conf,
		StoreController: storeController,
		MetaDB:          metaDB,
		Audit:           audit,
		Metrics:         metrics,
		Log:             log,
	}

	// The on-demand GC route is registered before the prefix subrouter so its
	// method set is not constrained to the GET-only mgmt route.
	gcRouter := router.PathPrefix(constants.ExtMgmt + "/gc").Subrouter()
	gcRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	gcRouter.Use(zcommon.AddExtensionSecurityHeaders())
	gcRouter.Use(zcommon.ACHeadersMiddleware(conf, http.MethodPost))
	gcRouter.Methods(http.MethodPost).HandlerFunc(mgmt.HandleRunGC)

	// The endpoint for reading configuration should be available to all users
	allowedMethods := zcommon.AllowedMethods(http.MethodGet)

	mgmtRouter := router.PathPrefix(constants.ExtMgmt).Subrouter()
	mgmtRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	mgmtRouter.Use(zcommon.AddExtensionSecurityHeaders())
	mgmtRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	mgmtRouter.Methods(allowedMethods...).HandlerFunc(mgmt.HandleGetConfig)

	log.Info().Msg("finished setting up mgmt routes")
}

type Mgmt struct {
	Conf            *config.Config
	StoreController storage.StoreController
	MetaDB          mTypes.MetaDB
	Audit           *log.Logger
	Metrics         monitoring.MetricServer
	Log             log.Logger
	gcRunning       atomic.Bool
}

// HandleGetConfig godoc
// @Summary Get current server configuration
// @Description Get current server configuration
// @Router  /v2/_zot/ext/mgmt [get]
// @Accept  json
// @Produce json
// @Param   resource       query     string   false   "specify resource" Enums(config)
// @Success 200 {object}   extensions.StrippedConfig
// @Failure 500 {string}   string   "internal server error"
func (mgmt *Mgmt) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	var stripped StrippedConfig

	sanitizedConfig := mgmt.Conf.Sanitize()

	if _, err := zcommon.MarshalThroughStruct(sanitizedConfig, &stripped); err != nil {
		mgmt.Log.Error().Err(err).Str("component", "mgmt").Msg("failed to marshal config response")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if stripped.HTTP.Auth != nil &&
		sanitizedConfig.HTTP.AccessControl != nil &&
		sanitizedConfig.HTTP.AccessControl.AnonymousPolicyExists() {
		stripped.HTTP.Auth.AllowAnonymousAccess = true
	}

	storageConfig := sanitizedConfig.CopyStorageConfig()
	stripped.Storage.GC = storageConfig.GC
	stripped.Storage.Dedupe = storageConfig.Dedupe

	if storageConfig.GCInterval > 0 {
		stripped.Storage.GCInterval = storageConfig.GCInterval.String()
	}

	for _, policy := range storageConfig.Retention.Policies {
		stripped.Storage.Retention = append(stripped.Storage.Retention, RetentionPolicySummary{
			Repositories:    policy.Repositories,
			DeleteReferrers: policy.DeleteReferrers,
			DeleteUntagged:  policy.DeleteUntagged == nil || *policy.DeleteUntagged,
			KeepTags:        len(policy.KeepTags),
		})
	}

	buf, err := json.Marshal(stripped)
	if err != nil {
		mgmt.Log.Error().Err(err).Str("component", "mgmt").Msg("failed to marshal config response")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	_, _ = w.Write(buf)
}

// HandleRunGC godoc
// @Summary Trigger garbage collection
// @Description Runs garbage collection across all storage roots, using the
// configured retention policies. Admin users only; runs asynchronously.
// @Router  /v2/_zot/ext/mgmt/gc [post]
// @Success 202 {string} string "accepted"
// @Failure 403 {string} string "forbidden"
// @Failure 409 {string} string "a gc run is already in progress"
func (mgmt *Mgmt) HandleRunGC(w http.ResponseWriter, r *http.Request) {
	userAc, err := reqCtx.UserAcFromContext(r.Context())
	if err != nil || userAc == nil || !userAc.IsAdmin() {
		w.WriteHeader(http.StatusForbidden)

		return
	}

	if !mgmt.gcRunning.CompareAndSwap(false, true) {
		w.WriteHeader(http.StatusConflict)

		return
	}

	go func() {
		defer mgmt.gcRunning.Store(false)
		mgmt.runGC(context.WithoutCancel(r.Context()))
	}()

	w.WriteHeader(http.StatusAccepted)
}

func (mgmt *Mgmt) runGC(ctx context.Context) {
	storageConfig := mgmt.Conf.CopyStorageConfig()

	if storageConfig.GC {
		mgmt.gcStore(ctx, mgmt.StoreController.DefaultStore, storageConfig.StorageConfig)
	}

	for route, subStorageConfig := range storageConfig.SubPaths {
		if !subStorageConfig.GC {
			continue
		}

		imgStore, ok := mgmt.StoreController.SubStore[route]
		if !ok {
			continue
		}

		mgmt.gcStore(ctx, imgStore, subStorageConfig)
	}
}

func (mgmt *Mgmt) gcStore(ctx context.Context, imgStore storageTypes.ImageStore,
	storageConfig config.StorageConfig,
) {
	collector := gc.NewGarbageCollect(imgStore, mgmt.MetaDB, gc.Options{
		Delay:             storageConfig.GCDelay,
		MaxSchedulerDelay: storageConfig.GCMaxSchedulerDelay,
		TimeWindow:        storageConfig.GCTimeWindow,
		ImageRetention:    storageConfig.Retention,
		StagingRoot:       mgmt.StoreController.SyncStagingRootForImageStore(imgStore),
	}, mgmt.Audit, mgmt.Log, mgmt.Metrics)

	repos, err := imgStore.GetRepositories()
	if err != nil {
		mgmt.Log.Error().Err(err).Str("component", "mgmt").Msg("failed to list repositories for gc")

		return
	}

	for _, repo := range repos {
		if err := collector.CleanRepo(ctx, repo); err != nil {
			mgmt.Log.Error().Err(err).Str("component", "mgmt").Str("repo", repo).
				Msg("gc failed for repository")
		}
	}
}
