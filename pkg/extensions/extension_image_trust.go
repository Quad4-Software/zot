//go:build imagetrust

package extensions

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	sconstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

func IsBuiltWithImageTrustExtension() bool {
	return true
}

func SetupImageTrustRoutes(conf *config.Config, router *mux.Router, metaDB mTypes.MetaDB, log log.Logger) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsImageTrustEnabled() ||
		(!extensionsConfig.IsCosignEnabled() && !extensionsConfig.IsNotationEnabled()) {
		log.Info().Msg("skip enabling the image trust routes as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up image trust routes")

	imgTrustStore, _ := metaDB.ImageTrustStore().(*imagetrust.ImageTrustStore)
	trust := ImageTrust{Conf: conf, ImageTrustStore: imgTrustStore, Log: log}
	allowedMethods := zcommon.AllowedMethods(http.MethodPost, http.MethodGet)

	if extensionsConfig.IsNotationEnabled() {
		log.Info().Msg("setting up notation route")

		notationRouter := router.PathPrefix(constants.ExtNotation).Subrouter()
		notationRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
		notationRouter.Use(zcommon.AddExtensionSecurityHeaders())
		notationRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
		// The endpoints for uploading signatures should be available only to admins
		notationRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
		notationRouter.Methods(http.MethodPost).HandlerFunc(trust.HandleNotationCertificateUpload)
		notationRouter.Methods(http.MethodGet).HandlerFunc(trust.HandleNotationCertificateList)
	}

	if extensionsConfig.IsCosignEnabled() {
		log.Info().Msg("setting up cosign route")

		cosignRouter := router.PathPrefix(constants.ExtCosign).Subrouter()
		cosignRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
		cosignRouter.Use(zcommon.AddExtensionSecurityHeaders())
		cosignRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
		// The endpoints for uploading signatures should be available only to admins
		cosignRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
		cosignRouter.Methods(http.MethodPost).HandlerFunc(trust.HandleCosignPublicKeyUpload)
		cosignRouter.Methods(http.MethodGet).HandlerFunc(trust.HandleCosignPublicKeyList)
	}

	log.Info().Msg("finished setting up image trust routes")
}

type ImageTrust struct {
	Conf            *config.Config
	ImageTrustStore *imagetrust.ImageTrustStore
	Log             log.Logger
}

// HandleCosignPublicKeyUpload godoc
// @Summary Upload cosign public keys for verifying signatures
// @Description Upload cosign public keys for verifying signatures
// @Router   /v2/_zot/ext/cosign [post]
// @Accept  octet-stream
// @Produce json
// @Param   requestBody     body     string   true   "Public key content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request"
// @Failure 413 {string}   string    "request entity too large"
// @Failure 500 {string}   string    "internal server error"
func (trust *ImageTrust) HandleCosignPublicKeyUpload(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, constants.MaxImageTrustBodySize))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			response.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to read cosign key body")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	err = imagetrust.UploadPublicKey(trust.ImageTrustStore.CosignStorage, body)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidPublicKeyContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to save cosign key")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

// HandleCosignPublicKeyList godoc
// @Summary List uploaded cosign public keys
// @Description Lists the digest names of uploaded cosign public keys. Admin users only.
// @Router   /v2/_zot/ext/cosign [get]
// @Produce json
// @Success 200 {object} map[string][]string
// @Failure 403 {string} string "forbidden"
// @Failure 500 {string} string "internal server error"
func (trust *ImageTrust) HandleCosignPublicKeyList(response http.ResponseWriter, request *http.Request) {
	if trust.ImageTrustStore == nil {
		response.WriteHeader(http.StatusNotImplemented)

		return
	}

	keys, err := trust.ImageTrustStore.CosignStorage.GetPublicKeys()
	if err != nil {
		trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to list cosign keys")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	writeJSON(response, map[string][]string{"keys": keys})
}

// HandleNotationCertificateList godoc
// @Summary List uploaded notation certificates
// @Description Lists stored notation certificates as truststore/x509 paths. Admin users only.
// @Router   /v2/_zot/ext/notation [get]
// @Produce json
// @Success 200 {object} map[string][]string
// @Failure 403 {string} string "forbidden"
// @Failure 500 {string} string "internal server error"
func (trust *ImageTrust) HandleNotationCertificateList(response http.ResponseWriter, request *http.Request) {
	if trust.ImageTrustStore == nil {
		response.WriteHeader(http.StatusNotImplemented)

		return
	}

	local, ok := trust.ImageTrustStore.NotationStorage.(*imagetrust.CertificateLocalStorage)
	if !ok {
		// cert material lives in a remote store (e.g. AWS secrets manager)
		// that has no listing API
		response.WriteHeader(http.StatusNotImplemented)

		return
	}

	certs, err := local.GetCertificateNames()
	if err != nil {
		trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to list notation certificates")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	writeJSON(response, map[string][]string{"certificates": certs})
}

func writeJSON(response http.ResponseWriter, value any) {
	buf, err := json.Marshal(value)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	response.Header().Set("Content-Type", "application/json")
	_, _ = response.Write(buf)
}

// HandleNotationCertificateUpload godoc
// @Summary Upload notation certificates for verifying signatures
// @Description Upload notation certificates for verifying signatures
// @Router  /v2/_zot/ext/notation [post]
// @Accept  octet-stream
// @Produce json
// @Param   truststoreType  query    string   false  "truststore type"
// @Param   requestBody     body     string   true   "Certificate content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request"
// @Failure 413 {string}   string    "request entity too large"
// @Failure 500 {string}   string    "internal server error"
func (trust *ImageTrust) HandleNotationCertificateUpload(response http.ResponseWriter, request *http.Request) {
	var truststoreType string

	if zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreType"}) {
		truststoreType = request.URL.Query().Get("truststoreType")
	} else {
		truststoreType = "ca" // default value of "truststoreType" query param
	}

	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, constants.MaxImageTrustBodySize))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			response.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to read notation certificate body")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	err = imagetrust.UploadCertificate(trust.ImageTrustStore.NotationStorage, body, truststoreType)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidTruststoreType) ||
			errors.Is(err, zerr.ErrInvalidCertificateContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			trust.Log.Error().Err(err).Str("component", "image-trust").Msg("failed to save notation certificate")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

func EnableImageTrustVerification(conf *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsImageTrustEnabled() {
		return
	}

	generator := imagetrust.NewTaskGenerator(metaDB, log)

	numberOfHours := 2
	interval := time.Duration(numberOfHours) * time.Hour
	taskScheduler.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func SetupImageTrustExtension(conf *config.Config, metaDB mTypes.MetaDB, log log.Logger) error {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsImageTrustEnabled() {
		return nil
	}

	var imgTrustStore mTypes.ImageTrustStore

	var err error

	if conf.Storage.RemoteCache && conf.Storage.CacheDriver["name"] == sconstants.DynamoDBDriverName {
		// AWS secrets manager
		// In case of AWS let's assume if dynamodDB is used, the AWS secrets manager is also used
		// we use the CacheDriver settings as opposed to the storage settings because we want to
		// be able to use S3/minio and redis in the same configuration
		endpoint, _ := conf.Storage.CacheDriver["endpoint"].(string)
		region, _ := conf.Storage.CacheDriver["region"].(string)

		imgTrustStore, err = imagetrust.NewAWSImageTrustStore(region, endpoint)
		if err != nil {
			return err
		}
	} else {
		// Store secrets on the local disk
		imgTrustStore, err = imagetrust.NewLocalImageTrustStore(conf.Storage.RootDirectory)
		if err != nil {
			return err
		}
	}

	metaDB.SetImageTrustStore(imgTrustStore)

	return nil
}
