//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/klauspost/compress/zstd"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// TestZstdCompressedLayers verifies that the registry accepts and serves images
// whose layers carry the application/vnd.oci.image.layer.v1.tar+zstd media type,
// matching what registries like GHCR accept from zstd-compressing clients.
func TestZstdCompressedLayers(t *testing.T) {
	Convey("Push and pull an image with zstd-compressed layers", t, func() {
		conf := config.New()
		conf.HTTP.Port = "0"

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()

		defer cm.StopServer()

		repoName, seed := test.GenerateRandomName()
		ctlr.Log.Info().Int64("seed", seed).Msg("random seed for repoName")

		img := CreateImageWith().ZstdLayers(2, 256).DefaultConfig().Build()

		// manifests carrying zstd layers must be accepted
		err := UploadImage(img, baseURL, repoName, "zstd")
		So(err, ShouldBeNil)

		// the registry must advertise the repo and tag
		resp, err := resty.R().Get(baseURL + "/v2/" + repoName + "/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(string(resp.Body()), ShouldContainSubstring, "zstd")

		// manifest GET returns the stored manifest with zstd layer media types intact
		resp, err = resty.R().
			SetHeader("Accept", ispec.MediaTypeImageManifest).
			Get(baseURL + "/v2/" + repoName + "/manifests/zstd")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var manifest ispec.Manifest
		So(json.Unmarshal(resp.Body(), &manifest), ShouldBeNil)
		So(len(manifest.Layers), ShouldEqual, len(img.Layers))

		for i, layer := range manifest.Layers {
			So(layer.MediaType, ShouldEqual, ispec.MediaTypeImageLayerZstd)
			So(layer.Digest, ShouldEqual, godigest.FromBytes(img.Layers[i]))
			So(layer.Size, ShouldEqual, len(img.Layers[i]))

			// HEAD blob
			resp, err := resty.R().Head(baseURL + "/v2/" + repoName + "/blobs/" + layer.Digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, layer.Digest.String())

			// GET blob returns the identical zstd bytes that were pushed
			resp, err = resty.R().Get(baseURL + "/v2/" + repoName + "/blobs/" + layer.Digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldResemble, img.Layers[i])
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldEqual, layer.Digest.String())

			// the served blob must still decode as a valid zstd stream
			decoder, err := zstd.NewReader(bytes.NewReader(resp.Body()))
			So(err, ShouldBeNil)

			decoded, err := io.ReadAll(decoder)
			So(err, ShouldBeNil)
			So(len(decoded), ShouldBeGreaterThan, 0)
			decoder.Close()

			// range requests work on zstd blobs too
			resp, err = resty.R().
				SetHeader("Range", "bytes=0-3").
				Get(baseURL + "/v2/" + repoName + "/blobs/" + layer.Digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Body(), ShouldResemble, img.Layers[i][:4])
		}
	})
}

// TestNonDistributableZstdLayer verifies that a manifest referencing a
// non-distributable zstd layer is accepted without the blob being present,
// mirroring the handling of foreign layers in other registries.
func TestNonDistributableZstdLayer(t *testing.T) {
	Convey("Push a manifest with a non-distributable zstd layer", t, func() {
		conf := config.New()
		conf.HTTP.Port = "0"

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()

		defer cm.StopServer()

		repoName, seed := test.GenerateRandomName()
		ctlr.Log.Info().Int64("seed", seed).Msg("random seed for repoName")

		zstdBlob, err := GetZstdLayerBlob(128)
		So(err, ShouldBeNil)

		img := CreateImageWith().
			Layers([]Layer{
				{
					Blob:      zstdBlob,
					MediaType: ispec.MediaTypeImageLayerNonDistributableZstd, //nolint:staticcheck
					Digest:    godigest.FromBytes(zstdBlob),
				},
			}).
			DefaultConfig().
			Build()

		// upload only the config blob; the non-distributable layer blob is
		// intentionally never pushed
		resp, err := resty.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		loc := test.Location(baseURL, resp)
		cblob := img.ConfigDescriptor.Data

		resp, err = resty.R().
			SetHeader("Content-Type", constants.BinaryMediaType).
			SetQueryParam("digest", godigest.FromBytes(cblob).String()).
			SetBody(cblob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		resp, err = resty.R().
			SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			SetBody(img.ManifestDescriptor.Data).
			Put(baseURL + "/v2/" + repoName + "/manifests/zstd-foreign")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// the manifest is served back with the non-distributable media type intact
		resp, err = resty.R().Get(baseURL + "/v2/" + repoName + "/manifests/zstd-foreign")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var manifest ispec.Manifest
		So(json.Unmarshal(resp.Body(), &manifest), ShouldBeNil)
		So(len(manifest.Layers), ShouldEqual, 1)
		So(manifest.Layers[0].MediaType, ShouldEqual, ispec.MediaTypeImageLayerNonDistributableZstd) //nolint:staticcheck

		// the missing blob is reported as not found
		resp, err = resty.R().Head(baseURL + "/v2/" + repoName + "/blobs/" + img.Manifest.Layers[0].Digest.String())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}
