//go:build search

package grype

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestScannerConfig(t *testing.T) {
	Convey("NewScanner derives store roots and defaults", t, func() {
		tempDir := t.TempDir()

		imageStore := local.NewImageStore(tempDir, false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		scanner := NewScanner(storeController, nil, &extconf.CVEConfig{
			Grype: &extconf.GrypeConfig{},
		}, log.NewTestLogger())

		So(scanner.roots, ShouldResemble, []string{tempDir})
		So(scanner.installCfg(tempDir).DBRootDir,
			ShouldEqual, filepath.Join(tempDir, dbDirName, "db"))
		So(scanner.distCfg.LatestURL, ShouldContainSubstring, "anchore.io")
	})

	Convey("DBListingURL override", t, func() {
		tempDir := t.TempDir()

		imageStore := local.NewImageStore(tempDir, false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		scanner := NewScanner(storage.StoreController{DefaultStore: imageStore}, nil,
			&extconf.CVEConfig{Grype: &extconf.GrypeConfig{DBListingURL: "https://example.invalid/db"}},
			log.NewTestLogger())

		So(scanner.distCfg.LatestURL, ShouldEqual, "https://example.invalid/db")
	})
}

func TestScanManifestWithoutDB(t *testing.T) {
	Convey("scan fails cleanly when the grype DB is absent", t, func() {
		tempDir := t.TempDir()

		imageStore := local.NewImageStore(tempDir, false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		img := CreateImageWith().DefaultLayers().DefaultConfig().Build()
		err := WriteImageToFileSystem(img, "repo", img.DigestStr(), storeController)
		So(err, ShouldBeNil)

		boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: tempDir})
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log.NewTestLogger())
		So(err, ShouldBeNil)
		So(meta.ParseStorage(metaDB, storeController, log.NewTestLogger()), ShouldBeNil)

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Grype: &extconf.GrypeConfig{},
		}, log.NewTestLogger())

		// short timeout so the unreachable listing endpoint fails fast
		scanner.distCfg.CheckTimeout = 1_000_000_000

		_, err = scanner.ScanImage(context.Background(), "repo@"+img.DigestStr())
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "grype")
	})
}

func TestBuildLayout(t *testing.T) {
	Convey("buildLayout produces a valid single-image OCI layout", t, func() {
		tempDir := t.TempDir()

		imageStore := local.NewImageStore(tempDir, false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		img := CreateImageWith().DefaultLayers().DefaultConfig().Build()
		So(WriteImageToFileSystem(img, "repo", img.DigestStr(), storeController), ShouldBeNil)

		scanner := NewScanner(storeController, nil, &extconf.CVEConfig{
			Grype: &extconf.GrypeConfig{},
		}, log.NewTestLogger())

		layoutDir, err := scanner.buildLayout(imageStore, "repo", img.DigestStr())
		So(err, ShouldBeNil)
		defer os.RemoveAll(layoutDir)

		// oci-layout marker
		_, err = os.Stat(filepath.Join(layoutDir, "oci-layout"))
		So(err, ShouldBeNil)

		// index.json references exactly the manifest digest
		indexBlob, err := os.ReadFile(filepath.Join(layoutDir, "index.json"))
		So(err, ShouldBeNil)

		var index ispec.Index
		So(json.Unmarshal(indexBlob, &index), ShouldBeNil)
		So(index.Manifests, ShouldHaveLength, 1)
		So(index.Manifests[0].Digest.String(), ShouldEqual, img.DigestStr())

		// manifest blob present (hardlinked or copied)
		manifestPath := filepath.Join(layoutDir, ispec.ImageBlobsDir, "sha256",
			godigest.Digest(img.DigestStr()).Encoded())
		info, err := os.Stat(manifestPath)
		So(err, ShouldBeNil)
		So(info.Size(), ShouldBeGreaterThan, 0)
	})
}

func TestConvertSeverity(t *testing.T) {
	Convey("grype severities map to zot severities", t, func() {
		So(convertSeverity("Critical"), ShouldEqual, cvemodel.SeverityCritical)
		So(convertSeverity("high"), ShouldEqual, cvemodel.SeverityHigh)
		So(convertSeverity("Medium"), ShouldEqual, cvemodel.SeverityMedium)
		So(convertSeverity("Low"), ShouldEqual, cvemodel.SeverityLow)
		So(convertSeverity("Negligible"), ShouldEqual, cvemodel.SeverityLow)
		So(convertSeverity("bogus"), ShouldEqual, cvemodel.SeverityUnknown)
	})
}

func TestGrypeCVEReference(t *testing.T) {
	Convey("reference prefers cve.org for CVE ids", t, func() {
		So(grypeCVEReference("CVE-2024-1", "", nil),
			ShouldEqual, "https://www.cve.org/CVERecord?id=CVE-2024-1")
		So(grypeCVEReference("GHSA-xxxx", "https://github.com/advisories/GHSA-xxxx", nil),
			ShouldEqual, "https://github.com/advisories/GHSA-xxxx")
		So(grypeCVEReference("GHSA-xxxx", "", []string{"https://x"}), ShouldEqual, "https://x")
		So(grypeCVEReference("GHSA-xxxx", "", nil), ShouldEqual, "")
	})
}
