// Package grype implements a CVE scanner backend using Anchore grype as a
// library. The vulnerability DB is downloaded through grype's distribution
// client into <storage-root>/_grype and images are scanned by assembling a
// single-manifest OCI layout (hardlinked blobs) that syft catalogs.
package grype

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/anchore/clio"
	anchoregrype "github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	gdistro "github.com/anchore/grype/grype/distro"
	gmatch "github.com/anchore/grype/grype/match"
	gmatcher "github.com/anchore/grype/grype/matcher"
	gpkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	godigest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	cvebase "zotregistry.dev/zot/v2/pkg/extensions/search/cve/base"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	scannerName = "grype"
	dbDirName   = "_grype"
)

var errImageStoreNotFound = errors.New("image store not found")

type Scanner struct {
	base            *cvebase.Scanner
	metaDB          mTypes.MetaDB
	storeController storage.StoreController
	log             log.Logger

	// dbLock serializes scans and DB updates against the provider table so a
	// provider is never closed while a scan is using it.
	dbLock    *sync.Mutex
	providers map[string]vulnerability.Provider
	statuses  map[string]*vulnerability.ProviderStatus
	distCfg   v6dist.Config
	roots     []string
}

func NewScanner(storeController storage.StoreController, metaDB mTypes.MetaDB,
	cveConfig *extconf.CVEConfig, log log.Logger,
) *Scanner {
	var grypeCfg *extconf.GrypeConfig
	if cveConfig != nil {
		grypeCfg = cveConfig.Grype
	}

	if grypeCfg == nil {
		grypeCfg = &extconf.GrypeConfig{}
	}

	distCfg := v6dist.DefaultConfig()
	if grypeCfg.DBListingURL != "" {
		distCfg.LatestURL = grypeCfg.DBListingURL
	}

	// surface update errors to the scheduler instead of masking them behind a
	// stale or missing database status
	distCfg.RequireUpdateCheck = true

	scanner := &Scanner{
		metaDB:          metaDB,
		storeController: storeController,
		log:             log,
		dbLock:          &sync.Mutex{},
		providers:       map[string]vulnerability.Provider{},
		statuses:        map[string]*vulnerability.ProviderStatus{},
		distCfg:         distCfg,
		roots:           storeRoots(storeController),
	}

	scanner.base = cvebase.NewScanner(storeController, metaDB, scannerName,
		scanner.scanManifest, nil, log)

	return scanner
}

func storeRoots(storeController storage.StoreController) []string {
	roots := []string{}

	if storeController.DefaultStore != nil {
		roots = append(roots, storeController.DefaultStore.RootDir())
	}

	for _, storage := range storeController.SubStore {
		roots = append(roots, storage.RootDir())
	}

	slices.Sort(roots)

	return slices.Compact(roots)
}

func (scanner *Scanner) Name() string {
	return scannerName
}

func (scanner *Scanner) installCfg(rootDir string) v6inst.Config {
	cfg := v6inst.DefaultConfig(clio.Identification{Name: "zot"})
	cfg.DBRootDir = filepath.Join(rootDir, dbDirName, "db")
	// the DB is refreshed by the scheduled UpdateDB task, so age validation
	// must not reject a database that is merely past its built age window
	cfg.ValidateAge = false
	cfg.ValidateChecksum = true

	return cfg
}

// getProvider returns the loaded vulnerability provider for the store root
// owning a repository, loading it without an update if needed.
func (scanner *Scanner) getProvider(rootDir string) (vulnerability.Provider, error) {
	if provider, ok := scanner.providers[rootDir]; ok {
		return provider, nil
	}

	provider, status, err := anchoregrype.LoadVulnerabilityDB(scanner.distCfg, scanner.installCfg(rootDir), false)
	if err != nil {
		return nil, err
	}

	scanner.providers[rootDir] = provider
	scanner.statuses[rootDir] = status

	return provider, nil
}

// DBStatus reports the grype DB freshness for the management endpoint. The
// DB is per storage root; the reported values are the conservative merge of
// all loaded providers (oldest build time, joined errors).
func (scanner *Scanner) DBStatus() cvemodel.ScannerDBStatus {
	scanner.dbLock.Lock()
	defer scanner.dbLock.Unlock()

	status := cvemodel.ScannerDBStatus{}

	var errs []error

	for _, providerStatus := range scanner.statuses {
		if providerStatus == nil {
			continue
		}

		if providerStatus.Error != nil {
			errs = append(errs, providerStatus.Error)

			continue
		}

		if status.DBVersion == "" && providerStatus.SchemaVersion != "" {
			status.DBVersion = providerStatus.SchemaVersion
		}

		if !providerStatus.Built.IsZero() && (status.DBUpdatedAt == nil || providerStatus.Built.Before(*status.DBUpdatedAt)) {
			built := providerStatus.Built
			status.DBUpdatedAt = &built
		}
	}

	if len(errs) > 0 {
		status.Error = errors.Join(errs...).Error()
	}

	return status
}

// UpdateDB downloads the grype vulnerability DB under each store root and
// swaps the loaded providers. It implements cveinfo.Scanner.
func (scanner *Scanner) UpdateDB(ctx context.Context) error {
	scanner.dbLock.Lock()
	defer scanner.dbLock.Unlock()

	for _, rootDir := range scanner.roots {
		scanner.log.Debug().Str("dbDir", rootDir).Msg("updating grype vulnerability DB")

		provider, status, err := anchoregrype.LoadVulnerabilityDB(scanner.distCfg, scanner.installCfg(rootDir), true)
		if err != nil {
			scanner.log.Error().Err(err).Str("dbDir", rootDir).
				Msg("failed to download grype vulnerability DB")

			return err
		}

		if old, ok := scanner.providers[rootDir]; ok {
			_ = old.Close()
		}

		scanner.providers[rootDir] = provider
		scanner.statuses[rootDir] = status
	}

	scanner.base.PurgeCache()

	return nil
}

func (scanner *Scanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	return scanner.base.ScanImage(ctx, image)
}

func (scanner *Scanner) IsImageFormatScannable(repo, ref string) (bool, error) {
	return scanner.base.IsImageFormatScannable(repo, ref)
}

func (scanner *Scanner) IsImageMediaScannable(repo, digestStr, mediaType string) (bool, error) {
	return scanner.base.IsImageMediaScannable(repo, digestStr, mediaType)
}

func (scanner *Scanner) IsResultCached(repo, digest string) bool {
	return scanner.base.IsResultCached(repo, digest)
}

func (scanner *Scanner) GetCachedResult(repo, digest string) map[string]zcommon.CVE {
	return scanner.base.GetCachedResult(repo, digest)
}

// scanManifest catalogs a single image manifest through syft and matches it
// against the grype vulnerability DB. Called through the base scanner, which
// owns caching, deduplication and index aggregation.
func (scanner *Scanner) scanManifest(ctx context.Context, repo, digest string) (map[string]zcommon.CVE, error) {
	imgStore := scanner.storeController.GetImageStore(repo)
	if imgStore == nil {
		return nil, fmt.Errorf("%w for repo %q", errImageStoreNotFound, repo)
	}

	scanner.dbLock.Lock()
	defer scanner.dbLock.Unlock()

	provider, err := scanner.getProvider(imgStore.RootDir())
	if err != nil {
		return nil, fmt.Errorf("grype vulnerability DB unavailable: %w", err)
	}

	layoutDir, err := scanner.buildLayout(imgStore, repo, digest)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(layoutDir)

	src, err := syft.GetSource(ctx, layoutDir, syft.DefaultGetSourceConfig().WithSources("oci-dir"))
	if err != nil {
		return nil, fmt.Errorf("failed to create image source: %w", err)
	}

	sbomObj, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to catalog image: %w", err)
	}

	srcDesc := src.Describe()
	pkgPtrs := gpkg.FromCollection(sbomObj.Artifacts.Packages, sbomObj.Relationships, gpkg.SynthesisConfig{})

	pkgs := make([]gpkg.Package, 0, len(pkgPtrs))
	for _, p := range pkgPtrs {
		pkgs = append(pkgs, *p)
	}

	vulnMatcher := &anchoregrype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              gmatcher.NewDefaultMatchers(gmatcher.Config{}),
		NormalizeByCVE:        true,
	}

	matches, _, err := vulnMatcher.FindMatchesContext(ctx, pkgs, gpkg.Context{
		Source: &srcDesc,
		Distro: gdistro.FromRelease(sbomObj.Artifacts.LinuxDistribution, nil),
	})
	if err != nil {
		return nil, err
	}

	cveidMap := map[string]zcommon.CVE{}

	for m := range matches.Enumerate() {
		addMatch(cveidMap, m)
	}

	return cveidMap, nil
}

// buildLayout assembles a single-image OCI layout directory inside the store
// root so blob hardlinks stay on one filesystem. The layout contains only the
// requested manifest plus its config and layer blobs.
func (scanner *Scanner) buildLayout(imgStore storageTypes.ImageStore, repo, digest string) (string, error) {
	manifestBlob, _, manifestMediaType, err := imgStore.GetImageManifest(repo, digest)
	if err != nil {
		return "", err
	}

	var manifest ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifest); err != nil {
		return "", fmt.Errorf("failed to parse manifest %s: %w", digest, err)
	}

	tmpRoot := filepath.Join(imgStore.RootDir(), dbDirName, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o755); err != nil {
		return "", err
	}

	layoutDir, err := os.MkdirTemp(tmpRoot, "scan-")
	if err != nil {
		return "", err
	}

	cleanupOnErr := func() { _ = os.RemoveAll(layoutDir) }

	if err := os.MkdirAll(filepath.Join(layoutDir, ispec.ImageBlobsDir, "sha256"), 0o755); err != nil {
		cleanupOnErr()

		return "", err
	}

	manifestDigest := godigest.Digest(digest)

	toLink := append([]godigest.Digest{manifestDigest, manifest.Config.Digest},
		layerDigests(manifest.Layers)...)

	for _, blobDigest := range toLink {
		if err := linkBlob(imgStore.BlobPath(repo, blobDigest), layoutDir, blobDigest); err != nil {
			cleanupOnErr()

			return "", err
		}
	}

	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{{
			MediaType: manifestMediaType,
			Digest:    manifestDigest,
			Size:      int64(len(manifestBlob)),
		}},
	}

	indexBlob, err := json.Marshal(index)
	if err != nil {
		cleanupOnErr()

		return "", err
	}

	if err := os.WriteFile(filepath.Join(layoutDir, "index.json"), indexBlob, 0o644); err != nil {
		cleanupOnErr()

		return "", err
	}

	if err := os.WriteFile(filepath.Join(layoutDir, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		cleanupOnErr()

		return "", err
	}

	return layoutDir, nil
}

func layerDigests(layers []ispec.Descriptor) []godigest.Digest {
	digests := make([]godigest.Digest, 0, len(layers))
	for _, layer := range layers {
		digests = append(digests, layer.Digest)
	}

	return digests
}

// linkBlob hardlinks a store blob into the layout dir, falling back to a copy
// if the filesystem does not support hardlinks.
func linkBlob(srcPath, layoutDir string, digest godigest.Digest) error {
	dstPath := filepath.Join(layoutDir, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

	if err := os.Link(srcPath, dstPath); err == nil {
		return nil
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()

	if copyErr != nil {
		return copyErr
	}

	return closeErr
}

func addMatch(cveidMap map[string]zcommon.CVE, m gmatch.Match) {
	id := m.Vulnerability.ID

	fixedVersion := cvemodel.NotSpecified
	if len(m.Vulnerability.Fix.Versions) > 0 {
		fixedVersion = strings.Join(m.Vulnerability.Fix.Versions, ", ")
	}

	packagePath := cvemodel.NotSpecified
	if locations := m.Package.Locations.ToSlice(); len(locations) > 0 && locations[0].RealPath != "" {
		packagePath = locations[0].RealPath
	}

	pack := zcommon.Package{
		Name:             m.Package.Name,
		PackagePath:      packagePath,
		InstalledVersion: m.Package.Version,
		FixedVersion:     fixedVersion,
	}

	if existing, ok := cveidMap[id]; ok {
		existing.PackageList = append(existing.PackageList, pack)
		cveidMap[id] = existing

		return
	}

	var (
		description string
		reference   string
		severity    string
	)

	if meta := m.Vulnerability.Metadata; meta != nil {
		description = meta.Description
		severity = convertSeverity(meta.Severity)
		reference = grypeCVEReference(id, meta.DataSource, meta.URLs)
	} else {
		severity = cvemodel.SeverityUnknown
	}

	cveidMap[id] = zcommon.CVE{
		ID:          id,
		Description: description,
		Reference:   reference,
		Severity:    severity,
		PackageList: []zcommon.Package{pack},
	}
}

func convertSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case cvemodel.SeverityCritical:
		return cvemodel.SeverityCritical
	case cvemodel.SeverityHigh:
		return cvemodel.SeverityHigh
	case cvemodel.SeverityMedium:
		return cvemodel.SeverityMedium
	case cvemodel.SeverityLow, "NEGLIGIBLE":
		return cvemodel.SeverityLow
	default:
		return cvemodel.SeverityUnknown
	}
}

func grypeCVEReference(id, dataSource string, urls []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return "https://www.cve.org/CVERecord?id=" + id
	}

	if dataSource != "" {
		return dataSource
	}

	if len(urls) > 0 {
		return urls[0]
	}

	return ""
}
