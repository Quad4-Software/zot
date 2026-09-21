// Package base provides the scanner-independent machinery shared by CVE
// scanner backends: result caching, scan deduplication, index aggregation and
// image scannability checks. A backend supplies a ManifestScanFunc that scans
// one image manifest and this package handles the rest of the Scanner
// interface.
package base

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/singleflight"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	cvecache "zotregistry.dev/zot/v2/pkg/extensions/search/cve/cache"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
)

const cacheSize = 1000000

// ManifestScanFunc scans a single image manifest (never an index) and returns
// the detected CVEs keyed by vulnerability ID. Implementations must not
// consult the cache; caching and deduplication are handled by Scanner.
type ManifestScanFunc func(ctx context.Context, repo, digest string) (map[string]zcommon.CVE, error)

// LayersScannableFunc reports whether a manifest's layer media types are
// supported by the backend. Nil means DefaultLayersScannable.
type LayersScannableFunc func(layers []ispec.Descriptor) (bool, error)

type Scanner struct {
	name            string
	metaDB          mTypes.MetaDB
	storeController storage.StoreController
	log             log.Logger
	cache           *cvecache.CveCache
	scanManifestFn  ManifestScanFunc
	layersScannable LayersScannableFunc

	// deduplicates concurrent scans of the same manifest/index
	scanSingleFlightGroup *singleflight.Group
}

func NewScanner(storeController storage.StoreController, metaDB mTypes.MetaDB,
	name string, scanFn ManifestScanFunc, layersFn LayersScannableFunc, log log.Logger,
) *Scanner {
	if layersFn == nil {
		layersFn = DefaultLayersScannable
	}

	return &Scanner{
		name:                  name,
		metaDB:                metaDB,
		storeController:       storeController,
		log:                   log,
		cache:                 cvecache.NewCveCache(cacheSize, log),
		scanManifestFn:        scanFn,
		layersScannable:       layersFn,
		scanSingleFlightGroup: &singleflight.Group{},
	}
}

// Name returns the backend identifier ("trivy", "grype", ...) used for
// per-scanner reporting.
func (scanner *Scanner) Name() string {
	return scanner.name
}

// PurgeCache drops all cached results, e.g. after a vulnerability DB update.
func (scanner *Scanner) PurgeCache() {
	scanner.cache.Purge()
}

// DefaultLayersScannable accepts the OCI and docker layer media types common
// image scanners support.
func DefaultLayersScannable(layers []ispec.Descriptor) (bool, error) {
	for _, imageLayer := range layers {
		switch imageLayer.MediaType {
		case ispec.MediaTypeImageLayerGzip,
			ispec.MediaTypeImageLayerZstd,
			ispec.MediaTypeImageLayer,
			"application/vnd.docker.image.rootfs.diff.tar.gzip":
			continue
		default:
			return false, fmt.Errorf("%w: layer media type '%s'",
				zerr.ErrScanNotSupported, imageLayer.MediaType)
		}
	}

	return true, nil
}

func (scanner *Scanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	var (
		digest    string
		mediaType string
	)

	repo, ref, isTag := zcommon.GetImageDirAndReference(image)

	digest = ref

	if isTag {
		imgDescriptor, err := getImageDescriptor(ctx, scanner.metaDB, repo, ref)
		if err != nil {
			return cvemodel.ScanResult{}, err
		}

		digest = imgDescriptor.Digest
		mediaType = imgDescriptor.MediaType
	} else {
		var found bool

		found, mediaType = findMediaTypeForDigest(scanner.metaDB, godigest.Digest(ref))
		if !found {
			return cvemodel.ScanResult{}, zerr.ErrManifestNotFound
		}
	}

	var (
		cveIDMap  map[string]zcommon.CVE
		wasCached bool
		err       error
	)

	if compat.IsImageIndexMediaType(mediaType) {
		cveIDMap, wasCached, err = scanner.scanIndex(ctx, repo, digest)
	} else if compat.IsImageManifestMediaType(mediaType) {
		cveIDMap, wasCached, err = scanner.scanManifest(ctx, repo, digest)
	}

	if err != nil {
		scanner.log.Error().Err(err).Str("image", image).Str("scanner", scanner.name).
			Msg("failed to scan image")

		return cvemodel.ScanResult{}, err
	}

	return cvemodel.ScanResult{
		CVEMap:    cveIDMap,
		Digest:    digest,
		MediaType: mediaType,
		WasCached: wasCached,
	}, nil
}

func (scanner *Scanner) IsImageFormatScannable(repo, ref string) (bool, error) {
	var (
		digestStr = ref
		mediaType string
	)

	if zcommon.IsTag(ref) {
		imgDescriptor, err := getImageDescriptor(context.Background(), scanner.metaDB, repo, ref)
		if err != nil {
			return false, err
		}

		digestStr = imgDescriptor.Digest
		mediaType = imgDescriptor.MediaType
	} else {
		var found bool

		found, mediaType = findMediaTypeForDigest(scanner.metaDB, godigest.Digest(ref))
		if !found {
			return false, zerr.ErrManifestNotFound
		}
	}

	return scanner.IsImageMediaScannable(repo, digestStr, mediaType)
}

func (scanner *Scanner) IsImageMediaScannable(repo, digestStr, mediaType string) (bool, error) {
	image := repo + "@" + digestStr

	if compat.IsImageManifestMediaType(mediaType) {
		ok, err := scanner.isManifestScannable(digestStr)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	} else if compat.IsImageIndexMediaType(mediaType) {
		ok, err := scanner.isIndexScannable(digestStr)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	}

	return false, nil
}

func (scanner *Scanner) isManifestScannable(digestStr string) (bool, error) {
	if scanner.cache.Get(digestStr) != nil {
		return true, nil
	}

	manifestData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digestStr))
	if err != nil {
		return false, err
	}

	if len(manifestData.Manifests) == 0 {
		return false, fmt.Errorf("%w: manifest data has 0 manifests", zerr.ErrScanNotSupported)
	}

	return scanner.layersScannable(manifestData.Manifests[0].Manifest.Layers)
}

func (scanner *Scanner) isManifestDataScannable(manifestData mTypes.ManifestMeta) (bool, error) {
	if scanner.cache.Get(manifestData.Digest.String()) != nil {
		return true, nil
	}

	return scanner.layersScannable(manifestData.Manifest.Layers)
}

func (scanner *Scanner) isIndexScannable(digestStr string) (bool, error) {
	indexData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digestStr))
	if err != nil {
		return false, err
	}

	if indexData.Index == nil {
		return false, zerr.ErrUnexpectedMediaType
	}

	if len(indexData.Index.Manifests) == 0 {
		return true, nil
	}

	for _, manifest := range indexData.Manifests {
		isScannable, err := scanner.isManifestDataScannable(manifest)
		if err != nil {
			continue
		}

		if isScannable {
			return true, nil
		}
	}

	return false, nil
}

func (scanner *Scanner) IsResultCached(repo, digest string) bool {
	if scanner.isIndexDigest(digest) {
		_, complete := scanner.cachedIndexAggregate(repo, digest)

		return complete
	}

	return scanner.cache.Contains(digest)
}

func (scanner *Scanner) GetCachedResult(repo, digest string) map[string]zcommon.CVE {
	if scanner.isIndexDigest(digest) {
		cveMap, complete := scanner.cachedIndexAggregate(repo, digest)
		if !complete {
			return map[string]zcommon.CVE{}
		}

		return cveMap
	}

	return scanner.cache.Get(digest)
}

func (scanner *Scanner) isIndexDigest(digest string) bool {
	imageMeta, err := scanner.metaDB.GetImageMeta(godigest.Digest(digest))
	if err != nil {
		return false
	}

	return compat.IsImageIndexMediaType(imageMeta.MediaType)
}

// cachedIndexAggregate returns the union of cached results for every present,
// scannable index member. complete is false if any such member is uncached.
func (scanner *Scanner) cachedIndexAggregate(repo, digest string) (map[string]zcommon.CVE, bool) {
	return scanner.cachedIndexAggregateSeen(repo, digest, map[string]struct{}{})
}

func (scanner *Scanner) cachedIndexAggregateSeen(repo, digest string, seen map[string]struct{},
) (map[string]zcommon.CVE, bool) {
	if _, ok := seen[digest]; ok {
		return map[string]zcommon.CVE{}, true
	}

	seen[digest] = struct{}{}

	indexData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digest))
	if err != nil || indexData.Index == nil {
		return nil, false
	}

	indexCveIDMap := map[string]zcommon.CVE{}
	imgStore := scanner.storeController.GetImageStore(repo)

	for _, manifest := range indexData.Index.Manifests {
		if imgStore != nil {
			var lockLatency time.Time

			imgStore.RLock(&lockLatency)
			_, _, _, err := imgStore.StatBlob(repo, manifest.Digest)
			imgStore.RUnlock(&lockLatency)

			if err != nil {
				if errors.Is(err, zerr.ErrManifestNotFound) || errors.Is(err, zerr.ErrBlobNotFound) {
					continue
				}

				return nil, false
			}
		}

		digestStr := manifest.Digest.String()

		if scanner.indexChildIsIndex(manifest) {
			nestedMap, complete := scanner.cachedIndexAggregateSeen(repo, digestStr, seen)
			if !complete {
				return nil, false
			}

			maps.Copy(indexCveIDMap, nestedMap)

			continue
		}

		isScannable, err := scanner.isManifestScannable(digestStr)
		if err != nil {
			if errors.Is(err, zerr.ErrScanNotSupported) {
				continue
			}

			return nil, false
		}

		if !isScannable {
			continue
		}

		cachedMap := scanner.cache.Get(digestStr)
		if cachedMap == nil {
			return nil, false
		}

		maps.Copy(indexCveIDMap, cachedMap)
	}

	return indexCveIDMap, true
}

func (scanner *Scanner) indexChildIsIndex(desc ispec.Descriptor) bool {
	if compat.IsImageIndexMediaType(desc.MediaType) {
		return true
	}

	if compat.IsImageManifestMediaType(desc.MediaType) {
		return false
	}

	return scanner.isIndexDigest(desc.Digest.String())
}

type cacheableScanResult struct {
	cachedMap map[string]zcommon.CVE
	wasCached bool
}

func (scanner *Scanner) scanManifest(ctx context.Context, repo, digest string) (map[string]zcommon.CVE, bool, error) {
	if cachedMap := scanner.cache.Get(digest); cachedMap != nil {
		return cachedMap, true, nil
	}

	resultChan := scanner.scanSingleFlightGroup.DoChan(repo+"@"+digest, func() (any, error) {
		return scanner.scanManifestDeduped(ctx, repo, digest)
	})

	select {
	case result := <-resultChan:
		if result.Err != nil {
			return map[string]zcommon.CVE{}, false, result.Err
		}

		scanResult, _ := result.Val.(cacheableScanResult)

		return scanResult.cachedMap, scanResult.wasCached, nil
	case <-ctx.Done():
		return map[string]zcommon.CVE{}, false, ctx.Err()
	}
}

func (scanner *Scanner) scanManifestDeduped(ctx context.Context, repo, digest string) (cacheableScanResult, error) {
	if cachedMap := scanner.cache.Get(digest); cachedMap != nil {
		return cacheableScanResult{cachedMap, true}, nil
	}

	cveidMap, err := scanner.scanManifestFn(context.WithoutCancel(ctx), repo, digest)
	if err != nil {
		return cacheableScanResult{}, err
	}

	scanner.cache.Add(digest, cveidMap)

	return cacheableScanResult{cveidMap, false}, nil
}

func (scanner *Scanner) scanIndex(ctx context.Context, repo, digest string) (map[string]zcommon.CVE, bool, error) {
	resultChan := scanner.scanSingleFlightGroup.DoChan(repo+"@"+digest, func() (any, error) {
		cveIDMap, wasCached, err := scanner.scanIndexSeen(context.WithoutCancel(ctx), repo, digest, map[string]struct{}{})
		if err != nil {
			return cacheableScanResult{}, err
		}

		return cacheableScanResult{cveIDMap, wasCached}, nil
	})

	select {
	case result := <-resultChan:
		if result.Err != nil {
			return map[string]zcommon.CVE{}, false, result.Err
		}

		scanResult, _ := result.Val.(cacheableScanResult)

		return scanResult.cachedMap, scanResult.wasCached, nil
	case <-ctx.Done():
		return map[string]zcommon.CVE{}, false, ctx.Err()
	}
}

// scanIndexSeen aggregates CVEs for an index's children. Index aggregates are
// never stored under the index digest because the same digest can be fully
// present in one repo and sparse in another; per-manifest results are cached.
func (scanner *Scanner) scanIndexSeen(ctx context.Context, repo, digest string, seen map[string]struct{},
) (map[string]zcommon.CVE, bool, error) {
	if _, ok := seen[digest]; ok {
		return map[string]zcommon.CVE{}, true, nil
	}

	seen[digest] = struct{}{}

	indexData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digest))
	if err != nil {
		return map[string]zcommon.CVE{}, false, err
	}

	if indexData.Index == nil {
		return map[string]zcommon.CVE{}, false, zerr.ErrUnexpectedMediaType
	}

	indexCveIDMap := map[string]zcommon.CVE{}
	wasCached := true

	imgStore := scanner.storeController.GetImageStore(repo)

	for _, manifest := range indexData.Index.Manifests {
		if imgStore != nil {
			var lockLatency time.Time

			imgStore.RLock(&lockLatency)
			_, _, _, err := imgStore.StatBlob(repo, manifest.Digest)
			imgStore.RUnlock(&lockLatency)

			if err != nil {
				if errors.Is(err, zerr.ErrManifestNotFound) || errors.Is(err, zerr.ErrBlobNotFound) {
					scanner.log.Warn().Err(err).Str("repo", repo).Str("index", digest).
						Str("manifest", manifest.Digest.String()).
						Msg("skipping missing child while scanning image index")

					continue
				}

				return map[string]zcommon.CVE{}, false, err
			}
		}

		digestStr := manifest.Digest.String()

		if scanner.indexChildIsIndex(manifest) {
			nestedCveIDMap, childCached, err := scanner.scanIndexSeen(ctx, repo, digestStr, seen)
			if err != nil {
				return map[string]zcommon.CVE{}, false, err
			}

			if !childCached {
				wasCached = false
			}

			maps.Copy(indexCveIDMap, nestedCveIDMap)

			continue
		}

		isScannable, err := scanner.isManifestScannable(digestStr)
		if err != nil {
			if errors.Is(err, zerr.ErrScanNotSupported) {
				continue
			}

			return map[string]zcommon.CVE{}, false, err
		}

		if !isScannable {
			continue
		}

		manifestCveIDMap, childCached, err := scanner.scanManifest(ctx, repo, digestStr)
		if err != nil {
			return map[string]zcommon.CVE{}, false, err
		}

		if !childCached {
			wasCached = false
		}

		maps.Copy(indexCveIDMap, manifestCveIDMap)
	}

	return indexCveIDMap, wasCached, nil
}

func getImageDescriptor(ctx context.Context, metaDB mTypes.MetaDB, repo, tag string) (mTypes.Descriptor, error) {
	repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		return mTypes.Descriptor{}, err
	}

	imageDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return mTypes.Descriptor{}, zerr.ErrTagMetaNotFound
	}

	return imageDescriptor, nil
}

func findMediaTypeForDigest(metaDB mTypes.MetaDB, digest godigest.Digest) (bool, string) {
	imageMeta, err := metaDB.GetImageMeta(digest)
	if err == nil {
		return true, imageMeta.MediaType
	}

	return false, ""
}
