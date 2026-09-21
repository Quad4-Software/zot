package cveinfo

import (
	"context"
	"errors"
	"maps"
	"slices"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
)

// dbStatusProvider is implemented by backend scanners that can report their
// vulnerability DB freshness.
type dbStatusProvider interface {
	DBStatus() cvemodel.ScannerDBStatus
}

// DBStatusReporter is implemented by scanners that can report DB freshness
// per enabled backend, used by the management endpoint for scanner health.
type DBStatusReporter interface {
	ScannerDBStatus() []cvemodel.ScannerDBStatus
}

// PerScannerReporter is implemented by scanners that can report results per
// backend scanner, used by the management endpoint to surface disagreements.
type PerScannerReporter interface {
	// ScannerNames returns the enabled backend names (e.g. "trivy", "grype").
	ScannerNames() []string
	// ScanPerScanner runs every enabled backend on the image and returns the
	// per-scanner result. Backends that fail report their error in the error
	// map instead of failing the whole call.
	ScanPerScanner(ctx context.Context, image string) (map[string]cvemodel.ScanResult, map[string]error)
	// CachedPerScanner returns cached results per backend without scanning.
	CachedPerScanner(repo, digest string) map[string]map[string]zcommon.CVE
}

type namedScanner struct {
	name    string
	scanner Scanner
}

// MultiScanner runs several CVE scanner backends and merges their results.
type MultiScanner struct {
	backends []namedScanner
	log      log.Logger
}

func NewMultiScanner(backends []namedScanner, log log.Logger) *MultiScanner {
	return &MultiScanner{backends: backends, log: log}
}

func (m *MultiScanner) ScannerNames() []string {
	names := make([]string, 0, len(m.backends))
	for _, b := range m.backends {
		names = append(names, b.name)
	}

	return names
}

func (m *MultiScanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	results, errs := m.ScanPerScanner(ctx, image)

	merged := cvemodel.ScanResult{CVEMap: map[string]zcommon.CVE{}}
	succeeded := 0
	allCached := true

	for _, b := range m.backends {
		result, ok := results[b.name]
		if !ok || errs[b.name] != nil {
			continue
		}

		succeeded++
		allCached = allCached && result.WasCached
		merged.Digest = result.Digest
		merged.MediaType = result.MediaType

		mergeCVEMap(merged.CVEMap, result.CVEMap)
	}

	merged.WasCached = allCached

	if succeeded == 0 {
		return cvemodel.ScanResult{}, errors.Join(slices.Collect(maps.Values(errs))...)
	}

	return merged, nil
}

// ScanPerScanner scans the image with every enabled backend. Backends share
// their cache so repeated calls are cheap; each result is tagged by backend
// name so callers can compute disagreements.
func (m *MultiScanner) ScanPerScanner(ctx context.Context, image string,
) (map[string]cvemodel.ScanResult, map[string]error) {
	results := map[string]cvemodel.ScanResult{}
	errs := map[string]error{}

	for _, b := range m.backends {
		result, err := b.scanner.ScanImage(ctx, image)
		if err != nil {
			m.log.Error().Err(err).Str("image", image).Str("scanner", b.name).
				Msg("scanner backend failed")

			errs[b.name] = err

			continue
		}

		results[b.name] = result
	}

	return results, errs
}

func (m *MultiScanner) CachedPerScanner(repo, digest string) map[string]map[string]zcommon.CVE {
	results := map[string]map[string]zcommon.CVE{}

	for _, b := range m.backends {
		if !b.scanner.IsResultCached(repo, digest) {
			continue
		}

		results[b.name] = b.scanner.GetCachedResult(repo, digest)
	}

	return results
}

func (m *MultiScanner) IsImageFormatScannable(repo, ref string) (bool, error) {
	var errs []error

	for _, b := range m.backends {
		ok, err := b.scanner.IsImageFormatScannable(repo, ref)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if ok {
			return true, nil
		}
	}

	return false, errors.Join(errs...)
}

func (m *MultiScanner) IsImageMediaScannable(repo, digestStr, mediaType string) (bool, error) {
	var errs []error

	for _, b := range m.backends {
		ok, err := b.scanner.IsImageMediaScannable(repo, digestStr, mediaType)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if ok {
			return true, nil
		}
	}

	return false, errors.Join(errs...)
}

func (m *MultiScanner) IsResultCached(repo, digestStr string) bool {
	for _, b := range m.backends {
		if !b.scanner.IsResultCached(repo, digestStr) {
			return false
		}
	}

	return true
}

func (m *MultiScanner) GetCachedResult(repo, digestStr string) map[string]zcommon.CVE {
	merged := map[string]zcommon.CVE{}

	for _, b := range m.backends {
		if !b.scanner.IsResultCached(repo, digestStr) {
			continue
		}

		mergeCVEMap(merged, b.scanner.GetCachedResult(repo, digestStr))
	}

	return merged
}

func (m *MultiScanner) ScannerDBStatus() []cvemodel.ScannerDBStatus {
	statuses := make([]cvemodel.ScannerDBStatus, 0, len(m.backends))

	for _, b := range m.backends {
		if provider, ok := b.scanner.(dbStatusProvider); ok {
			status := provider.DBStatus()
			status.Name = b.name
			statuses = append(statuses, status)
		} else {
			statuses = append(statuses, cvemodel.ScannerDBStatus{Name: b.name})
		}
	}

	return statuses
}

func (m *MultiScanner) UpdateDB(ctx context.Context) error {
	var errs []error

	for _, b := range m.backends {
		if err := b.scanner.UpdateDB(ctx); err != nil {
			m.log.Error().Err(err).Str("scanner", b.name).Msg("failed to update scanner DB")

			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// mergeCVEMap unions src into dst by vulnerability ID. Entries found by
// several backends merge their package lists and keep the highest severity.
func mergeCVEMap(dst, src map[string]zcommon.CVE) {
	for id, cve := range src {
		existing, ok := dst[id]
		if !ok {
			dst[id] = cve

			continue
		}

		if cvemodel.CompareSeverities(existing.Severity, cve.Severity) > 0 {
			existing.Severity = cve.Severity
		}

		if existing.Description == "" {
			existing.Description = cve.Description
		}

		if existing.Reference == "" {
			existing.Reference = cve.Reference
		}

		// existing may alias a CVE struct (and its PackageList backing array)
		// handed out of a backend's LRU cache; clone before appending so the
		// merge never writes into cache-owned memory
		existing.PackageList = slices.Clone(existing.PackageList)

		for _, pack := range cve.PackageList {
			if slices.Contains(existing.PackageList, pack) {
				continue
			}

			existing.PackageList = append(existing.PackageList, pack)
		}

		dst[id] = existing
	}
}

func namedBackend(name string, scanner Scanner) namedScanner {
	return namedScanner{name: name, scanner: scanner}
}
