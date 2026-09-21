package cveinfo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// openVEXPredicatePrefix matches the OpenVEX predicateType values used by
// cosign attest and oras (https://openvex.dev/ns, https://openvex.dev/ns/v0.2.0).
const openVEXPredicatePrefix = "https://openvex.dev"

// VexScanner applies OpenVEX statements attached to an image as referrers.
// Statements with status not_affected or fixed suppress the named
// vulnerability from every backend's results, so reports and any future
// gates observe the triaged posture rather than raw scanner output.
type VexScanner struct {
	Scanner
	metaDB          mTypes.MetaDB
	storeController storage.StoreController
	log             log.Logger
}

func NewVexScanner(base Scanner, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) *VexScanner {
	return &VexScanner{Scanner: base, metaDB: metaDB, storeController: storeController, log: log}
}

// vexVulnerability identifies a vulnerability inside an OpenVEX statement.
// Name carries IDs like CVE-2024-1234; ID carries the canonical URI form.
type vexVulnerability struct {
	Name string `json:"name"`
	ID   string `json:"@id"`
}

type vexStatement struct {
	Vulnerability vexVulnerability `json:"vulnerability"`
	Status        string           `json:"status"`
}

type vexDoc struct {
	Statements []vexStatement `json:"statements"`
}

type intotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

// bundleJSON covers the sigstore bundle layout cosign v3 produces: the DSSE
// envelope is embedded directly in the bundle JSON.
type bundleJSON struct {
	DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"`
}

// parseVEXDoc unwraps a blob into an OpenVEX document. It accepts a raw
// OpenVEX document, a bare in-toto statement, a DSSE envelope wrapping an
// in-toto statement, or a sigstore bundle carrying the same.
func parseVEXDoc(blob []byte) *vexDoc {
	var doc vexDoc
	if err := json.Unmarshal(blob, &doc); err == nil && len(doc.Statements) > 0 {
		return &doc
	}

	var stmt intotoStatement
	if err := json.Unmarshal(blob, &stmt); err == nil && stmt.Predicate != nil &&
		strings.HasPrefix(stmt.PredicateType, openVEXPredicatePrefix) {
		if err := json.Unmarshal(stmt.Predicate, &doc); err == nil && len(doc.Statements) > 0 {
			return &doc
		}
	}

	var env dsseEnvelope
	if err := json.Unmarshal(blob, &env); err == nil && env.Payload != "" {
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err == nil {
			return parseVEXDoc(payload)
		}
	}

	var bnd bundleJSON
	if err := json.Unmarshal(blob, &bnd); err == nil && bnd.DSSEEnvelope != nil {
		raw, err := json.Marshal(bnd.DSSEEnvelope)
		if err == nil {
			return parseVEXDoc(raw)
		}
	}

	return nil
}

// suppressedStatuses are the OpenVEX statement statuses that remove a finding.
var suppressedStatuses = map[string]bool{
	"not_affected": true,
	"fixed":        true,
}

// vexSuppressions returns vulnerability IDs suppressed for digest in repo by
// OpenVEX statements in its referrers, mapped to their declared status.
func (v *VexScanner) vexSuppressions(repo string, digest godigest.Digest) map[string]string {
	suppressed := map[string]string{}

	referrers, err := v.metaDB.GetReferrersInfo(repo, digest, nil)

	v.log.Debug().Str("repo", repo).Str("digest", digest.String()).Int("referrers", len(referrers)).
		Msg("vex: resolving referrers")
	if err != nil {
		v.log.Debug().Err(err).Str("repo", repo).Str("digest", digest.String()).
			Msg("vex: failed to list referrers")

		return suppressed
	}

	imgStore := v.storeController.GetImageStore(repo)
	if imgStore == nil {
		return suppressed
	}

	for _, ref := range referrers {
		refDigest, err := godigest.Parse(ref.Digest)
		if err != nil {
			continue
		}

		manifestBlob, err := imgStore.GetBlobContent(repo, refDigest)
		if err != nil {
			continue
		}

		var manifest ispec.Manifest
		if err := json.Unmarshal(manifestBlob, &manifest); err != nil || len(manifest.Layers) == 0 {
			continue
		}

		for _, layer := range manifest.Layers {
			layerBlob, err := imgStore.GetBlobContent(repo, layer.Digest)
			if err != nil {
				continue
			}

			doc := parseVEXDoc(layerBlob)
			if doc == nil {
				continue
			}

			v.log.Debug().Str("repo", repo).Str("digest", digest.String()).
				Int("statements", len(doc.Statements)).Msg("vex: parsed document")

			for _, stmt := range doc.Statements {
				if !suppressedStatuses[stmt.Status] {
					continue
				}

				if stmt.Vulnerability.Name != "" {
					suppressed[stmt.Vulnerability.Name] = stmt.Status
				}

				if stmt.Vulnerability.ID != "" {
					suppressed[stmt.Vulnerability.ID] = stmt.Status

					// statements often use a URI @id like
					// https://nvd.nist.gov/vuln/detail/CVE-2024-1234; match the
					// trailing identifier against plain CVE keys too
					if idx := strings.LastIndex(stmt.Vulnerability.ID, "/"); idx >= 0 {
						suppressed[stmt.Vulnerability.ID[idx+1:]] = stmt.Status
					}
				}
			}
		}
	}

	return suppressed
}

// applyVex drops suppressed findings from cveMap in place. Statements name
// vulnerabilities by ID or URI; both map to the plain CVE ID keys scanners use.
func (v *VexScanner) applyVex(repo, digestStr string, cveMap map[string]zcommon.CVE) {
	if len(cveMap) == 0 {
		return
	}

	digest, err := godigest.Parse(digestStr)
	if err != nil {
		v.log.Debug().Str("repo", repo).Str("digest", digestStr).Msg("vex: unparseable digest, skipping")

		return
	}

	suppressed := v.vexSuppressions(repo, digest)

	for id := range cveMap {
		if _, ok := suppressed[id]; ok {
			delete(cveMap, id)
		}
	}
}

// VexSuppressed returns the vulnerability IDs suppressed by VEX statements for
// digest in repo, mapped to their status, for the management report.
func (v *VexScanner) VexSuppressed(repo, digestStr string) map[string]string {
	digest, err := godigest.Parse(digestStr)
	if err != nil {
		return nil
	}

	return v.vexSuppressions(repo, digest)
}

func (v *VexScanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	v.log.Debug().Str("image", image).Msg("vex: ScanImage")

	result, err := v.Scanner.ScanImage(ctx, image)
	if err != nil {
		return result, err
	}

	repo, _, _ := zcommon.GetImageDirAndReference(image)
	v.applyVex(repo, result.Digest, result.CVEMap)

	return result, nil
}

func (v *VexScanner) GetCachedResult(repo, digestStr string) map[string]zcommon.CVE {
	cveMap := v.Scanner.GetCachedResult(repo, digestStr)
	v.applyVex(repo, digestStr, cveMap)

	return cveMap
}

// PerScannerReporter passthroughs, same forwarding pattern as the decorated
// scanner in scan.go, with VEX suppression applied per backend so the
// disagreement report shows the post-triage state.
func (v *VexScanner) ScannerNames() []string {
	if reporter, ok := v.Scanner.(PerScannerReporter); ok {
		return reporter.ScannerNames()
	}

	return []string{"scanner"}
}

func (v *VexScanner) ScanPerScanner(ctx context.Context, image string,
) (map[string]cvemodel.ScanResult, map[string]error) {
	var results map[string]cvemodel.ScanResult
	var errs map[string]error

	if reporter, ok := v.Scanner.(PerScannerReporter); ok {
		results, errs = reporter.ScanPerScanner(ctx, image)
	} else {
		result, err := v.Scanner.ScanImage(ctx, image)
		if err != nil {
			return nil, map[string]error{"scanner": err}
		}

		results = map[string]cvemodel.ScanResult{"scanner": result}
	}

	repo, _, _ := zcommon.GetImageDirAndReference(image)

	for name, result := range results {
		v.applyVex(repo, result.Digest, result.CVEMap)
		results[name] = result
	}

	return results, errs
}

func (v *VexScanner) CachedPerScanner(repo, digest string) map[string]map[string]zcommon.CVE {
	var results map[string]map[string]zcommon.CVE

	if reporter, ok := v.Scanner.(PerScannerReporter); ok {
		results = reporter.CachedPerScanner(repo, digest)
	} else {
		results = map[string]map[string]zcommon.CVE{"scanner": v.Scanner.GetCachedResult(repo, digest)}
	}

	for name, cveMap := range results {
		v.applyVex(repo, digest, cveMap)
		results[name] = cveMap
	}

	return results
}

// ScannerDBStatus forwards DB freshness reporting to the wrapped scanner when
// it implements DBStatusReporter.
func (v *VexScanner) ScannerDBStatus() []cvemodel.ScannerDBStatus {
	if reporter, ok := v.Scanner.(DBStatusReporter); ok {
		return reporter.ScannerDBStatus()
	}

	return nil
}
