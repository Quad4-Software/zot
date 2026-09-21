package cveinfo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// openVEXPredicatePrefix matches the OpenVEX predicateType values used by
// cosign attest and oras (https://openvex.dev/ns, https://openvex.dev/ns/v0.2.0).
const openVEXPredicatePrefix = "https://openvex.dev"

// maxVexBlobSize bounds how much of a single referrer manifest or layer blob
// is read into memory. Referrers are push-controlled data, so unbounded reads
// would let any user with push access amplify memory and disk usage per scan.
const maxVexBlobSize = 4 << 20 // 4 MiB

// vexArtifactHints are the artifact types that may carry an OpenVEX document.
// Referrers with a clearly unrelated artifact type are never read; referrers
// with no artifact type are still inspected because some tooling pushes
// attestation artifacts untyped.
var vexArtifactHints = []string{"vex", "in-toto", "dsse", "sigstore", "attestation"}

// isVexCandidateArtifactType reports whether a referrer artifact type may
// carry an OpenVEX document. Empty types are accepted.
func isVexCandidateArtifactType(artifactType string) bool {
	if artifactType == "" {
		return true
	}

	lower := strings.ToLower(artifactType)
	for _, hint := range vexArtifactHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}

	return false
}

// isVexCandidateLayerType reports whether a layer media type may contain an
// OpenVEX document or a wrapper (DSSE envelope, sigstore bundle, in-toto
// statement) holding one. Compressed or non-JSON layers are skipped.
func isVexCandidateLayerType(mediaType string) bool {
	if mediaType == "application/json" {
		return true
	}

	lower := strings.ToLower(mediaType)
	if !strings.HasSuffix(lower, "+json") {
		return false
	}

	for _, hint := range vexArtifactHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}

	return false
}

// VexScanner applies OpenVEX statements attached to an image as referrers.
// Statements with status not_affected or fixed suppress the named
// vulnerability from every backend's results, so reports and any future
// gates observe the triaged posture rather than raw scanner output.
//
// Trust boundary: statements are parsed but their signatures are not
// verified. A VEX document is trusted because it was pushed by an identity
// allowed to push artifacts into the repository. Operators who need
// cryptographic provenance for suppressions should restrict push access or
// verify documents before pushing them.
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

// VexSuppressor is implemented by scanners that can report which
// vulnerability IDs OpenVEX statements suppress for a digest.
type VexSuppressor interface {
	VexSuppressed(repo, digestStr string) map[string]string
}

// vexVulnerability identifies a vulnerability inside an OpenVEX statement.
// Name carries IDs like CVE-2024-1234; ID carries the canonical URI form.
type vexVulnerability struct {
	Name string `json:"name"`
	ID   string `json:"@id"`
}

// vexProduct names a product a statement applies to. OpenVEX allows both a
// bare identifier string (pkg:oci/repo@sha256:abc) and an object form with
// @id, so entries are decoded leniently.
type vexProduct struct {
	ID   string `json:"@id"`
	Name string `json:"name"`
}

// productIDs extracts the identifier strings from a raw product entry in
// either the string or object form.
func productIDs(raw json.RawMessage) []string {
	var id string
	if err := json.Unmarshal(raw, &id); err == nil {
		return []string{id}
	}

	var product vexProduct
	if err := json.Unmarshal(raw, &product); err == nil {
		return []string{product.ID, product.Name}
	}

	return nil
}

type vexStatement struct {
	Vulnerability vexVulnerability  `json:"vulnerability"`
	Products      []json.RawMessage `json:"products"`
	Status        string            `json:"status"`
}

// vexDoc keeps statements raw so a single malformed statement does not
// invalidate the whole document.
type vexDoc struct {
	Statements []json.RawMessage `json:"statements"`
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

// vexUnwrapMaxDepth bounds DSSE envelope unwrapping. Nested envelopes are
// legitimate but rare; a referrer blob under push control could otherwise
// recurse arbitrarily deep.
const vexUnwrapMaxDepth = 8

// parseVEXDoc unwraps a blob into an OpenVEX document. It accepts a raw
// OpenVEX document, a bare in-toto statement, a DSSE envelope wrapping an
// in-toto statement, or a sigstore bundle carrying the same.
func parseVEXDoc(blob []byte) *vexDoc {
	return parseVEXDocDepth(blob, 0)
}

func parseVEXDocDepth(blob []byte, depth int) *vexDoc {
	if depth > vexUnwrapMaxDepth {
		return nil
	}

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
			return parseVEXDocDepth(payload, depth+1)
		}
	}

	var bnd bundleJSON
	if err := json.Unmarshal(blob, &bnd); err == nil && bnd.DSSEEnvelope != nil {
		raw, err := json.Marshal(bnd.DSSEEnvelope)
		if err == nil {
			return parseVEXDocDepth(raw, depth+1)
		}
	}

	return nil
}

// suppressedStatuses are the OpenVEX statement statuses that remove a finding.
var suppressedStatuses = map[string]bool{
	"not_affected": true,
	"fixed":        true,
}

// readBlobLimited streams at most maxVexBlobSize bytes of a blob. The second
// return value reports whether the blob was truncated. GetBlob takes the
// store read lock internally, so no lock is held here.
func readBlobLimited(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest) ([]byte, bool, error) {
	rc, _, err := imgStore.GetBlob(repo, digest, "")
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxVexBlobSize+1))
	if err != nil {
		return nil, false, err
	}

	if len(data) > maxVexBlobSize {
		return data[:maxVexBlobSize], true, nil
	}

	return data, false, nil
}

// productMatchesSubject reports whether a statement's products scope it to
// the scanned image. Statements with no digest-pinned OCI products apply to
// any subject; when products pin a digest, at least one must carry the
// scanned digest so a statement written for another image cannot suppress
// findings here.
func productMatchesSubject(products []json.RawMessage, digest godigest.Digest) bool {
	pinned := false

	for _, raw := range products {
		for _, id := range productIDs(raw) {
			at := strings.LastIndex(id, "@")
			if at < 0 || !strings.Contains(id[at+1:], ":") {
				continue
			}

			alg, _, _ := strings.Cut(id[at+1:], ":")
			if !strings.HasPrefix(alg, "sha") {
				continue
			}

			pinned = true

			if id[at+1:] == digest.String() {
				return true
			}
		}
	}

	return !pinned
}

// vexSuppressions returns vulnerability IDs suppressed for digest in repo by
// OpenVEX statements in its referrers, mapped to their declared status.
func (v *VexScanner) vexSuppressions(repo string, digest godigest.Digest) map[string]string {
	suppressed := map[string]string{}

	// nil artifact filter lists every referrer: the MetaDB filter cannot
	// express "untyped or attestation", so candidates are filtered below
	// before any blob is read. Listing itself is index metadata only.
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
		if !isVexCandidateArtifactType(ref.ArtifactType) {
			continue
		}

		// skip oversized referrer manifests without opening the blob
		if ref.Size > 0 && int64(ref.Size) > maxVexBlobSize {
			continue
		}

		refDigest, err := godigest.Parse(ref.Digest)
		if err != nil {
			continue
		}

		manifestBlob, truncated, err := readBlobLimited(imgStore, repo, refDigest)
		if err != nil || truncated {
			continue
		}

		var manifest ispec.Manifest
		if err := json.Unmarshal(manifestBlob, &manifest); err != nil || len(manifest.Layers) == 0 {
			continue
		}

		for _, layer := range manifest.Layers {
			if !isVexCandidateLayerType(layer.MediaType) ||
				layer.Size > maxVexBlobSize {
				continue
			}

			layerBlob, truncated, err := readBlobLimited(imgStore, repo, layer.Digest)
			if err != nil || truncated {
				continue
			}

			doc := parseVEXDoc(layerBlob)
			if doc == nil {
				continue
			}

			v.log.Debug().Str("repo", repo).Str("digest", digest.String()).
				Int("statements", len(doc.Statements)).Msg("vex: parsed document")

			for _, raw := range doc.Statements {
				var stmt vexStatement
				// a single malformed statement is skipped rather than
				// invalidating the whole document
				if err := json.Unmarshal(raw, &stmt); err != nil {
					continue
				}

				if !suppressedStatuses[stmt.Status] {
					continue
				}

				if !productMatchesSubject(stmt.Products, digest) {
					continue
				}

				for _, id := range []string{stmt.Vulnerability.Name, stmt.Vulnerability.ID} {
					if id == "" {
						continue
					}

					// statements may name the vulnerability as a bare ID
					// (CVE-2024-1234) or a URI like
					// https://nvd.nist.gov/vuln/detail/CVE-2024-1234; match the
					// trailing identifier against plain scanner keys too
					if idx := strings.LastIndex(id, "/"); idx >= 0 {
						id = id[idx+1:]
					}

					if id != "" {
						suppressed[strings.ToUpper(id)] = stmt.Status
					}
				}
			}
		}
	}

	return suppressed
}

// applyVexSuppressions returns a copy of cveMap with suppressed findings removed.
// Statements name vulnerabilities by ID or URI; both map to the plain
// CVE ID keys scanners use. The input map must not be mutated: backends
// hand out references to their LRU cache contents, so deleting in place
// would corrupt the cache and race with concurrent readers.
func applyVexSuppressions(suppressed map[string]string, cveMap map[string]zcommon.CVE) map[string]zcommon.CVE {
	if len(cveMap) == 0 || len(suppressed) == 0 {
		return cveMap
	}

	filtered := make(map[string]zcommon.CVE, len(cveMap))

	for id, cve := range cveMap {
		if _, ok := suppressed[strings.ToUpper(id)]; !ok {
			filtered[id] = cve
		}
	}

	return filtered
}

// suppressionsByDigest memoizes vexSuppressions per digest inside a single
// scan call so multi-backend scans resolve referrers once.
type suppressionsByDigest struct {
	v     *VexScanner
	repo  string
	cache map[string]map[string]string
}

func newSuppressionsByDigest(v *VexScanner, repo string) *suppressionsByDigest {
	return &suppressionsByDigest{v: v, repo: repo, cache: map[string]map[string]string{}}
}

func (s *suppressionsByDigest) get(digestStr string) map[string]string {
	if suppressed, ok := s.cache[digestStr]; ok {
		return suppressed
	}

	digest, err := godigest.Parse(digestStr)
	if err != nil {
		s.v.log.Debug().Str("repo", s.repo).Str("digest", digestStr).
			Msg("vex: unparseable digest, skipping")

		s.cache[digestStr] = nil

		return nil
	}

	suppressed := s.v.vexSuppressions(s.repo, digest)
	s.cache[digestStr] = suppressed

	return suppressed
}

func (v *VexScanner) applyVex(supp *suppressionsByDigest, digestStr string,
	cveMap map[string]zcommon.CVE,
) map[string]zcommon.CVE {
	if len(cveMap) == 0 {
		return cveMap
	}

	return applyVexSuppressions(supp.get(digestStr), cveMap)
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
	result, err := v.Scanner.ScanImage(ctx, image)
	if err != nil {
		return result, err
	}

	repo, _, _ := zcommon.GetImageDirAndReference(image)
	result.CVEMap = v.applyVex(newSuppressionsByDigest(v, repo), result.Digest, result.CVEMap)

	return result, nil
}

func (v *VexScanner) GetCachedResult(repo, digestStr string) map[string]zcommon.CVE {
	return v.applyVex(newSuppressionsByDigest(v, repo), digestStr,
		v.Scanner.GetCachedResult(repo, digestStr))
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
	supp := newSuppressionsByDigest(v, repo)

	for name, result := range results {
		result.CVEMap = v.applyVex(supp, result.Digest, result.CVEMap)
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

	supp := newSuppressionsByDigest(v, repo)

	for name, cveMap := range results {
		results[name] = v.applyVex(supp, digest, cveMap)
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
