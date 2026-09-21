//go:build search

package cveinfo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()

	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func rawVexDoc(t *testing.T) []byte {
	t.Helper()

	statements := []json.RawMessage{}
	for _, stmt := range []vexStatement{
		{Vulnerability: vexVulnerability{Name: "CVE-1"}, Status: "not_affected"},
		{Vulnerability: vexVulnerability{Name: "CVE-2"}, Status: "fixed"},
		{Vulnerability: vexVulnerability{Name: "CVE-3"}, Status: "under_investigation"},
		{Vulnerability: vexVulnerability{ID: "https://nvd.nist.gov/vuln/detail/CVE-4"}, Status: "not_affected"},
	} {
		statements = append(statements, json.RawMessage(mustJSON(t, stmt)))
	}

	return mustJSON(t, vexDoc{Statements: statements})
}

func intotoVexStatement(t *testing.T) []byte {
	t.Helper()

	return mustJSON(t, intotoStatement{
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate:     json.RawMessage(rawVexDoc(t)),
	})
}

func TestParseVexDoc(t *testing.T) {
	Convey("parse raw openvex document", t, func() {
		doc := parseVEXDoc(rawVexDoc(t))
		So(doc, ShouldNotBeNil)
		So(doc.Statements, ShouldHaveLength, 4)
	})

	Convey("parse in-toto statement with openvex predicate", t, func() {
		doc := parseVEXDoc(intotoVexStatement(t))
		So(doc, ShouldNotBeNil)
		So(doc.Statements, ShouldHaveLength, 4)
	})

	Convey("in-toto statement with non-vex predicate is ignored", t, func() {
		blob := mustJSON(t, intotoStatement{
			PredicateType: "https://slsa.dev/provenance/v1",
			Predicate:     json.RawMessage(`{"statements": []}`),
		})
		So(parseVEXDoc(blob), ShouldBeNil)
	})

	Convey("parse dsse envelope wrapping in-toto statement", t, func() {
		envelope := mustJSON(t, dsseEnvelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     base64.StdEncoding.EncodeToString(intotoVexStatement(t)),
		})
		doc := parseVEXDoc(envelope)
		So(doc, ShouldNotBeNil)
		So(doc.Statements, ShouldHaveLength, 4)
	})

	Convey("parse sigstore bundle with dsse envelope", t, func() {
		bundle := mustJSON(t, map[string]interface{}{
			"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
			"dsseEnvelope": dsseEnvelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString(intotoVexStatement(t)),
			},
		})
		doc := parseVEXDoc(bundle)
		So(doc, ShouldNotBeNil)
		So(doc.Statements, ShouldHaveLength, 4)
	})

	Convey("dsse nesting beyond the depth cap returns nil", t, func() {
		payload := intotoVexStatement(t)

		for i := 0; i < vexUnwrapMaxDepth+2; i++ {
			payload = mustJSON(t, dsseEnvelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString(payload),
			})
		}

		So(parseVEXDoc(payload), ShouldBeNil)
	})

	Convey("garbage returns nil", t, func() {
		So(parseVEXDoc([]byte("not json")), ShouldBeNil)
		So(parseVEXDoc([]byte("{}")), ShouldBeNil)
	})
}

func TestVexScanner(t *testing.T) {
	imgDigest := godigest.FromString("img").String()

	scannerFor := func(cves map[string]zcommon.CVE) mocks.CveScannerMock {
		mock := scannerReturning(cves, nil)
		mock.ScanImageFn = func(ctx context.Context, image string) (cvemodel.ScanResult, error) {
			return cvemodel.ScanResult{CVEMap: cves, Digest: imgDigest}, nil
		}

		return mock
	}

	manifestBlob := mustJSON(t, ispec.Manifest{
		Versioned: struct {
			SchemaVersion int `json:"schemaVersion"`
		}{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageManifest,
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				Digest:    godigest.FromString("layer"),
				Size:      1,
			},
		},
	})

	layerBlob := mustJSON(t, map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": dsseEnvelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     base64.StdEncoding.EncodeToString(intotoVexStatement(t)),
		},
	})

	blobs := map[godigest.Digest][]byte{
		godigest.FromString("referrer"): manifestBlob,
		godigest.FromString("layer"):    layerBlob,
	}

	makeStore := func() storage.StoreController {
		return storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetBlobFn: func(repo string, digest godigest.Digest, mediaType string,
			) (io.ReadCloser, int64, error) {
				blob, ok := blobs[digest]
				if !ok {
					return nil, -1, zerr.ErrBlobNotFound
				}

				return io.NopCloser(strings.NewReader(string(blob))), int64(len(blob)), nil
			},
		}}
	}

	metaDB := mocks.MetaDBMock{
		GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
			artifactTypes []string,
		) ([]mTypes.ReferrerInfo, error) {
			return []mTypes.ReferrerInfo{
				{
					Digest:       godigest.FromString("referrer").String(),
					MediaType:    ispec.MediaTypeImageManifest,
					ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				},
			}, nil
		},
	}

	Convey("vex statements suppress matching findings", t, func() {
		base := scannerFor(map[string]zcommon.CVE{
			"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
			"CVE-2": cveFinding("CVE-2", cvemodel.SeverityLow, "libb"),
			"CVE-3": cveFinding("CVE-3", cvemodel.SeverityMedium, "libc"),
			"CVE-9": cveFinding("CVE-9", cvemodel.SeverityCritical, "libz"),
		})

		vs := NewVexScanner(base, makeStore(), metaDB, log.NewLogger("debug", ""))

		result, err := vs.ScanImage(context.Background(), "repo@sha256:abc")
		So(err, ShouldBeNil)
		So(result.CVEMap, ShouldNotContainKey, "CVE-1")
		So(result.CVEMap, ShouldNotContainKey, "CVE-2")
		So(result.CVEMap, ShouldContainKey, "CVE-3")
		So(result.CVEMap, ShouldContainKey, "CVE-9")
	})

	Convey("the input cve map is never mutated", t, func() {
		// backends hand out references to their LRU cache contents; filtering
		// must return a copy so the cached data survives a VEX doc removal
		original := map[string]zcommon.CVE{
			"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
			"CVE-9": cveFinding("CVE-9", cvemodel.SeverityCritical, "libz"),
		}

		base := mocks.CveScannerMock{
			GetCachedResultFn: func(repo, digest string) map[string]zcommon.CVE {
				return original
			},
		}

		vs := NewVexScanner(base, makeStore(), metaDB, log.NewLogger("debug", ""))

		filtered := vs.GetCachedResult("repo", imgDigest)
		So(filtered, ShouldNotContainKey, "CVE-1")
		So(original, ShouldContainKey, "CVE-1")
		So(original, ShouldContainKey, "CVE-9")
	})

	Convey("vulnerability id matching is case-insensitive", t, func() {
		base := scannerFor(map[string]zcommon.CVE{
			"cve-1": cveFinding("cve-1", cvemodel.SeverityHigh, "liba"),
		})

		vs := NewVexScanner(base, makeStore(), metaDB, log.NewLogger("debug", ""))

		result, err := vs.ScanImage(context.Background(), "repo@sha256:abc")
		So(err, ShouldBeNil)
		So(result.CVEMap, ShouldNotContainKey, "cve-1")
	})

	Convey("suppressed ids are reported for the mgmt endpoint", t, func() {
		base := scannerFor(nil)
		vs := NewVexScanner(base, makeStore(), metaDB, log.NewLogger("debug", ""))

		suppressed := vs.VexSuppressed("repo", godigest.FromString("img").String())
		So(suppressed, ShouldContainKey, "CVE-1")
		So(suppressed, ShouldContainKey, "CVE-4")
		So(suppressed, ShouldNotContainKey, "CVE-3")
	})

	Convey("scanner with no vex referrers passes results through", t, func() {
		emptyMeta := mocks.MetaDBMock{
			GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
				artifactTypes []string,
			) ([]mTypes.ReferrerInfo, error) {
				return nil, nil
			},
		}

		base := scannerFor(map[string]zcommon.CVE{
			"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
		})

		vs := NewVexScanner(base, makeStore(), emptyMeta, log.NewLogger("debug", ""))

		result, err := vs.ScanImage(context.Background(), "repo@sha256:abc")
		So(err, ShouldBeNil)
		So(result.CVEMap, ShouldContainKey, "CVE-1")
	})

	Convey("per-scanner forwarding applies suppression per backend", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerFor(map[string]zcommon.CVE{
				"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
				"CVE-9": cveFinding("CVE-9", cvemodel.SeverityCritical, "libz"),
			})),
		}, log.NewLogger("debug", ""))

		vs := NewVexScanner(multi, makeStore(), metaDB, log.NewLogger("debug", ""))

		results, errs := vs.ScanPerScanner(context.Background(), "repo@sha256:abc")
		So(errs, ShouldBeEmpty)
		So(results["trivy"].CVEMap, ShouldNotContainKey, "CVE-1")
		So(results["trivy"].CVEMap, ShouldContainKey, "CVE-9")
	})

	Convey("referrers with unrelated artifact types are never read", t, func() {
		blobReads := 0

		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetBlobFn: func(repo string, digest godigest.Digest, mediaType string,
			) (io.ReadCloser, int64, error) {
				blobReads++

				return nil, -1, zerr.ErrBlobNotFound
			},
		}}

		sigOnlyMeta := mocks.MetaDBMock{
			GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
				artifactTypes []string,
			) ([]mTypes.ReferrerInfo, error) {
				return []mTypes.ReferrerInfo{
					{
						Digest:       godigest.FromString("referrer").String(),
						MediaType:    ispec.MediaTypeImageManifest,
						ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json",
					},
				}, nil
			},
		}

		vs := NewVexScanner(scannerFor(nil), store, sigOnlyMeta, log.NewLogger("debug", ""))

		suppressed := vs.VexSuppressed("repo", imgDigest)
		So(suppressed, ShouldBeEmpty)
		So(blobReads, ShouldEqual, 0)
	})

	Convey("oversized layers are skipped without a read", t, func() {
		bigManifest := mustJSON(t, ispec.Manifest{
			Versioned: struct {
				SchemaVersion int `json:"schemaVersion"`
			}{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.vex+json",
					Digest:    godigest.FromString("biglayer"),
					Size:      maxVexBlobSize + 1,
				},
			},
		})

		layerReads := 0

		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetBlobFn: func(repo string, digest godigest.Digest, mediaType string,
			) (io.ReadCloser, int64, error) {
				if digest == godigest.FromString("biglayer") {
					layerReads++
				}

				if digest == godigest.FromString("bigreferrer") {
					return io.NopCloser(strings.NewReader(string(bigManifest))), int64(len(bigManifest)), nil
				}

				return nil, -1, zerr.ErrBlobNotFound
			},
		}}

		bigMeta := mocks.MetaDBMock{
			GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
				artifactTypes []string,
			) ([]mTypes.ReferrerInfo, error) {
				return []mTypes.ReferrerInfo{
					{
						Digest:       godigest.FromString("bigreferrer").String(),
						MediaType:    ispec.MediaTypeImageManifest,
						ArtifactType: "application/vnd.vex+json",
						Size:         len(bigManifest),
					},
				}, nil
			},
		}

		vs := NewVexScanner(scannerFor(nil), store, bigMeta, log.NewLogger("debug", ""))

		suppressed := vs.VexSuppressed("repo", imgDigest)
		So(suppressed, ShouldBeEmpty)
		So(layerReads, ShouldEqual, 0)
	})

	Convey("a malformed statement does not invalidate the document", t, func() {
		// wrong-typed fields fail per statement; valid siblings still apply
		docWithBad := []byte(`{"statements":[{"vulnerability":123,"status":"not_affected"},` +
			string(mustJSON(t, vexStatement{
				Vulnerability: vexVulnerability{Name: "CVE-7"},
				Status:        "not_affected",
			})) + `]}`)

		So(parseVEXDoc(docWithBad), ShouldNotBeNil)

		badManifest := mustJSON(t, ispec.Manifest{
			Versioned: struct {
				SchemaVersion int `json:"schemaVersion"`
			}{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.vex+json",
					Digest:    godigest.FromString("badlayer"),
					Size:      1,
				},
			},
		})

		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetBlobFn: func(repo string, digest godigest.Digest, mediaType string,
			) (io.ReadCloser, int64, error) {
				switch digest {
				case godigest.FromString("badreferrer"):
					return io.NopCloser(strings.NewReader(string(badManifest))), int64(len(badManifest)), nil
				case godigest.FromString("badlayer"):
					return io.NopCloser(strings.NewReader(string(docWithBad))), int64(len(docWithBad)), nil
				}

				return nil, -1, zerr.ErrBlobNotFound
			},
		}}

		badMeta := mocks.MetaDBMock{
			GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
				artifactTypes []string,
			) ([]mTypes.ReferrerInfo, error) {
				return []mTypes.ReferrerInfo{
					{
						Digest:       godigest.FromString("badreferrer").String(),
						MediaType:    ispec.MediaTypeImageManifest,
						ArtifactType: "application/vnd.vex+json",
					},
				}, nil
			},
		}

		vs := NewVexScanner(scannerFor(nil), store, badMeta, log.NewLogger("debug", ""))

		suppressed := vs.VexSuppressed("repo", imgDigest)
		So(suppressed, ShouldContainKey, "CVE-7")
	})
}

func TestVexProductScoping(t *testing.T) {
	imgDigest := godigest.FromString("img")
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }

	Convey("statements pinned to a different digest do not apply", t, func() {
		products := []json.RawMessage{
			raw(`"pkg:oci/other@` + godigest.FromString("other").String() + `"`),
		}
		So(productMatchesSubject(products, imgDigest), ShouldBeFalse)

		objectProducts := []json.RawMessage{
			raw(`{"@id":"pkg:oci/other@` + godigest.FromString("other").String() + `"}`),
		}
		So(productMatchesSubject(objectProducts, imgDigest), ShouldBeFalse)
	})

	Convey("statements pinned to the scanned digest apply", t, func() {
		products := []json.RawMessage{
			raw(`"pkg:oci/other@` + godigest.FromString("other").String() + `"`),
			raw(`"pkg:oci/repo@` + imgDigest.String() + `"`),
		}
		So(productMatchesSubject(products, imgDigest), ShouldBeTrue)
	})

	Convey("unpinned products apply to any subject", t, func() {
		So(productMatchesSubject([]json.RawMessage{raw(`"pkg:oci/repo@latest"`)}, imgDigest), ShouldBeTrue)
		So(productMatchesSubject(nil, imgDigest), ShouldBeTrue)
	})

	Convey("a string product array parses under the spec form", t, func() {
		stmt := vexStatement{}
		err := json.Unmarshal([]byte(`{"vulnerability":{"name":"CVE-1"},"products":["pkg:oci/repo@`+
			imgDigest.String()+`"],"status":"not_affected"}`), &stmt)
		So(err, ShouldBeNil)
		So(productMatchesSubject(stmt.Products, imgDigest), ShouldBeTrue)
	})
}
