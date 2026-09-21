//go:build search

package cveinfo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

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

	return mustJSON(t, vexDoc{Statements: []vexStatement{
		{Vulnerability: vexVulnerability{Name: "CVE-1"}, Status: "not_affected"},
		{Vulnerability: vexVulnerability{Name: "CVE-2"}, Status: "fixed"},
		{Vulnerability: vexVulnerability{Name: "CVE-3"}, Status: "under_investigation"},
		{Vulnerability: vexVulnerability{ID: "https://nvd.nist.gov/vuln/detail/CVE-4"}, Status: "not_affected"},
	}})
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

	makeStore := func() storage.StoreController {
		return storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				switch digest {
				case godigest.FromString("referrer"):
					return manifestBlob, nil
				case godigest.FromString("layer"):
					return layerBlob, nil
				}

				return nil, nil
			},
		}}
	}

	metaDB := mocks.MetaDBMock{
		GetReferrersInfoFn: func(repo string, referredDigest godigest.Digest,
			artifactTypes []string,
		) ([]mTypes.ReferrerInfo, error) {
			return []mTypes.ReferrerInfo{
				{Digest: godigest.FromString("referrer").String(), MediaType: ispec.MediaTypeImageManifest},
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
}
