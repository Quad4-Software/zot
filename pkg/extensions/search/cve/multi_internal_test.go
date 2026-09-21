//go:build search

package cveinfo

import (
	"context"
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func cveFinding(id, severity, pkgName string) zcommon.CVE {
	return zcommon.CVE{
		ID:       id,
		Severity: severity,
		PackageList: []zcommon.Package{
			{Name: pkgName, InstalledVersion: "1.0", FixedVersion: "1.1"},
		},
	}
}

func scannerReturning(cves map[string]zcommon.CVE, err error) mocks.CveScannerMock {
	return mocks.CveScannerMock{
		ScanImageFn: func(ctx context.Context, image string) (cvemodel.ScanResult, error) {
			if err != nil {
				return cvemodel.ScanResult{}, err
			}

			return cvemodel.ScanResult{CVEMap: cves, Digest: "sha256:abc"}, nil
		},
		IsResultCachedFn: func(repo, digest string) bool {
			return true
		},
		GetCachedResultFn: func(repo, digest string) map[string]zcommon.CVE {
			return cves
		},
	}
}

func TestMultiScanner(t *testing.T) {
	Convey("merged scan results", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerReturning(map[string]zcommon.CVE{
				"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
				"CVE-2": cveFinding("CVE-2", cvemodel.SeverityLow, "libb"),
			}, nil)),
			namedBackend("grype", scannerReturning(map[string]zcommon.CVE{
				"CVE-2": cveFinding("CVE-2", cvemodel.SeverityCritical, "libb"),
				"CVE-3": cveFinding("CVE-3", cvemodel.SeverityMedium, "libc"),
			}, nil)),
		}, log.NewLogger("debug", ""))

		result, err := multi.ScanImage(context.Background(), "repo:tag")
		So(err, ShouldBeNil)
		So(result.CVEMap, ShouldHaveLength, 3)

		// severity merge keeps the higher finding
		So(result.CVEMap["CVE-2"].Severity, ShouldEqual, cvemodel.SeverityCritical)

		names := multi.ScannerNames()
		So(names, ShouldResemble, []string{"trivy", "grype"})
	})

	Convey("per-scanner results preserve disagreements", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerReturning(map[string]zcommon.CVE{
				"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
			}, nil)),
			namedBackend("grype", scannerReturning(map[string]zcommon.CVE{
				"CVE-3": cveFinding("CVE-3", cvemodel.SeverityMedium, "libc"),
			}, nil)),
		}, log.NewLogger("debug", ""))

		results, errs := multi.ScanPerScanner(context.Background(), "repo:tag")
		So(errs, ShouldBeEmpty)
		So(results, ShouldHaveLength, 2)
		So(results["trivy"].CVEMap, ShouldContainKey, "CVE-1")
		So(results["trivy"].CVEMap, ShouldNotContainKey, "CVE-3")
		So(results["grype"].CVEMap, ShouldContainKey, "CVE-3")
	})

	Convey("one backend failing still returns the other's results", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerReturning(nil, errors.New("db missing"))),
			namedBackend("grype", scannerReturning(map[string]zcommon.CVE{
				"CVE-3": cveFinding("CVE-3", cvemodel.SeverityMedium, "libc"),
			}, nil)),
		}, log.NewLogger("debug", ""))

		result, err := multi.ScanImage(context.Background(), "repo:tag")
		So(err, ShouldBeNil)
		So(result.CVEMap, ShouldHaveLength, 1)
		So(result.CVEMap, ShouldContainKey, "CVE-3")
	})

	Convey("all backends failing returns error", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerReturning(nil, errors.New("a"))),
			namedBackend("grype", scannerReturning(nil, errors.New("b"))),
		}, log.NewLogger("debug", ""))

		_, err := multi.ScanImage(context.Background(), "repo:tag")
		So(err, ShouldNotBeNil)
	})

	Convey("IsResultCached requires all backends", t, func() {
		cached := scannerReturning(nil, nil)
		cached.IsResultCachedFn = func(repo, digest string) bool { return true }

		uncached := scannerReturning(nil, nil)
		uncached.IsResultCachedFn = func(repo, digest string) bool { return false }

		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", cached),
			namedBackend("grype", uncached),
		}, log.NewLogger("debug", ""))

		So(multi.IsResultCached("repo", "sha256:x"), ShouldBeFalse)
	})

	Convey("GetCachedResult merges cached maps", t, func() {
		multi := NewMultiScanner([]namedScanner{
			namedBackend("trivy", scannerReturning(map[string]zcommon.CVE{
				"CVE-1": cveFinding("CVE-1", cvemodel.SeverityHigh, "liba"),
			}, nil)),
			namedBackend("grype", scannerReturning(map[string]zcommon.CVE{
				"CVE-3": cveFinding("CVE-3", cvemodel.SeverityMedium, "libc"),
			}, nil)),
		}, log.NewLogger("debug", ""))

		cached := multi.GetCachedResult("repo", "sha256:x")
		So(cached, ShouldHaveLength, 2)
	})
}
