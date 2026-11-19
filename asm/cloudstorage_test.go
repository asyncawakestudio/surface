package asm

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestBucketCandidates(t *testing.T) {
	got := bucketCandidates("example.com")
	for _, want := range []string{"example", "example-backups", "backups-example", "example-com", "example-com-static", "example.com", "example.com-dev"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if len(got) != 3*(1+2*len(bucketWords)) {
		t.Errorf("%d candidates", len(got))
	}
	az := azureAccountCandidates("my-shop.example")
	if az[0] != "myshop" || !slices.Contains(az, "myshopexample") || !slices.Contains(az, "myshopbackups") {
		t.Errorf("azure = %v", az)
	}
}

func TestCountListing(t *testing.T) {
	for body, want := range map[string]string{
		`<ListBucketResult><Name>b</Name><Contents><Key>a</Key></Contents><Contents><Key>b</Key></Contents></ListBucketResult>`: "2 true",
		`<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>x</Name></Blob></Blobs></EnumerationResults>`:              "1 true",
		`<Error><Code>AccessDenied</Code></Error>`: "0 false",
		`<html><body>site</body></html>`:           "0 false",
		`not xml`:                                  "0 false",
	} {
		n, ok := countListing([]byte(body))
		if got := fmt.Sprint(n, " ", ok); got != want {
			t.Errorf("countListing(%s) = %s, want %s", body, got, want)
		}
	}
}

func TestFindPublicBuckets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s3/example-backups/": // public
			fmt.Fprint(w, `<ListBucketResult><Contents><Key>db.sql.gz</Key></Contents></ListBucketResult>`)
		case "/s3/example-assets/": // exists, private
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<Error><Code>AccessDenied</Code></Error>`)
		case "/gcs/example-com-static/": // public, empty
			fmt.Fprint(w, `<ListBucketResult></ListBucketResult>`)
		case "/gcs/example-www/": // static website, not a listing
			fmt.Fprint(w, `<html>hi</html>`)
		case "/azure/examplemedia/": // the account exists
			w.WriteHeader(http.StatusForbidden)
		case "/azure/examplemedia/images":
			fmt.Fprint(w, `<EnumerationResults><Blobs><Blob/><Blob/><Blob/></Blobs></EnumerationResults>`)
		default:
			if strings.HasPrefix(r.URL.Path, "/azure/") && strings.Count(r.URL.Path, "/") == 3 && strings.HasSuffix(r.URL.Path, "/") {
				// unknown account: emulate a DNS failure by closing the connection
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
		}
	}))
	defer srv.Close()
	old := cloudEndpoints
	defer func() { cloudEndpoints = old }()
	cloudEndpoints.s3 = func(b string) string { return srv.URL + "/s3/" + b + "/" }
	cloudEndpoints.gcs = func(b string) string { return srv.URL + "/gcs/" + b + "/" }
	cloudEndpoints.azureAccount = func(a string) string { return srv.URL + "/azure/" + a + "/" }
	cloudEndpoints.azureList = func(a, c string) string { return srv.URL + "/azure/" + a + "/" + c + "?restype=container&comp=list" }

	got, err := New(Options{}).findPublicBuckets(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, b := range got {
		lines = append(lines, fmt.Sprintf("%s %s %d", b.provider, strings.TrimPrefix(b.url, srv.URL), b.objects))
	}
	slices.Sort(lines)
	want := []string{
		"AWS S3 /s3/example-backups/ 1",
		"Azure Blob Storage /azure/examplemedia/images 3",
		"Google Cloud Storage /gcs/example-com-static/ 0",
	}
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Errorf("got %v\nwant %v", lines, want)
	}

	m := publicBucket{provider: "AWS S3", url: "https://example-backups.s3.amazonaws.com/", objects: 1}.misconfig("example.com")
	if m.Host != "example-backups.s3.amazonaws.com" || m.Check != "public_bucket" || m.Severity != "high" || m.Service != "AWS S3" ||
		!strings.Contains(m.Detail, "may not be yours") {
		t.Errorf("misconfig = %+v", m)
	}
}

func TestRunCloudStorageNeedsMisconfig(t *testing.T) {
	_, err := New(Options{CloudStorage: true, SkipMisconfig: true}).Run(t.Context(), Target{Domain: "example.com"}, nil)
	if err != ErrCloudStorageNeedsMisconfig {
		t.Fatalf("err = %v", err)
	}
}
