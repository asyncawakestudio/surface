package asm

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ErrCloudStorageNeedsCloud is returned when the cloud storage check is
// requested with the cloud stage, which reports it, turned off.
var ErrCloudStorageNeedsCloud = errors.New("the cloud storage check is part of the cloud stage, which is skipped")

// bucketWords are combined with the domain's name to guess bucket names.
var bucketWords = []string{
	"assets", "backup", "backups", "cdn", "data", "dev", "files", "images",
	"logs", "media", "prod", "public", "staging", "static", "test", "uploads", "www",
}

// azureContainers are the container names tried on Azure storage accounts
// named after the domain.
var azureContainers = []string{"public", "assets", "static", "images", "media", "files", "uploads", "backup", "backups", "data"}

// cloudEndpoints builds the URLs the check requests; tests point them at a
// local server.
var cloudEndpoints = struct {
	s3, gcs      func(bucket string) string
	azureAccount func(account string) string
	azureList    func(account, container string) string
}{
	s3: func(b string) string {
		if strings.Contains(b, ".") { // dots break the virtual-host certificate
			return "https://s3.amazonaws.com/" + b + "/"
		}
		return "https://" + b + ".s3.amazonaws.com/"
	},
	gcs:          func(b string) string { return "https://storage.googleapis.com/" + b + "/" },
	azureAccount: func(a string) string { return "https://" + a + ".blob.core.windows.net/?comp=list" },
	azureList: func(a, c string) string {
		return "https://" + a + ".blob.core.windows.net/" + c + "?restype=container&comp=list"
	},
}

var (
	bucketNameRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	azureAccountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
)

// bucketCandidates guesses bucket names from the domain: its name
// ("example"), its name with the suffix ("example-com", "example.com"), and
// each of those with a common word before or after it.
func bucketCandidates(domain string) []string {
	name, _, _ := strings.Cut(domain, ".")
	bases := []string{name, strings.ReplaceAll(domain, ".", "-"), domain}
	var out []string
	seen := map[string]bool{}
	add := func(b string) {
		if !seen[b] && bucketNameRe.MatchString(b) && !strings.Contains(b, "..") {
			seen[b] = true
			out = append(out, b)
		}
	}
	for _, base := range bases {
		add(base)
		for _, w := range bucketWords {
			add(base + "-" + w)
			add(w + "-" + base)
		}
	}
	return out
}

// azureAccountCandidates guesses Azure storage account names, which allow
// only lowercase letters and digits.
func azureAccountCandidates(domain string) []string {
	name, _, _ := strings.Cut(domain, ".")
	name = strings.ReplaceAll(name, "-", "")
	full := strings.NewReplacer(".", "", "-", "").Replace(domain)
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] && azureAccountNameRe.MatchString(a) {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, base := range []string{name, full} {
		add(base)
		for _, w := range bucketWords {
			add(base + w)
		}
	}
	return out
}

// PublicBucket is a storage bucket or container named after the domain that
// anyone can list. It may belong to someone else.
type PublicBucket struct {
	// Provider is "AWS S3", "Google Cloud Storage" or "Azure Blob Storage".
	Provider string `json:"provider"`
	URL      string `json:"url"`
	// Objects is the number of objects in the first page of the listing.
	Objects int `json:"objects"`
}

// findPublicBuckets requests the bucket names guessed from domain on AWS S3,
// Google Cloud Storage and Azure Blob Storage, anonymously, and returns those
// that list their contents. Only listings are read, never objects.
func (s *Scanner) findPublicBuckets(ctx context.Context, domain string) ([]PublicBucket, error) {
	client := &http.Client{
		Timeout:       s.opts.WebTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(url string) (int, []byte, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, nil, false
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, body, true
	}

	type probe struct {
		provider, url string
	}
	var probes []probe
	buckets := bucketCandidates(domain)
	for _, b := range buckets {
		probes = append(probes, probe{"AWS S3", cloudEndpoints.s3(b)}, probe{"Google Cloud Storage", cloudEndpoints.gcs(b)})
	}
	accounts := azureAccountCandidates(domain)
	s.opts.Logger.Info("cloud: checking cloud storage", "buckets", len(buckets), "azure_accounts", len(accounts))

	found := make([]*PublicBucket, len(probes))
	forEach(ctx, probes, s.opts.WebConcurrency, func(i int, p probe) {
		if status, body, ok := get(p.url); ok && status == http.StatusOK {
			if n, ok := countListing(body); ok {
				found[i] = &PublicBucket{Provider: p.provider, URL: p.url, Objects: n}
			}
		}
	})

	// Azure: find the accounts that exist (any HTTP answer), then try
	// listing common containers on them.
	exists := make([]bool, len(accounts))
	forEach(ctx, accounts, s.opts.WebConcurrency, func(i int, a string) {
		_, _, exists[i] = get(cloudEndpoints.azureAccount(a))
	})
	var containers []probe
	for i, a := range accounts {
		if exists[i] {
			for _, c := range azureContainers {
				containers = append(containers, probe{"Azure Blob Storage", cloudEndpoints.azureList(a, c)})
			}
		}
	}
	azure := make([]*PublicBucket, len(containers))
	forEach(ctx, containers, s.opts.WebConcurrency, func(i int, p probe) {
		if status, body, ok := get(p.url); ok && status == http.StatusOK {
			if n, ok := countListing(body); ok {
				azure[i] = &PublicBucket{Provider: p.provider, URL: strings.TrimSuffix(p.url, "?restype=container&comp=list"), Objects: n}
			}
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var out []PublicBucket
	for _, b := range append(found, azure...) {
		if b != nil {
			out = append(out, *b)
		}
	}
	return out, nil
}

// countListing parses an S3/GCS ListBucketResult or an Azure
// EnumerationResults document and counts the objects in it. ok is false for
// anything else, such as an error page or a website served from the bucket.
func countListing(body []byte) (int, bool) {
	var doc struct {
		XMLName  xml.Name
		Contents []struct{} `xml:"Contents"`
		Blobs    struct {
			Blob []struct{} `xml:"Blob"`
		} `xml:"Blobs"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		return 0, false
	}
	switch doc.XMLName.Local {
	case "ListBucketResult":
		return len(doc.Contents), true
	case "EnumerationResults":
		return len(doc.Blobs.Blob), true
	}
	return 0, false
}
