package asm

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	miekgdns "github.com/miekg/dns"
)

// ErrCloudServicesNeedsCloud is returned when guessing cloud services is
// requested with the cloud stage, which reports them, turned off.
var ErrCloudServicesNeedsCloud = errors.New("guessing cloud services is part of the cloud stage, which is skipped")

// guessedServices are cloud services whose resources get a DNS name from
// their owner's choice of name, e.g. <name>.azurewebsites.net.
var guessedServices = []struct {
	suffix, provider, service string
	name                      *regexp.Regexp // names the service allows
}{
	{"azurewebsites.net", "Azure", "App Service", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,58}[a-z0-9]$`)},
	{"vault.azure.net", "Azure", "Key Vault", regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)},
	{"database.windows.net", "Azure", "SQL Database", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)},
	{"azurecr.io", "Azure", "Container Registry", regexp.MustCompile(`^[a-z0-9]{5,50}$`)},
	{"documents.azure.com", "Azure", "Cosmos DB", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,42}[a-z0-9]$`)},
	{"azure-api.net", "Azure", "API Management", regexp.MustCompile(`^[a-z][a-z0-9-]{0,48}[a-z0-9]$`)},
	{"servicebus.windows.net", "Azure", "Service Bus / Event Hubs", regexp.MustCompile(`^[a-z][a-z0-9-]{4,48}[a-z0-9]$`)},
	{"redis.cache.windows.net", "Azure", "Cache for Redis", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)},
	{"sharepoint.com", "Microsoft 365", "SharePoint", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)},
	{"appspot.com", "Google Cloud", "App Engine", regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)},
	{"firebaseio.com", "Google Cloud", "Firebase Realtime Database", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{4,28}[a-z0-9]$`)},
	{"web.app", "Google Cloud", "Firebase Hosting", regexp.MustCompile(`^[a-z0-9][a-z0-9-]{4,28}[a-z0-9]$`)},
}

// cloudServiceWords are combined with the domain's name to guess resource
// names, e.g. example-dev.
var cloudServiceWords = []string{"dev", "prod", "staging", "test", "api", "app", "web"}

// cloudNameCandidates guesses resource names from the domain: its name, its
// name with the suffix ("example-com"), and each with a common word appended
// (with and without a hyphen).
func cloudNameCandidates(domain string) []string {
	name, _, _ := strings.Cut(domain, ".")
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, base := range []string{name, strings.ReplaceAll(domain, ".", "-")} {
		add(base)
		add(strings.ReplaceAll(base, "-", "")) // for services that forbid hyphens
		for _, w := range cloudServiceWords {
			add(base + "-" + w)
			add(strings.ReplaceAll(base, "-", "") + w)
		}
	}
	return out
}

// guessCloudServices looks up cloud resources named after the domain by
// resolving <name>.<service suffix> for each guessed name, and Okta orgs by
// requesting their sign-in metadata. A service whose suffix answers for any
// name (wildcard DNS) is skipped.
func (s *Scanner) guessCloudServices(ctx context.Context, client *http.Client, domain string) ([]CloudAsset, []IdentityProvider, error) {
	q := dnsQuerier{resolvers: plainResolvers(s.dnsResolvers(domain))}
	exists := func(name string) bool {
		rrs, err := q.lookup(ctx, name, miekgdns.TypeA)
		return err == nil && len(rrs) > 0
	}
	names := cloudNameCandidates(domain)

	type probe struct {
		host, provider, service string
	}
	var probes []probe
	for _, svc := range guessedServices {
		if exists(randomLabel() + "." + svc.suffix) {
			s.opts.Logger.Info("cloud: skipping service with wildcard DNS", "suffix", svc.suffix)
			continue
		}
		for _, n := range names {
			if svc.name.MatchString(n) {
				probes = append(probes, probe{n + "." + svc.suffix, svc.provider, svc.service})
			}
		}
	}
	s.opts.Logger.Info("cloud: guessing cloud services", "names", len(probes))

	found := make([]bool, len(probes))
	forEach(ctx, probes, s.opts.DNSConcurrency, func(i int, p probe) {
		found[i] = exists(p.host)
	})
	var assets []CloudAsset
	for i, ok := range found {
		if ok {
			p := probes[i]
			assets = append(assets, CloudAsset{Host: p.host, Provider: p.provider, Service: p.service, Evidence: "guess"})
		}
	}

	oktaFound := make([]bool, len(names))
	forEach(ctx, names, s.opts.WebConcurrency, func(i int, n string) {
		status, body := httpGet(ctx, client, cloudURLs.okta(n))
		oktaFound[i] = status == http.StatusOK && strings.Contains(string(body), `"issuer"`)
	})
	var okta []IdentityProvider
	for i, ok := range oktaFound {
		if ok {
			okta = append(okta, IdentityProvider{Domain: domain, Provider: "Okta", URL: "https://" + names[i] + ".okta.com", Evidence: "guess"})
		}
	}
	return assets, okta, ctx.Err()
}
