package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/projectdiscovery/cdncheck"
)

// CloudAsset is a host running on a cloud or edge service, or a cloud
// resource named after the domain.
type CloudAsset struct {
	Host string `json:"host"`
	// IPs are the host's addresses inside the provider's ranges, for
	// Evidence "ip-range".
	IPs []string `json:"ips,omitempty"`
	// Provider is e.g. "AWS", "Azure", "Google Cloud", "Cloudflare".
	Provider string `json:"provider"`
	// Service is e.g. "EC2", "CloudFront", "App Service"; empty when only the
	// provider is known.
	Service string `json:"service,omitempty"`
	// Region is the provider's region, e.g. "us-east-1", when known.
	Region string `json:"region,omitempty"`
	// Evidence is how it was found: "ip-range" (an address in the provider's
	// published ranges), "cname" (a CNAME to the service) or "guess" (a
	// resource named after the domain, found with Options.CloudServices; it
	// may belong to someone else).
	Evidence string `json:"evidence"`
}

// IdentityProvider is a sign-in service the domain uses.
type IdentityProvider struct {
	// Domain is the domain it was looked up for.
	Domain string `json:"domain"`
	// Provider is "Microsoft Entra ID", "Google Workspace" or "Okta".
	Provider string `json:"provider"`
	// TenantID is the Entra tenant ID.
	TenantID string `json:"tenant_id,omitempty"`
	// TenantRegion is Entra's region scope, e.g. "EU".
	TenantRegion string `json:"tenant_region,omitempty"`
	// Authentication is "managed" (the provider checks passwords) or
	// "federated" (sign-in is handed to the organization's own identity
	// provider at AuthURL).
	Authentication string `json:"authentication,omitempty"`
	// AuthURL is the federated sign-in page, e.g. an ADFS server.
	AuthURL string `json:"auth_url,omitempty"`
	// BrandName is the organization name shown at sign-in.
	BrandName string `json:"brand_name,omitempty"`
	// Domains are the other domains verified in the same Entra tenant, as far
	// as Microsoft discloses them.
	Domains []string `json:"domains,omitempty"`
	// URL is the provider's address for the organization, e.g. an Okta org.
	URL string `json:"url,omitempty"`
	// Evidence is how it was found: "openid", "mx" or "guess".
	Evidence string `json:"evidence"`
}

// cloudURLs are the endpoints the cloud stage requests; tests point them at a
// local server.
var cloudURLs = struct {
	awsRanges    string
	entraOpenID  func(domain string) string
	entraRealm   func(domain string) string
	autodiscover string
	okta         func(org string) string
}{
	awsRanges: "https://ip-ranges.amazonaws.com/ip-ranges.json",
	entraOpenID: func(d string) string {
		return "https://login.microsoftonline.com/" + d + "/v2.0/.well-known/openid-configuration"
	},
	entraRealm: func(d string) string {
		// Realm discovery is per domain; the user part is a placeholder.
		return "https://login.microsoftonline.com/getuserrealm.srf?json=1&login=surface-realm-check@" + d
	},
	autodiscover: "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
	okta:         func(o string) string { return "https://" + o + ".okta.com/.well-known/openid-configuration" },
}

// discoverCloud attributes resolved hosts to cloud and edge services (by IP
// range and CNAME), and looks up the identity providers the domain uses. With
// Options.CloudServices it also guesses cloud resources named after the
// domain.
func (s *Scanner) discoverCloud(ctx context.Context, domain string, records []DNSRecord, hosts []resolvedHost) ([]CloudAsset, []IdentityProvider, error) {
	client := &http.Client{Timeout: s.opts.WebTimeout}

	assets := s.attributeHosts(ctx, client, records, hosts)
	identity := s.identityProviders(ctx, client, domain, records)

	if s.opts.CloudServices {
		guessed, okta, err := s.guessCloudServices(ctx, client, domain)
		if err != nil {
			return nil, nil, err
		}
		assets = append(assets, guessed...)
		identity = append(identity, okta...)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	slices.SortStableFunc(assets, func(a, b CloudAsset) int { return strings.Compare(a.Host, b.Host) })
	return assets, identity, nil
}

// --- host attribution ---

// cnameServices maps CNAME targets to the service behind them.
var cnameServices = []struct {
	re                *regexp.Regexp
	provider, service string
}{
	{regexp.MustCompile(`\.elb\.amazonaws\.com$`), "AWS", "Elastic Load Balancing"},
	{regexp.MustCompile(`\.cloudfront\.net$`), "AWS", "CloudFront"},
	{regexp.MustCompile(`(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$`), "AWS", "S3"},
	{regexp.MustCompile(`\.execute-api\.[a-z0-9-]+\.amazonaws\.com$`), "AWS", "API Gateway"},
	{regexp.MustCompile(`\.compute(-1)?\.amazonaws\.com$`), "AWS", "EC2"},
	{regexp.MustCompile(`\.elasticbeanstalk\.com$`), "AWS", "Elastic Beanstalk"},
	{regexp.MustCompile(`\.amplifyapp\.com$`), "AWS", "Amplify"},
	{regexp.MustCompile(`\.awsglobalaccelerator\.com$`), "AWS", "Global Accelerator"},
	{regexp.MustCompile(`\.azurewebsites\.net$`), "Azure", "App Service"},
	{regexp.MustCompile(`\.cloudapp\.(net|azure\.com)$`), "Azure", "Virtual Machines / Cloud Services"},
	{regexp.MustCompile(`\.blob\.core\.windows\.net$`), "Azure", "Blob Storage"},
	{regexp.MustCompile(`\.web\.core\.windows\.net$`), "Azure", "Storage static website"},
	{regexp.MustCompile(`\.azureedge\.net$`), "Azure", "CDN"},
	{regexp.MustCompile(`\.azurefd\.net$`), "Azure", "Front Door"},
	{regexp.MustCompile(`\.trafficmanager\.net$`), "Azure", "Traffic Manager"},
	{regexp.MustCompile(`\.azure-api\.net$`), "Azure", "API Management"},
	{regexp.MustCompile(`\.azurestaticapps\.net$`), "Azure", "Static Web Apps"},
	{regexp.MustCompile(`\.azurecontainerapps\.io$`), "Azure", "Container Apps"},
	{regexp.MustCompile(`\.appspot\.com$`), "Google Cloud", "App Engine"},
	{regexp.MustCompile(`\.run\.app$`), "Google Cloud", "Cloud Run"},
	{regexp.MustCompile(`(^|\.)storage\.googleapis\.com$`), "Google Cloud", "Cloud Storage"},
	{regexp.MustCompile(`(\.web\.app|\.firebaseapp\.com)$`), "Google Cloud", "Firebase Hosting"},
	{regexp.MustCompile(`^ghs\.googlehosted\.com$`), "Google", "Google-hosted site"},
	{regexp.MustCompile(`\.herokuapp\.com$|\.herokudns\.com$`), "Heroku", ""},
	{regexp.MustCompile(`\.vercel-dns\.com$|\.vercel\.app$`), "Vercel", ""},
	{regexp.MustCompile(`\.netlify\.(app|com)$|\.netlifyglobalcdn\.com$`), "Netlify", ""},
	{regexp.MustCompile(`\.github\.io$`), "GitHub", "Pages"},
	{regexp.MustCompile(`\.fastly\.net$`), "Fastly", "CDN"},
	{regexp.MustCompile(`\.(akamaiedge|edgekey|edgesuite|akamaized)\.net$`), "Akamai", "CDN"},
	{regexp.MustCompile(`\.cdn\.cloudflare\.net$`), "Cloudflare", "CDN"},
}

// cdncheckProviders names cdncheck's provider keys.
var cdncheckProviders = map[string]string{
	"aws": "AWS", "amazon": "AWS", "cloudfront": "AWS", "azure": "Azure", "office365": "Microsoft 365",
	"google": "Google Cloud", "oracle": "Oracle Cloud", "cloudflare": "Cloudflare", "fastly": "Fastly",
	"akamai": "Akamai", "incapsula": "Imperva", "zscaler": "Zscaler", "edgecast": "Edgecast",
}

// awsServiceNames prettifies AWS ip-ranges.json service codes.
var awsServiceNames = map[string]string{
	"EC2": "EC2", "CLOUDFRONT": "CloudFront", "S3": "S3", "API_GATEWAY": "API Gateway",
	"GLOBALACCELERATOR": "Global Accelerator", "ROUTE53": "Route 53", "ROUTE53_HEALTHCHECKS": "Route 53",
	"DYNAMODB": "DynamoDB", "CODEBUILD": "CodeBuild", "WORKSPACES_GATEWAYS": "WorkSpaces",
	"EBS": "EBS", "KINESIS_VIDEO_STREAMS": "Kinesis Video Streams", "CHIME_VOICECONNECTOR": "Chime",
	"AMAZON_APPFLOW": "AppFlow", "AMAZON_CONNECT": "Connect", "CLOUD9": "Cloud9", "EC2_INSTANCE_CONNECT": "EC2",
}

type awsRange struct {
	prefix          netip.Prefix
	service, region string
}

// attributeHosts labels each host by the service its CNAME points at and the
// provider whose published ranges contain its addresses.
func (s *Scanner) attributeHosts(ctx context.Context, client *http.Client, records []DNSRecord, hosts []resolvedHost) []CloudAsset {
	var out []CloudAsset
	cnames := map[string][]string{}
	for _, r := range records {
		if r.Type == "CNAME" {
			cnames[r.Host] = append(cnames[r.Host], normalizeName(r.Value))
		}
	}
	var hostNames []string
	for h := range cnames {
		hostNames = append(hostNames, h)
	}
	slices.Sort(hostNames)
	for _, h := range hostNames {
		if p, svc, ok := cnameService(cnames[h]); ok {
			out = append(out, CloudAsset{Host: h, Provider: p, Service: svc, Evidence: "cname"})
		}
	}

	aws, err := fetchAWSRanges(ctx, client)
	if err != nil {
		s.opts.Logger.Warn("cloud: AWS ranges unavailable; AWS services won't be named", "err", err)
	}
	cdn := cdncheck.New()
	for _, h := range hosts {
		// One asset per provider/service/region, listing the host's IPs in it.
		byKey := map[string]*CloudAsset{}
		var order []string
		for _, raw := range h.IPs {
			a, ok := attributeIP(cdn, aws, raw)
			if !ok {
				continue
			}
			k := a.Provider + "\x00" + a.Service + "\x00" + a.Region
			if byKey[k] == nil {
				a.Host, a.Evidence = h.Host, "ip-range"
				byKey[k] = &a
				order = append(order, k)
			}
			byKey[k].IPs = append(byKey[k].IPs, raw)
		}
		for _, k := range order {
			out = append(out, *byKey[k])
		}
	}
	return out
}

func cnameService(targets []string) (provider, service string, ok bool) {
	// The last CNAME in the chain is the most specific.
	for i := len(targets) - 1; i >= 0; i-- {
		for _, c := range cnameServices {
			if c.re.MatchString(targets[i]) {
				return c.provider, c.service, true
			}
		}
	}
	return "", "", false
}

// attributeIP finds the provider (and, for AWS, the service and region) of ip.
func attributeIP(cdn *cdncheck.Client, aws []awsRange, ip string) (CloudAsset, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return CloudAsset{}, false
	}
	// AWS ranges name the service: a prefix naming one (EC2, CloudFront...)
	// wins over the generic AMAZON, then the longest prefix.
	var best *awsRange
	for i := range aws {
		r := &aws[i]
		if !r.prefix.Contains(addr) {
			continue
		}
		if best == nil || (r.service != "") != (best.service != "") && r.service != "" ||
			(r.service != "") == (best.service != "") && r.prefix.Bits() > best.prefix.Bits() {
			best = r
		}
	}
	if best != nil {
		return CloudAsset{Provider: "AWS", Service: best.service, Region: best.region}, true
	}
	if cdn == nil {
		return CloudAsset{}, false
	}
	matched, value, itemType, err := cdn.Check(net.ParseIP(ip))
	if err != nil || !matched || value == "" {
		return CloudAsset{}, false
	}
	a := CloudAsset{Provider: cdncheckProviders[value]}
	if a.Provider == "" {
		a.Provider = value
	}
	switch {
	case value == "cloudfront":
		a.Service = "CloudFront"
	case itemType == "cdn":
		a.Service = "CDN"
	case itemType == "waf":
		a.Service = "WAF"
	}
	return a, true
}

// fetchAWSRanges downloads AWS's published IP ranges, keeping the prefixes
// that name a service.
func fetchAWSRanges(ctx context.Context, client *http.Client) ([]awsRange, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudURLs.awsRanges, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	var out []awsRange
	add := func(prefix, service, region string) {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return
		}
		name := ""
		if service != "AMAZON" {
			if name = awsServiceNames[service]; name == "" {
				name = service
			}
		}
		if region == "GLOBAL" {
			region = ""
		}
		out = append(out, awsRange{prefix: p, service: name, region: region})
	}
	for _, p := range doc.Prefixes {
		add(p.Prefix, p.Service, p.Region)
	}
	for _, p := range doc.IPv6 {
		add(p.Prefix, p.Service, p.Region)
	}
	// Generic AMAZON entries cover the same prefixes as specific ones; drop
	// them where a named service has the identical prefix.
	named := map[netip.Prefix]bool{}
	for _, r := range out {
		if r.service != "" {
			named[r.prefix] = true
		}
	}
	out = slices.DeleteFunc(out, func(r awsRange) bool { return r.service == "" && named[r.prefix] })
	return out, nil
}

// CloudDiff lists cloud assets and tenant domains that appeared or went away.
type CloudDiff struct {
	// Compared is false unless both scans ran the cloud stage.
	Compared bool                `json:"compared"`
	Assets   SetDiff[CloudAsset] `json:"assets"`
	// TenantDomains are domains added to or removed from the Entra tenant.
	TenantDomains SetDiff[string] `json:"tenant_domains"`
}

func compareCloud(prev, cur *Result) CloudDiff {
	d := CloudDiff{
		Assets:        SetDiff[CloudAsset]{Added: []CloudAsset{}, Removed: []CloudAsset{}},
		TenantDomains: SetDiff[string]{Added: []string{}, Removed: []string{}},
	}
	if !prev.ran(StageCloud) || !cur.ran(StageCloud) {
		return d
	}
	d.Compared = true
	d.Assets = setDiff(prev.CloudAssets, cur.CloudAssets, func(a CloudAsset) string {
		return strings.Join([]string{a.Host, a.Provider, a.Service, a.Region, a.Evidence}, "\x00")
	})
	d.TenantDomains = setDiff(tenantDomainList(prev), tenantDomainList(cur), func(s string) string { return s })
	return d
}

func tenantDomainList(r *Result) []string {
	var out []string
	for _, idp := range r.Identity {
		for _, d := range idp.Domains {
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}
