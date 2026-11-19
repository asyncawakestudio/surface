package asm

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/cdncheck"
)

// fakeCloud serves AWS ranges, Entra sign-in endpoints, autodiscover and
// Okta metadata, and points cloudURLs at it for the test.
func fakeCloud(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/aws":
			fmt.Fprint(w, `{"prefixes":[
				{"ip_prefix":"203.0.113.0/24","region":"us-east-1","service":"AMAZON"},
				{"ip_prefix":"203.0.113.0/24","region":"us-east-1","service":"EC2"},
				{"ip_prefix":"198.51.100.0/24","region":"GLOBAL","service":"AMAZON"},
				{"ip_prefix":"198.51.100.128/25","region":"GLOBAL","service":"CLOUDFRONT"}],
				"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"eu-west-1","service":"S3"}]}`)
		case r.URL.Path == "/entra/example.com/openid":
			fmt.Fprint(w, `{"issuer":"https://login.microsoftonline.com/0e7f1b6a-1234-4c5d-8e9f-0123456789ab/v2.0","tenant_region_scope":"EU"}`)
		case strings.HasPrefix(r.URL.Path, "/entra/") && strings.HasSuffix(r.URL.Path, "/openid"):
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_tenant"}`)
		case r.URL.Path == "/entra/example.com/realm":
			fmt.Fprint(w, `{"NameSpaceType":"Federated","AuthURL":"https://adfs.example.com/adfs/ls/","FederationBrandName":"Example Corp"}`)
		case r.URL.Path == "/autodiscover":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "<Domain>example.com</Domain>") || r.Header.Get("SOAPAction") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
				<GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Response>
				<ApplicationUri>urn:federation:MicrosoftOnline</ApplicationUri>
				<Domains><Domain>example.com</Domain><Domain>Example.co.uk</Domain><Domain>example.onmicrosoft.com</Domain></Domains>
				</Response></GetFederationInformationResponseMessage></s:Body></s:Envelope>`)
		case r.URL.Path == "/okta/example":
			fmt.Fprint(w, `{"issuer":"https://example.okta.com"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	old := cloudURLs
	t.Cleanup(func() { cloudURLs = old })
	cloudURLs.awsRanges = srv.URL + "/aws"
	cloudURLs.entraOpenID = func(d string) string { return srv.URL + "/entra/" + d + "/openid" }
	cloudURLs.entraRealm = func(d string) string { return srv.URL + "/entra/" + d + "/realm" }
	cloudURLs.autodiscover = srv.URL + "/autodiscover"
	cloudURLs.okta = func(o string) string { return srv.URL + "/okta/" + o }
	return srv
}

func TestAttributeHosts(t *testing.T) {
	fakeCloud(t)
	records := []DNSRecord{
		{Host: "app.example.com", Type: "CNAME", Value: "example-app.azurewebsites.net."},
		{Host: "lb.example.com", Type: "CNAME", Value: "www.example.com"},
		{Host: "lb.example.com", Type: "CNAME", Value: "my-lb-123.us-east-1.elb.amazonaws.com"},
		{Host: "www.example.com", Type: "CNAME", Value: "www.unknown-host.example"},
	}
	hosts := []resolvedHost{
		{Host: "api.example.com", IPs: []string{"203.0.113.5", "203.0.113.6"}},
		{Host: "cdn.example.com", IPs: []string{"198.51.100.200"}},
		{Host: "files.example.com", IPs: []string{"2001:db8::1"}},
		{Host: "cf.example.com", IPs: []string{"104.16.0.1"}}, // Cloudflare, from cdncheck's data
		{Host: "home.example.com", IPs: []string{"192.0.2.1"}},
	}
	got := New(Options{}).attributeHosts(t.Context(), &http.Client{}, records, hosts)
	var lines []string
	for _, a := range got {
		lines = append(lines, fmt.Sprintf("%s %v %s/%s/%s %s", a.Host, a.IPs, a.Provider, a.Service, a.Region, a.Evidence))
	}
	want := []string{
		"app.example.com [] Azure/App Service/ cname",
		"lb.example.com [] AWS/Elastic Load Balancing/ cname",
		"api.example.com [203.0.113.5 203.0.113.6] AWS/EC2/us-east-1 ip-range",
		"cdn.example.com [198.51.100.200] AWS/CloudFront/ ip-range",
		"files.example.com [2001:db8::1] AWS/S3/eu-west-1 ip-range",
		"cf.example.com [104.16.0.1] Cloudflare/WAF/ ip-range",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestAttributeIPWithoutAWSRanges(t *testing.T) {
	// Without AWS's ranges, cdncheck still names the provider.
	a, ok := attributeIP(cdncheck.New(), nil, "104.16.0.1")
	if !ok || a.Provider != "Cloudflare" {
		t.Errorf("got %+v, %v", a, ok)
	}
	if _, ok := attributeIP(cdncheck.New(), nil, "192.0.2.1"); ok {
		t.Error("documentation address attributed")
	}
}

func TestEntraTenant(t *testing.T) {
	fakeCloud(t)
	records := []DNSRecord{{Host: "example.com", Type: "MX", Value: "aspmx.l.google.com"}}
	got := New(Options{}).identityProviders(t.Context(), &http.Client{}, "example.com", records)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	e := got[0]
	if e.Provider != "Microsoft Entra ID" || e.TenantID != "0e7f1b6a-1234-4c5d-8e9f-0123456789ab" || e.TenantRegion != "EU" ||
		e.Authentication != "federated" || e.AuthURL != "https://adfs.example.com/adfs/ls/" || e.BrandName != "Example Corp" ||
		fmt.Sprint(e.Domains) != "[example.co.uk example.com example.onmicrosoft.com]" || e.Evidence != "openid" {
		t.Errorf("entra = %+v", e)
	}
	if g := got[1]; g.Provider != "Google Workspace" || g.Evidence != "mx" {
		t.Errorf("google = %+v", g)
	}

	// No tenant, no Google MX: nothing.
	if got := New(Options{}).identityProviders(t.Context(), &http.Client{}, "other.example", nil); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestGuessCloudServices(t *testing.T) {
	fakeCloud(t)
	resolver := bruteZone(t, map[string]string{
		"example-dev.azurewebsites.net": "192.0.2.10",
		"example.vault.azure.net":       "192.0.2.11",
		"examplecom.azurecr.io":         "192.0.2.12",
		"example.sharepoint.com":        "192.0.2.13",
	}, "")
	assets, okta, err := New(Options{Resolvers: []string{resolver}}).guessCloudServices(t.Context(), &http.Client{}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, a := range assets {
		lines = append(lines, fmt.Sprintf("%s %s/%s %s", a.Host, a.Provider, a.Service, a.Evidence))
	}
	want := []string{
		"example-dev.azurewebsites.net Azure/App Service guess",
		"example.vault.azure.net Azure/Key Vault guess",
		"examplecom.azurecr.io Azure/Container Registry guess",
		"example.sharepoint.com Microsoft 365/SharePoint guess",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if len(okta) != 1 || okta[0].URL != "https://example.okta.com" || okta[0].Evidence != "guess" {
		t.Errorf("okta = %+v", okta)
	}
}

func TestGuessCloudServicesSkipsWildcards(t *testing.T) {
	fakeCloud(t)
	// Every name resolves: no service can be told apart.
	resolver := bruteZone(t, nil, "192.0.2.99")
	assets, _, err := New(Options{Resolvers: []string{resolver}}).guessCloudServices(t.Context(), &http.Client{}, "example.com")
	if err != nil || len(assets) != 0 {
		t.Errorf("got %+v, %v", assets, err)
	}
}

func TestCompareCloud(t *testing.T) {
	asset := func(h string) CloudAsset {
		return CloudAsset{Host: h, Provider: "AWS", Service: "EC2", Evidence: "ip-range"}
	}
	idp := func(domains ...string) []IdentityProvider {
		return []IdentityProvider{{Provider: "Microsoft Entra ID", TenantID: "t", Domains: domains}}
	}
	prev := &Result{Stages: []Stage{StageCloud}, CloudAssets: []CloudAsset{asset("a"), asset("old")}, Identity: idp("example.com", "old.example")}
	cur := &Result{Stages: []Stage{StageCloud}, CloudAssets: []CloudAsset{asset("a"), asset("new")}, Identity: idp("example.com", "new.example")}
	d := Compare(prev, cur).Cloud
	if !d.Compared || fmt.Sprint(d.Assets.Added) != fmt.Sprint([]CloudAsset{asset("new")}) ||
		fmt.Sprint(d.TenantDomains.Added) != "[new.example]" || fmt.Sprint(d.TenantDomains.Removed) != "[old.example]" {
		t.Errorf("diff = %+v", d)
	}
	if d := Compare(&Result{Stages: []Stage{StageDNS}}, cur); d.Cloud.Compared || !d.Empty() {
		t.Errorf("diff = %+v", d.Cloud)
	}
}

func TestRunCloudServicesNeedsCloud(t *testing.T) {
	_, err := New(Options{CloudServices: true, SkipCloud: true}).Run(t.Context(), Target{Domain: "example.com"}, nil)
	if err != ErrCloudServicesNeedsCloud {
		t.Fatalf("err = %v", err)
	}
}
