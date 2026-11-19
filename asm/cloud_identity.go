package asm

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

var tenantIDRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// identityProviders finds the domain's Microsoft Entra ID tenant (from
// Microsoft's public sign-in endpoints) and Google Workspace or Microsoft 365
// mail (from the root domain's MX records).
func (s *Scanner) identityProviders(ctx context.Context, client *http.Client, domain string, records []DNSRecord) []IdentityProvider {
	var out []IdentityProvider
	if entra, ok := s.entraTenant(ctx, client, domain); ok {
		out = append(out, entra)
	}
	for _, r := range records {
		if r.Host != domain || r.Type != "MX" {
			continue
		}
		mx := normalizeName(r.Value)
		if f := strings.Fields(mx); len(f) > 0 { // "10 aspmx.l.google.com" in some formats
			mx = f[len(f)-1]
		}
		if strings.HasSuffix(mx, ".google.com") || strings.HasSuffix(mx, ".googlemail.com") {
			out = append(out, IdentityProvider{Domain: domain, Provider: "Google Workspace", Evidence: "mx"})
			break
		}
	}
	return out
}

// entraTenant looks up the domain's Entra tenant: its ID and region (OpenID
// configuration), how sign-in works (realm discovery) and the other domains
// in the tenant (Exchange autodiscover).
func (s *Scanner) entraTenant(ctx context.Context, client *http.Client, domain string) (IdentityProvider, bool) {
	var oidc struct {
		Issuer      string `json:"issuer"`
		RegionScope string `json:"tenant_region_scope"`
	}
	if status, body := httpGet(ctx, client, cloudURLs.entraOpenID(domain)); status != http.StatusOK ||
		json.Unmarshal(body, &oidc) != nil {
		return IdentityProvider{}, false
	}
	tenant := tenantIDRe.FindString(oidc.Issuer)
	if tenant == "" {
		return IdentityProvider{}, false
	}
	idp := IdentityProvider{Domain: domain, Provider: "Microsoft Entra ID", TenantID: tenant, TenantRegion: oidc.RegionScope, Evidence: "openid"}

	var realm struct {
		NameSpaceType       string `json:"NameSpaceType"`
		AuthURL             string `json:"AuthURL"`
		FederationBrandName string `json:"FederationBrandName"`
	}
	if status, body := httpGet(ctx, client, cloudURLs.entraRealm(domain)); status == http.StatusOK && json.Unmarshal(body, &realm) == nil {
		switch realm.NameSpaceType {
		case "Managed":
			idp.Authentication = "managed"
		case "Federated":
			idp.Authentication = "federated"
			idp.AuthURL = realm.AuthURL
		}
		idp.BrandName = realm.FederationBrandName
	}

	domains, err := tenantDomains(ctx, client, domain)
	if err != nil {
		s.opts.Logger.Warn("cloud: tenant domains unavailable", "err", err)
	}
	idp.Domains = domains
	return idp, true
}

const autodiscoverRequest = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>DOMAIN</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>`

// tenantDomains asks Exchange Online's autodiscover service which domains
// share the domain's tenant. Microsoft may return only some of them.
func tenantDomains(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body := strings.Replace(autodiscoverRequest, "DOMAIN", html.EscapeString(domain), 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cloudURLs.autodiscover, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`)
	req.Header.Set("User-Agent", "AutodiscoverClient")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return parseTenantDomains(data), nil
}

// parseTenantDomains collects the <Domain> elements inside <Domains>.
func parseTenantDomains(data []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var out []string
	inDomains := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "Domains":
				inDomains = true
			case t.Name.Local == "Domain" && inDomains:
				var d string
				if dec.DecodeElement(&d, &t) == nil {
					if d = strings.ToLower(strings.TrimSpace(d)); d != "" && !slices.Contains(out, d) {
						out = append(out, d)
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "Domains" {
				inDomains = false
			}
		}
	}
	slices.Sort(out)
	return out
}

func httpGet(ctx context.Context, client *http.Client, url string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, body
}
