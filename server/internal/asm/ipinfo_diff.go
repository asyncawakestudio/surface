package asm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// IPInfoDiff lists IPs that appeared or disappeared and IPs whose ipinfo
// data changed (new owner, ASN, location...).
type IPInfoDiff struct {
	// Compared is false when the previous scan predates IP lookups, so there
	// is no baseline and nothing else in the diff is meaningful.
	Compared bool `json:"compared"`
	SetDiff[IPInfo]
	Changed []IPInfoChange `json:"changed"`
}

// IPInfoChange is an IP present in both scans with different ipinfo data.
type IPInfoChange struct {
	IP     string        `json:"ip"`
	Fields []FieldChange `json:"fields"`
}

// FieldChange is one flattened ipinfo field ("asn.name") that changed. An
// empty Before or After means the field was absent on that side.
type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// ignoredIPInfoFields never count as changes.
var ignoredIPInfoFields = map[string]bool{"ip": true, "readme": true}

func compareIPInfo(prev, cur *Result) IPInfoDiff {
	d := IPInfoDiff{
		SetDiff: SetDiff[IPInfo]{Added: []IPInfo{}, Removed: []IPInfo{}},
		Changed: []IPInfoChange{},
	}
	if len(prev.IPInfo) == 0 && hasPublicAddress(prev.DNSRecords) {
		return d // previous scan ran before IP lookups existed
	}
	d.Compared = true
	d.SetDiff = setDiff(prev.IPInfo, cur.IPInfo, func(i IPInfo) string { return i.IP })

	before := make(map[string]IPInfo, len(prev.IPInfo))
	for _, info := range prev.IPInfo {
		before[info.IP] = info
	}
	for _, info := range cur.IPInfo {
		old, ok := before[info.IP]
		// A failed lookup on either side says nothing about a change.
		if !ok || old.Error != "" || info.Error != "" {
			continue
		}
		if fields := diffFields(flattenJSON(old.Data), flattenJSON(info.Data)); len(fields) > 0 {
			d.Changed = append(d.Changed, IPInfoChange{IP: info.IP, Fields: fields})
		}
	}
	slices.SortFunc(d.Changed, func(a, b IPInfoChange) int { return strings.Compare(a.IP, b.IP) })
	return d
}

func hasPublicAddress(records []DNSRecord) bool {
	var ips []string
	for _, r := range records {
		if r.Type == "A" || r.Type == "AAAA" {
			ips = append(ips, r.Value)
		}
	}
	return len(publicIPs([]resolvedHost{{IPs: ips}})) > 0
}

func diffFields(before, after map[string]string) []FieldChange {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var out []FieldChange
	for k := range keys {
		if ignoredIPInfoFields[k] || before[k] == after[k] {
			continue
		}
		out = append(out, FieldChange{Field: k, Before: before[k], After: after[k]})
	}
	slices.SortFunc(out, func(a, b FieldChange) int { return strings.Compare(a.Field, b.Field) })
	return out
}

// flattenJSON turns a JSON object into dot-separated keys ("asn.name") with
// string values. Arrays are kept as compact JSON; null becomes "".
func flattenJSON(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if raw == nil {
		return out
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as sent
	var v any
	if dec.Decode(&v) != nil {
		return out
	}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, child)
			}
		case []any:
			b, _ := json.Marshal(t)
			out[prefix] = string(b)
		case nil:
			out[prefix] = ""
		default:
			out[prefix] = fmt.Sprint(t)
		}
	}
	walk("", v)
	return out
}
