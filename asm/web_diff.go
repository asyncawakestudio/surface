package asm

import (
	"slices"
	"strconv"
	"strings"
)

// WebDiff lists sites that appeared or disappeared and sites whose response
// changed (status, title, server, redirect or technologies).
type WebDiff struct {
	// Compared is false unless both scans ran the web stage.
	Compared bool `json:"compared"`
	SetDiff[WebPage]
	Changed []WebChange `json:"changed"`
}

// WebChange is a URL present in both scans whose response differs. Fields
// uses the names "status_code", "title", "web_server", "location", "cdn" and
// "technologies".
type WebChange struct {
	URL    string        `json:"url"`
	Fields []FieldChange `json:"fields"`
}

func compareWeb(prev, cur *Result) WebDiff {
	d := WebDiff{
		SetDiff: SetDiff[WebPage]{Added: []WebPage{}, Removed: []WebPage{}},
		Changed: []WebChange{},
	}
	if !prev.ran(StageWeb) || !cur.ran(StageWeb) {
		return d
	}
	d.Compared = true
	d.SetDiff = setDiff(prev.Web, cur.Web, func(p WebPage) string { return p.URL })

	before := make(map[string]WebPage, len(prev.Web))
	for _, p := range prev.Web {
		before[p.URL] = p
	}
	for _, p := range cur.Web {
		old, ok := before[p.URL]
		if !ok {
			continue
		}
		var fields []FieldChange
		add := func(name, a, b string) {
			if a != b {
				fields = append(fields, FieldChange{Field: name, Before: a, After: b})
			}
		}
		add("status_code", strconv.Itoa(old.StatusCode), strconv.Itoa(p.StatusCode))
		add("title", old.Title, p.Title)
		add("web_server", old.WebServer, p.WebServer)
		add("location", old.Location, p.Location)
		add("cdn", old.CDN, p.CDN)
		add("technologies", techList(old.Technologies), techList(p.Technologies))
		if len(fields) > 0 {
			d.Changed = append(d.Changed, WebChange{URL: p.URL, Fields: fields})
		}
	}
	slices.SortFunc(d.Changed, func(a, b WebChange) int { return strings.Compare(a.URL, b.URL) })
	return d
}

// techList is a page's technologies as "Name Version" items, comma separated.
func techList(techs []Technology) string {
	items := make([]string, len(techs))
	for i, t := range techs {
		items[i] = strings.TrimSpace(t.Name + " " + t.Version)
	}
	slices.Sort(items)
	return strings.Join(items, ", ")
}
