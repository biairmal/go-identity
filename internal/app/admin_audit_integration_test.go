package app

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// auditPage reads GET /v1/admin/audit with query as bia.
func (f *adminFixture) auditPage(t *testing.T, query string) (total float64, entries []map[string]any) {
	t.Helper()
	r := f.do(t, http.MethodGet, "/v1/admin/audit"+query, f.bia, nil, "")
	if r.Status != http.StatusOK {
		t.Fatalf("GET /v1/admin/audit%s = %d %s", query, r.Status, r.Raw)
	}
	raw, _ := r.Data["items"].([]any)
	for _, it := range raw {
		m, _ := it.(map[string]any)
		entries = append(entries, m)
	}
	total, _ = r.Data["total"].(float64)
	return total, entries
}

// TestAdminAuditRead filters the tenant's log by actor, action and time,
// newest first, and shows nothing of another tenant.
func TestAdminAuditRead(t *testing.T) {
	f := newAdminFixture(t)
	id := f.createRole(t, f.bia, "Support", "users:read")
	patch := map[string]any{"description": "x"}
	if r := f.do(t, http.MethodPatch, "/v1/admin/roles/"+id, f.bia, patch, `"1"`); r.Status != http.StatusOK {
		t.Fatalf("PATCH role = %d %s", r.Status, r.Raw)
	}
	tenant := f.text(t, `SELECT id::text FROM tenants WHERE slug = 'default'`)
	f.exec(t, `INSERT INTO audit_log (tenant_id, action) VALUES ($1, 'test.anonymous')`, tenant)
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme')`)
	f.exec(t, `INSERT INTO audit_log (tenant_id, action)
		SELECT id, 'test.other_tenant' FROM tenants WHERE slug = 'acme'`)

	total, all := f.auditPage(t, "?size=100")
	if int(total) != len(all) || len(all) < 4 {
		t.Fatalf("entries = %v of %d", total, len(all))
	}
	for i := 1; i < len(all); i++ {
		prev, _ := time.Parse(time.RFC3339Nano, all[i-1]["at"].(string))
		cur, _ := time.Parse(time.RFC3339Nano, all[i]["at"].(string))
		if cur.After(prev) {
			t.Fatalf("entry %d is newer than entry %d: not newest first", i, i-1)
		}
	}
	for _, e := range all {
		switch e["action"] {
		case "test.other_tenant":
			t.Error("another tenant's entry is visible")
		case "test.anonymous":
			if _, has := e["actor"]; has {
				t.Errorf("anonymous entry has an actor: %v", e)
			}
		case "role.update":
			actor, _ := e["actor"].(map[string]any)
			before, _ := e["before"].(map[string]any)
			if actor["display_name"] != "Bia" || before["description"] != "" || e["target_id"] != id {
				t.Errorf("role.update entry = %v", e)
			}
		}
	}

	bia := f.userID(t, "Bia")
	future := url.QueryEscape(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	past := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	for query, want := range map[string]int{
		"?action=role.%25":                      2, // role.create, role.update
		"?action=role.create":                   1,
		"?action=update%3Blike":                 1, // the ;like suffix, percent-encoded
		"?from=" + future:                       0,
		"?to=" + past:                           0,
		"?from=" + past:                         len(all),
		"?actor=" + bia:                         4, // register, login, role.create, role.update
		"?actor=" + bia + "&action=role.update": 1,
	} {
		if n, _ := f.auditPage(t, query); int(n) != want {
			t.Errorf("GET /v1/admin/audit%s total = %v, want %d", query, n, want)
		}
	}
	if n, page := f.auditPage(t, "?size=1&page=2"); int(n) != len(all) || len(page) != 1 {
		t.Errorf("size=1 page 2 = %d items of %v", len(page), n)
	}

	for _, q := range []string{"?actor=x", "?from=yesterday", "?tenant_id=" + tenant, "?target=role"} {
		if r := f.do(t, http.MethodGet, "/v1/admin/audit"+q, f.bia, nil, ""); r.Status != http.StatusBadRequest {
			t.Errorf("GET /v1/admin/audit%s = %d, want 400", q, r.Status)
		}
	}
	if r := f.do(t, http.MethodGet, "/v1/admin/audit", f.kim, nil, ""); r.Status != http.StatusForbidden {
		t.Errorf("member GET /v1/admin/audit = %d, want 403", r.Status)
	}
}

// TestAdminAuditTargetFilter filters the log by target, alone and with the
// other filters, and never shows another tenant's entries for the same target.
func TestAdminAuditTargetFilter(t *testing.T) {
	f := newAdminFixture(t)
	id := f.createRole(t, f.bia, "Support", "users:read")
	patch := map[string]any{"description": "x"}
	if r := f.do(t, http.MethodPatch, "/v1/admin/roles/"+id, f.bia, patch, `"1"`); r.Status != http.StatusOK {
		t.Fatalf("PATCH role = %d %s", r.Status, r.Raw)
	}
	other := f.createRole(t, f.bia, "Other", "users:read")
	f.exec(t, `INSERT INTO tenants (slug, name) VALUES ('acme', 'Acme')`)
	f.exec(t, `INSERT INTO audit_log (tenant_id, action, target_type, target_id)
		SELECT id, 'role.update', 'role', $1 FROM tenants WHERE slug = 'acme'`, id)
	bia := f.userID(t, "Bia")

	for query, want := range map[string]int{
		"?target_type=role&target_id=" + id:                                     2, // create, update; not acme's
		"?target_type=role&target_id=" + other:                                  1,
		"?target_type=role&target_id=" + id + "&action=role.update":             1,
		"?target_type=role&target_id=" + id + "&actor=" + bia:                   2,
		"?target_type=role&target_id=" + id + "&from=2000-01-01T00:00:00Z":      2,
		"?target_type=role&target_id=" + id + "&to=2000-01-01T00:00:00Z":        0,
		"?target_type=role&target_id=" + id + "&action=role.create&actor=" + id: 0, // not an actor
		"?target_type=role&target_id=nothing":                                   0,
		"?target_type=nothing":                                                  0,
	} {
		if n, items := f.auditPage(t, query); int(n) != want {
			t.Errorf("GET /v1/admin/audit%s total = %v, want %d (%v)", query, n, want, items)
		}
	}
	n, items := f.auditPage(t, "?target_type=role&size=100")
	if int(n) != 3 { // role.create x2, role.update; acme's entry is hidden
		t.Errorf("target_type=role total = %v, want 3", n)
	}
	for _, e := range items {
		if e["target_type"] != "role" {
			t.Errorf("entry of another type: %v", e)
		}
	}
	if len(items) == 3 && items[0]["action"] != "role.create" && items[0]["action"] != "role.update" {
		t.Errorf("unexpected first entry: %v", items[0])
	}

	bad := []string{
		"?target_id=" + id,
		"?target_type=role&target_id=" + id + "%3Blike",
		"?target_type=a%3Blike",
	}
	for _, q := range bad {
		r := f.do(t, http.MethodGet, "/v1/admin/audit"+q, f.bia, nil, "")
		if r.Status != http.StatusBadRequest {
			t.Errorf("GET /v1/admin/audit%s = %d, want 400", q, r.Status)
		}
	}
	r := f.do(t, http.MethodGet, "/v1/admin/audit?target_id="+id, f.bia, nil, "")
	if !strings.Contains(string(r.Raw), `"target_id"`) {
		t.Errorf("400 body does not name target_id: %s", r.Raw)
	}
}
