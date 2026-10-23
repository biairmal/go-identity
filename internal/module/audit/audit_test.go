package audit

import (
	"context"
	"testing"

	"github.com/biairmal/go-sdk/lib/ctxkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/requestip"
)

// TestRowFromEvent covers the mapping from an Event to the stored row without
// a database: which fields become NULL, and where the metadata comes from.
func TestRowFromEvent(t *testing.T) {
	id := uuid.New()
	tests := []struct {
		name  string
		ctx   func() context.Context
		event Event
		check func(t *testing.T, r *Row)
	}{
		{
			name: "ids and state are carried through",
			ctx:  context.Background,
			event: Event{
				TenantID: id, ActorID: id, Action: ActionLogin,
				TargetType: TargetUser, TargetID: id.String(),
				After: map[string]string{"status": "active"},
			},
			check: func(t *testing.T, r *Row) {
				if r.TenantID == nil || *r.TenantID != id {
					t.Errorf("TenantID = %v, want %v", r.TenantID, id)
				}
				if r.Action != string(ActionLogin) {
					t.Errorf("Action = %q, want %q", r.Action, ActionLogin)
				}
				if string(r.After) != `{"status":"active"}` {
					t.Errorf("After = %s, want the encoded state", r.After)
				}
				if r.Before != nil {
					t.Errorf("Before = %s, want nil", r.Before)
				}
			},
		},
		{
			name:  "zero ids become NULL",
			ctx:   context.Background,
			event: Event{Action: ActionLoginFailed},
			check: func(t *testing.T, r *Row) {
				if r.TenantID != nil || r.ActorID != nil {
					t.Errorf("TenantID = %v, ActorID = %v, want both nil", r.TenantID, r.ActorID)
				}
				if r.IP != nil {
					t.Errorf("IP = %v, want nil", r.IP)
				}
			},
		},
		{
			name: "request metadata comes from the context",
			ctx: func() context.Context {
				return requestip.With(ctxkit.WithRequestID(context.Background(), "req-9"), "198.51.100.4")
			},
			event: Event{Action: ActionLogout},
			check: func(t *testing.T, r *Row) {
				if r.RequestID != "req-9" {
					t.Errorf("RequestID = %q, want req-9", r.RequestID)
				}
				if r.IP == nil || *r.IP != "198.51.100.4" {
					t.Errorf("IP = %v, want 198.51.100.4", r.IP)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWriter(nil, nil)
			row, err := w.row(tt.ctx(), &tt.event)
			if err != nil {
				t.Fatalf("row() = %v", err)
			}
			tt.check(t, row)
		})
	}
}

// TestRowRejectsUnencodableState checks a state value that cannot be JSON
// becomes an error rather than a silently empty audit row.
func TestRowRejectsUnencodableState(t *testing.T) {
	w := NewWriter(nil, nil)
	if _, err := w.row(context.Background(), &Event{
		Action: ActionRoleUpdate,
		Before: func() {}, // functions cannot be marshaled
	}); err == nil {
		t.Fatal("row() = nil, want an encoding error")
	}
}
