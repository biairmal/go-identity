package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeOps records what the command asked for and returns canned results.
type fakeOps struct {
	email string
	temp  string
	id    uuid.UUID
	err   error
}

func (f *fakeOps) ops() superAdminOps {
	return superAdminOps{
		reset: func(_ context.Context, email string) (string, error) {
			f.email = email
			return f.temp, f.err
		},
		transfer: func(_ context.Context, email string) (uuid.UUID, error) {
			f.email = email
			return f.id, f.err
		},
	}
}

func TestSuperAdminCommand(t *testing.T) {
	id := uuid.MustParse("6f1c2a52-8d3e-4c55-9a51-2f4f8f6b7a10")
	tests := []struct {
		name      string
		args      []string
		opsErr    error
		wantEmail string
		wantOut   string
		wantErr   string
	}{
		{name: "no command", args: nil, wantErr: "usage"},
		{name: "unknown command", args: []string{"promote"}, wantErr: `unknown superadmin command "promote"`},
		{
			name: "reset prints the temporary password once", args: []string{"reset", "--email", "root@example.com"},
			wantEmail: "root@example.com", wantOut: "temp-password-xyz",
		},
		{
			name: "reset accepts the -flag=value form", args: []string{"reset", "-email=root@example.com"},
			wantEmail: "root@example.com", wantOut: "temp-password-xyz",
		},
		{name: "reset without email", args: []string{"reset"}, wantErr: "--email is required"},
		{name: "reset with blank email", args: []string{"reset", "--email", " "}, wantErr: "--email is required"},
		{name: "reset with wrong flag", args: []string{"reset", "--to", "x@example.com"}, wantErr: "usage"},
		{
			name: "reset with a stray argument", args: []string{"reset", "--email", "a@example.com", "extra"},
			wantErr: `unexpected argument "extra"`,
		},
		{
			name: "reset failure is returned and prints nothing", args: []string{"reset", "--email", "a@example.com"},
			opsErr: errors.New("not the super admin"), wantEmail: "a@example.com", wantErr: "not the super admin",
		},
		{
			name: "transfer", args: []string{"transfer", "--to", "next@example.com"},
			wantEmail: "next@example.com", wantOut: id.String(),
		},
		{name: "transfer without target", args: []string{"transfer"}, wantErr: "--to is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeOps{temp: "temp-password-xyz", id: id, err: tt.opsErr}
			var out bytes.Buffer
			err := superAdmin(context.Background(), f.ops(), tt.args, &out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("superAdmin(%v) = %v, want an error containing %q", tt.args, err, tt.wantErr)
				}
				if out.Len() != 0 {
					t.Errorf("output on error = %q, want none", out.String())
				}
			} else if err != nil {
				t.Fatalf("superAdmin(%v) = %v", tt.args, err)
			}
			if f.email != tt.wantEmail {
				t.Errorf("operation got email %q, want %q", f.email, tt.wantEmail)
			}
			if tt.wantOut != "" && strings.Count(out.String(), tt.wantOut) != 1 {
				t.Errorf("output %q must contain %q exactly once", out.String(), tt.wantOut)
			}
		})
	}
}
