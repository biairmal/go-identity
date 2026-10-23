package scope

import (
	"context"
	"errors"
	"testing"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/repository"
	"github.com/google/uuid"
)

func TestTenant(t *testing.T) {
	tid := uuid.New()
	withClaims := func(c map[string]any) context.Context {
		return auth.ContextWithClaims(context.Background(), auth.NewClaims(c))
	}
	tests := []struct {
		name    string
		ctx     context.Context
		want    uuid.UUID
		wantErr bool
	}{
		{"tenant claim", withClaims(map[string]any{"sub": "u", "tid": tid.String()}), tid, false},
		{"no claims", context.Background(), uuid.Nil, true},
		{"no tenant claim", withClaims(map[string]any{"sub": "u"}), uuid.Nil, true},
		{"not a uuid", withClaims(map[string]any{"sub": "u", "tid": "acme"}), uuid.Nil, true},
		{"nil uuid", withClaims(map[string]any{"sub": "u", "tid": uuid.Nil.String()}), uuid.Nil, true},
		{"wrong type", withClaims(map[string]any{"sub": "u", "tid": 7}), uuid.Nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Tenant(tt.ctx)
			if tt.wantErr {
				var e *errorz.Error
				if !errors.Is(err, ErrNoTenant) || !errors.As(err, &e) || e.Code != errorz.CodeUnauthorized {
					t.Fatalf("Tenant() err = %v, want ErrNoTenant as a 401", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Tenant() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestTenantFilter(t *testing.T) {
	tid := uuid.New()
	ctx := auth.ContextWithClaims(context.Background(), auth.NewClaims(map[string]any{"sub": "u", "tid": tid.String()}))
	f, err := TenantFilter(ctx)
	if err != nil {
		t.Fatalf("TenantFilter: %v", err)
	}
	if f.Field != TenantColumn || f.Operator != repository.FilterOperatorEq || f.Value != tid {
		t.Errorf("TenantFilter = %+v", f)
	}
	if _, err := TenantFilter(context.Background()); !errors.Is(err, ErrNoTenant) {
		t.Errorf("TenantFilter without tenant = %v, want ErrNoTenant", err)
	}
}
