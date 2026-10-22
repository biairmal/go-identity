// Package scope turns the request context into the tenant filter every
// repository must apply. The tenant comes only from the token's tenant claim,
// never from a request body or query, and a missing tenant is an error, so a
// forgotten filter fails loudly instead of leaking another tenant's rows.
package scope

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/repository"
	"github.com/google/uuid"
)

// TenantColumn is the tenant column on every tenant-owned table.
const TenantColumn = "tenant_id"

// ErrNoTenant reports a context without a valid tenant claim.
var ErrNoTenant = errors.New("scope: no tenant in context")

// Tenant returns the caller's tenant from the token claim. It fails with a 401
// when the context carries no claims, no tenant claim or a malformed one.
func Tenant(ctx context.Context) (uuid.UUID, error) {
	raw, ok := authz.TenantID(ctx)
	if !ok {
		return uuid.Nil, errorz.Wrap(ErrNoTenant).WithCode(errorz.CodeUnauthorized).WithMessage(ErrNoTenant.Error())
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errorz.Wrap(ErrNoTenant).WithCode(errorz.CodeUnauthorized).
			WithMessage("scope: tenant claim is not a UUID")
	}
	return id, nil
}

// TenantFilter returns the tenant condition to add to repository.ListOptions.
func TenantFilter(ctx context.Context) (repository.FilterCondition, error) {
	id, err := Tenant(ctx)
	if err != nil {
		return repository.FilterCondition{}, err
	}
	return repository.FilterCondition{Field: TenantColumn, Operator: repository.FilterOperatorEq, Value: id}, nil
}
