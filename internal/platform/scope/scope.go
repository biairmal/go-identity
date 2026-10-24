// Package scope turns the request context into the tenant filter every
// repository must apply. The tenant comes only from the token's tenant claim,
// never from a request body or query, and a missing tenant is an error, so a
// forgotten filter fails loudly instead of leaking another tenant's rows.
package scope

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/ctxkit"
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

// ClaimSession is the access-token claim naming the refresh-token family the
// token was issued with. A token issued without a session (the restricted
// password-change token) carries none.
const ClaimSession = "sid"

// ErrNoUser reports a context without an authenticated subject.
var ErrNoUser = errors.New("scope: no user in context")

// User returns the caller's user ID from the token subject. It fails with a
// 401 when the context carries no subject or a malformed one.
func User(ctx context.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(ctxkit.UserID(ctx))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errorz.Wrap(ErrNoUser).WithCode(errorz.CodeUnauthorized).WithMessage(ErrNoUser.Error())
	}
	return id, nil
}

// Session returns the refresh-token family the caller's token was issued
// with, or uuid.Nil when the token names none.
func Session(ctx context.Context) uuid.UUID {
	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return uuid.Nil
	}
	raw, _ := claims.Get(ClaimSession)
	s, ok := raw.(string)
	if !ok {
		return uuid.Nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}
