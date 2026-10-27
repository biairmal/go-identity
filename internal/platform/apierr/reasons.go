package apierr

import "github.com/biairmal/go-sdk/lib/errorz"

// Reason is the machine-readable meta.reason clients branch on (TRD 9.2).
type Reason string

// Every meta.reason the API returns. Add a reason here only when the TRD
// table lists it.
const (
	ReasonInvalidCredentials     Reason = "INVALID_CREDENTIALS" //nolint:gosec // a reason code, not a credential
	ReasonAccountLocked          Reason = "ACCOUNT_LOCKED"
	ReasonEmailNotVerified       Reason = "EMAIL_NOT_VERIFIED"
	ReasonAccountDisabled        Reason = "ACCOUNT_DISABLED"
	ReasonPasswordChangeRequired Reason = "PASSWORD_CHANGE_REQUIRED"
	ReasonTenantSuspended        Reason = "TENANT_SUSPENDED"
	ReasonNotAMember             Reason = "NOT_A_MEMBER"
	ReasonTokenInvalid           Reason = "TOKEN_INVALID"
	ReasonRefreshReused          Reason = "REFRESH_REUSED"
	ReasonRefreshExpired         Reason = "REFRESH_EXPIRED"
	ReasonProviderDisabled       Reason = "PROVIDER_DISABLED"
	ReasonOAuthStateInvalid      Reason = "OAUTH_STATE_INVALID"
	ReasonOAuthEmailUnverified   Reason = "OAUTH_EMAIL_UNVERIFIED"
	ReasonOAuthDomainNotAllowed  Reason = "OAUTH_DOMAIN_NOT_ALLOWED"
	ReasonRegistrationClosed     Reason = "REGISTRATION_CLOSED"
	ReasonPasswordPolicy         Reason = "PASSWORD_POLICY"
	ReasonLastSignInMethod       Reason = "LAST_SIGN_IN_METHOD"
	ReasonPermissionNotHeld      Reason = "PERMISSION_NOT_HELD"
	ReasonSelfEscalation         Reason = "SELF_ESCALATION"
	ReasonLastAdmin              Reason = "LAST_ADMIN"
	ReasonSystemRole             Reason = "SYSTEM_ROLE"
	ReasonRoleInUse              Reason = "ROLE_IN_USE"
	ReasonSuperAdminProtected    Reason = "SUPER_ADMIN_PROTECTED"
	ReasonSelfAction             Reason = "SELF_ACTION"
	ReasonAlreadyMember          Reason = "ALREADY_MEMBER"
	ReasonVersionConflict        Reason = "VERSION_CONFLICT"
	ReasonDuplicate              Reason = "DUPLICATE"
	ReasonRateLimited            Reason = "RATE_LIMITED"
	ReasonInvalidClient          Reason = "INVALID_CLIENT"
	ReasonUnsupportedGrantType   Reason = "UNSUPPORTED_GRANT_TYPE"

	// ReasonTenantRequired is not an error: sign-in answers 200 with the
	// tenants to choose from. It has no errorz code.
	ReasonTenantRequired Reason = "TENANT_REQUIRED"
)

// reasonCodes maps each error reason to the errorz code that selects its HTTP
// status, so a reason can never be paired with the wrong status.
var reasonCodes = map[Reason]string{ //nolint:dupl // the test pins the same table to HTTP statuses
	ReasonInvalidCredentials:     errorz.CodeUnauthorized,
	ReasonAccountLocked:          errorz.CodeUnauthorized,
	ReasonEmailNotVerified:       errorz.CodeForbidden,
	ReasonAccountDisabled:        errorz.CodeForbidden,
	ReasonPasswordChangeRequired: errorz.CodeForbidden,
	ReasonTenantSuspended:        errorz.CodeForbidden,
	ReasonNotAMember:             errorz.CodeForbidden,
	ReasonTokenInvalid:           errorz.CodeBadRequest,
	ReasonRefreshReused:          errorz.CodeUnauthorized,
	ReasonRefreshExpired:         errorz.CodeUnauthorized,
	ReasonProviderDisabled:       errorz.CodeNotFound,
	ReasonOAuthStateInvalid:      errorz.CodeBadRequest,
	ReasonOAuthEmailUnverified:   errorz.CodeForbidden,
	ReasonOAuthDomainNotAllowed:  errorz.CodeForbidden,
	ReasonRegistrationClosed:     errorz.CodeForbidden,
	ReasonPasswordPolicy:         errorz.CodeBadRequest,
	ReasonLastSignInMethod:       errorz.CodeConflict,
	ReasonPermissionNotHeld:      errorz.CodeForbidden,
	ReasonSelfEscalation:         errorz.CodeForbidden,
	ReasonLastAdmin:              errorz.CodeConflict,
	ReasonSystemRole:             errorz.CodeForbidden,
	ReasonRoleInUse:              errorz.CodeConflict,
	ReasonSuperAdminProtected:    errorz.CodeForbidden,
	ReasonSelfAction:             errorz.CodeForbidden,
	ReasonAlreadyMember:          errorz.CodeConflict,
	ReasonVersionConflict:        errorz.CodeConflict,
	ReasonDuplicate:              errorz.CodeConflict,
	ReasonRateLimited:            errorz.CodeTooManyRequests,
	ReasonInvalidClient:          errorz.CodeUnauthorized,
	ReasonUnsupportedGrantType:   errorz.CodeBadRequest,
}
