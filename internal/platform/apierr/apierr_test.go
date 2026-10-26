package apierr

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
)

// TestReasonStatuses pins every reason to the HTTP status in TRD 9.2.
func TestReasonStatuses(t *testing.T) {
	want := map[Reason]int{
		ReasonInvalidCredentials:     http.StatusUnauthorized,
		ReasonAccountLocked:          http.StatusUnauthorized,
		ReasonEmailNotVerified:       http.StatusForbidden,
		ReasonAccountDisabled:        http.StatusForbidden,
		ReasonPasswordChangeRequired: http.StatusForbidden,
		ReasonTenantSuspended:        http.StatusForbidden,
		ReasonNotAMember:             http.StatusForbidden,
		ReasonTokenInvalid:           http.StatusBadRequest,
		ReasonRefreshReused:          http.StatusUnauthorized,
		ReasonRefreshExpired:         http.StatusUnauthorized,
		ReasonProviderDisabled:       http.StatusNotFound,
		ReasonOAuthStateInvalid:      http.StatusBadRequest,
		ReasonOAuthEmailUnverified:   http.StatusForbidden,
		ReasonOAuthDomainNotAllowed:  http.StatusForbidden,
		ReasonRegistrationClosed:     http.StatusForbidden,
		ReasonPasswordPolicy:         http.StatusBadRequest,
		ReasonLastSignInMethod:       http.StatusConflict,
		ReasonPermissionNotHeld:      http.StatusForbidden,
		ReasonSelfEscalation:         http.StatusForbidden,
		ReasonLastAdmin:              http.StatusConflict,
		ReasonSystemRole:             http.StatusForbidden,
		ReasonRoleInUse:              http.StatusConflict,
		ReasonSuperAdminProtected:    http.StatusForbidden,
		ReasonSelfAction:             http.StatusForbidden,
		ReasonAlreadyMember:          http.StatusConflict,
		ReasonVersionConflict:        http.StatusConflict,
		ReasonDuplicate:              http.StatusConflict,
		ReasonRateLimited:            http.StatusTooManyRequests,
	}
	if len(want) != len(reasonCodes) {
		t.Fatalf("test covers %d reasons, table has %d", len(want), len(reasonCodes))
	}
	for reason, status := range want {
		t.Run(string(reason), func(t *testing.T) {
			err := New(reason)
			if got := handler.StatusCodeFromError(err); got != status {
				t.Errorf("status = %d, want %d", got, status)
			}
			if got := ReasonOf(err); got != reason {
				t.Errorf("ReasonOf = %q, want %q", got, reason)
			}
		})
	}
}

func TestUnknownReasonIs500(t *testing.T) {
	for _, r := range []Reason{"TYPO", ReasonTenantRequired} {
		if got := handler.StatusCodeFromError(New(r)); got != http.StatusInternalServerError {
			t.Errorf("New(%q) status = %d, want 500", r, got)
		}
	}
}

func TestMetaHelpers(t *testing.T) {
	err := WithFields(ReasonPasswordPolicy, map[string]string{"password": "too common"})
	var e *errorz.Error
	if !errors.As(err, &e) || e.Meta[MetaFields].(map[string]string)["password"] != "too common" {
		t.Errorf("WithFields meta = %v", e.Meta)
	}

	tests := []struct {
		d    time.Duration
		want int
	}{{90 * time.Second, 90}, {1500 * time.Millisecond, 2}, {0, 0}}
	for _, tt := range tests {
		s, ok := RetryAfterOf(WithRetryAfter(ReasonRateLimited, tt.d))
		if !ok || s != tt.want {
			t.Errorf("RetryAfterOf(%v) = %d, %v; want %d", tt.d, s, ok, tt.want)
		}
	}
	if _, ok := RetryAfterOf(New(ReasonRateLimited)); ok {
		t.Error("RetryAfterOf without the meta should report false")
	}
	if ReasonOf(errorz.NotFound()) != "" || ReasonOf(nil) != "" {
		t.Error("ReasonOf should be empty for errors without a reason")
	}
}
