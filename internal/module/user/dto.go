package user

import (
	"time"

	"github.com/biairmal/go-sdk/lib/common/dto"
)

// UserResponse is the user shape the API returns. It is a separate type from the
// row struct on purpose: the row gains columns that must not leak (the lock
// counters, the super admin flag's neighbors), and a DTO makes every added
// field an explicit decision.
type UserResponse struct { //nolint:revive // named for its resource: the package will hold other response DTOs
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	Status             string     `json:"status"`
	EmailVerified      bool       `json:"email_verified"`
	MustChangePassword bool       `json:"must_change_password"`
	LastSignInAt       *time.Time `json:"last_sign_in_at"`
	CreatedAt          time.Time  `json:"created_at"`
	Version            int        `json:"version"`
}

// AdminUserResponse is one member in GET /v1/admin/users.
type AdminUserResponse struct {
	ID               string            `json:"id"`
	Email            string            `json:"email"`
	DisplayName      string            `json:"display_name"`
	Status           string            `json:"status"`
	MembershipStatus string            `json:"membership_status"`
	Roles            []RoleRefResponse `json:"roles"`
	CreatedAt        time.Time         `json:"created_at"`
	LastSignInAt     *time.Time        `json:"last_sign_in_at"`
}

// AdminUserDetailResponse is GET /v1/admin/users/{id}: the list shape plus
// sign-in methods and version.
type AdminUserDetailResponse struct {
	AdminUserResponse
	Providers ProvidersResponse `json:"providers"`
	Version   int               `json:"version"`
}

// AdminUserPageResponse is the data of GET /v1/admin/users.
type AdminUserPageResponse = dto.PageResponse[AdminUserResponse]

// ProvidersResponse says which sign-in methods an account has.
type ProvidersResponse struct {
	Password bool `json:"password"`
	Google   bool `json:"google"`
}

// RoleRefResponse names one role a member holds.
type RoleRefResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// newAdminUserResponse maps a member and their roles to the list shape.
func newAdminUserResponse(m *Member, roles []RoleRef) *AdminUserResponse {
	refs := make([]RoleRefResponse, 0, len(roles))
	for _, r := range roles {
		refs = append(refs, RoleRefResponse{ID: r.ID.String(), Name: r.Name})
	}
	return &AdminUserResponse{
		ID: m.ID.String(), Email: m.Email, DisplayName: m.DisplayName, Status: m.Status,
		MembershipStatus: m.MembershipStatus, Roles: refs, CreatedAt: m.CreatedAt.UTC(), LastSignInAt: utc(m.LastSignInAt),
	}
}

// NewUserResponse maps a user row to its API shape.
func NewUserResponse(u *User) UserResponse {
	return UserResponse{
		ID:                 u.ID.String(),
		Email:              u.Email,
		DisplayName:        u.DisplayName,
		Status:             u.Status,
		EmailVerified:      u.EmailVerified(),
		MustChangePassword: u.MustChangePassword,
		LastSignInAt:       u.LastSignInAt,
		CreatedAt:          u.CreatedAt,
		Version:            u.Version,
	}
}

// InternalUserResponse is GET /v1/internal/users/{id} (TRD 9.8): no email, so
// a resource service never learns an address it has no business seeing.
type InternalUserResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

// newInternalUserResponse maps a user row to its internal-API shape.
func newInternalUserResponse(u *User) *InternalUserResponse {
	return &InternalUserResponse{ID: u.ID.String(), DisplayName: u.DisplayName, Status: u.Status}
}

// utc returns t in UTC, or nil.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
