package user

import "time"

// UserResponse is the user shape the API returns. It is a separate type from the
// row struct on purpose: the row gains columns that must not leak (the lock
// counters, the super admin flag's neighbors), and a DTO makes every added
// field an explicit decision.
//
// The admin list adds the caller's tenant membership and roles, which come
// from other modules and arrive with the admin user endpoints.
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
