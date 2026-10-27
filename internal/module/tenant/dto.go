package tenant

import (
	"time"

	"github.com/biairmal/go-sdk/lib/common/dto"
)

// TenantPageResponse is the data of GET /v1/admin/tenants.
type TenantPageResponse = dto.PageResponse[TenantSummaryResponse] //nolint:revive // resource-named DTO

// TenantSummaryResponse is one row of GET /v1/admin/tenants.
type TenantSummaryResponse struct { //nolint:revive // named for its resource: the package holds several tenant DTOs
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	Version     int       `json:"version"`
}

// TenantResponse is one tenant, returned by get, create and patch.
type TenantResponse struct { //nolint:revive // named for its resource: the package holds several tenant DTOs
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Version   int       `json:"version"`
}

// CreateTenantRequest is the body of POST /v1/admin/tenants.
type CreateTenantRequest struct {
	Slug            string `json:"slug"`
	Name            string `json:"name" validate:"required,max=100"`
	FirstAdminEmail string `json:"first_admin_email" validate:"required,email"`
}

// UpdateTenantRequest is the body of PATCH /v1/admin/tenants/{id}. Absent
// fields keep their value.
type UpdateTenantRequest struct {
	Name   *string `json:"name" validate:"omitnil,min=1,max=100"`
	Status *string `json:"status" validate:"omitnil,oneof=active suspended"`
	// Version stands in for the If-Match header.
	Version *int `json:"version"`
}

// InternalTenantResponse is GET /v1/internal/tenants/{id} (TRD 9.8): the
// minimal shape a resource service needs.
type InternalTenantResponse struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// newTenantResponse builds the single-tenant response.
func newTenantResponse(t *Tenant) *TenantResponse {
	return &TenantResponse{
		ID: t.ID.String(), Slug: t.Slug, Name: t.Name, Status: t.Status,
		CreatedAt: t.CreatedAt.UTC(), Version: t.Version,
	}
}
