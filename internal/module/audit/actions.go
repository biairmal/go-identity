package audit

// Action names every audited event. They are constants because the admin
// filter and the tests match on them, and a typo in a string literal would
// silently create a new action.
type Action string

// Authentication events.
const (
	ActionLogin          Action = "auth.login"
	ActionLoginFailed    Action = "auth.login_failed"
	ActionLogout         Action = "auth.logout"
	ActionLogoutAll      Action = "auth.logout_all"
	ActionRegister       Action = "auth.register"
	ActionEmailVerified  Action = "auth.email_verified"
	ActionPasswordReset  Action = "auth.password_reset"
	ActionPasswordChange Action = "auth.password_change"
	ActionTokenRefresh   Action = "auth.token_refresh" //nolint:gosec // an audit action name, not a credential
	ActionRefreshReuse   Action = "auth.refresh_reuse"
	ActionTenantSwitch   Action = "auth.tenant_switch"
)

// User and membership events.
const (
	ActionUserCreate     Action = "user.create"
	ActionUserDisable    Action = "user.disable"
	ActionUserEnable     Action = "user.enable"
	ActionUserDelete     Action = "user.delete"
	ActionUserInvite     Action = "user.invite"
	ActionInviteAccepted Action = "user.invite_accepted"
	ActionMemberAdd      Action = "member.add"
	ActionMemberRemove   Action = "member.remove"
)

// Role and permission events.
const (
	ActionRoleCreate        Action = "role.create"
	ActionRoleUpdate        Action = "role.update"
	ActionRoleDelete        Action = "role.delete"
	ActionRolePermissions   Action = "role.permissions"
	ActionUserRolesAssigned Action = "user.roles_assigned"
)

// Tenant events.
const (
	ActionTenantCreate     Action = "tenant.create"
	ActionTenantUpdate     Action = "tenant.update"
	ActionTenantSuspend    Action = "tenant.suspend"
	ActionTenantReactivate Action = "tenant.reactivate"
)

// Session and identity events.
const (
	ActionSessionRevoke  Action = "session.revoke"
	ActionSessionsRevoke Action = "session.revoke_all"
	ActionIdentityLink   Action = "identity.link"
	ActionIdentityUnlink Action = "identity.unlink"
)

// Super admin events, all CLI-only.
const (
	ActionSuperAdminCreate   Action = "superadmin.create"
	ActionSuperAdminReset    Action = "superadmin.reset"
	ActionSuperAdminTransfer Action = "superadmin.transfer"
)

// Target types an event can point at.
const (
	TargetUser       = "user"
	TargetRole       = "role"
	TargetTenant     = "tenant"
	TargetSession    = "session"
	TargetMembership = "membership"
	TargetIdentity   = "identity"
)
