package templates_test

import (
	"strings"
	"testing"

	"github.com/biairmal/go-identity/internal/module/auth/templates"
)

// TestMessagesUseTheFrontendPaths pins the link paths, which are a contract
// with the frontend pages that read the token from the fragment.
func TestMessagesUseTheFrontendPaths(t *testing.T) {
	const base = "http://localhost:3000"
	tests := []struct {
		name     string
		msg      interface{ Link(string) string }
		template string
		wantLink string
	}{
		{
			name:     "verify email",
			msg:      templates.VerifyEmailMessage("bia@example.com", "tok", nil),
			template: templates.VerifyEmail,
			wantLink: base + "/verify-email#token=tok",
		},
		{
			name:     "reset password",
			msg:      templates.ResetPasswordMessage("bia@example.com", "tok", nil),
			template: templates.ResetPassword,
			wantLink: base + "/reset-password#token=tok",
		},
		{
			name:     "invite",
			msg:      templates.InviteMessage("bia@example.com", "tok", nil),
			template: templates.Invite,
			wantLink: base + "/invite#token=tok",
		},
		{
			name:     "existing account carries no token",
			msg:      templates.ExistingAccountMessage("bia@example.com", nil),
			template: templates.ExistingAccount,
			wantLink: base + "/sign-in",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.Link(base); got != tt.wantLink {
				t.Errorf("Link() = %q, want %q", got, tt.wantLink)
			}
			if templates.Subject(tt.template) == "" {
				t.Errorf("template %q has no subject", tt.template)
			}
		})
	}
}

// TestRender checks every template renders with its link substituted, and
// that an unknown name fails instead of sending an empty mail.
func TestRender(t *testing.T) {
	const link = "http://localhost:3000/verify-email#token=tok"
	names := []string{
		templates.VerifyEmail, templates.ResetPassword,
		templates.Invite, templates.ExistingAccount,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			body, err := templates.Render(name, link, map[string]string{
				"DisplayName": "Bia", "TenantName": "Acme", "InviterName": "Sam",
			})
			if err != nil {
				t.Fatalf("Render(%q) = %v", name, err)
			}
			if !strings.Contains(body, link) {
				t.Errorf("Render(%q) does not contain the link:\n%s", name, body)
			}
			if strings.Contains(body, "{{") {
				t.Errorf("Render(%q) left a template action unrendered:\n%s", name, body)
			}
		})
	}
	if _, err := templates.Render("nope", link, nil); err == nil {
		t.Error("Render() accepted an unknown template name")
	}
}

// TestRenderWithoutOptionalData keeps a mail sendable when the optional
// variables are absent.
func TestRenderWithoutOptionalData(t *testing.T) {
	body, err := templates.Render(templates.Invite, "http://x/invite#token=t", nil)
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	if strings.Contains(body, "<no value>") {
		t.Errorf("a missing variable rendered as <no value>:\n%s", body)
	}
}
