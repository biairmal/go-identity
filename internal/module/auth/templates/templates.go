// Package templates holds the bodies of the emails identity sends and builds
// the messages that carry them. The link paths are a contract with the
// frontend: the token always travels in the URL fragment.
package templates

import (
	"bytes"
	"text/template"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/platform/mail"
)

// Template names. Each one has a <name>.txt body in this package.
const (
	VerifyEmail     = "verify_email"
	ResetPassword   = "reset_password"
	Invite          = "invite"
	ExistingAccount = "existing_account"
)

// Frontend paths the links point at (frontend TRD 6.3).
const (
	PathVerifyEmail   = "/verify-email"
	PathResetPassword = "/reset-password"
	PathInvite        = "/invite"
	PathSignIn        = "/sign-in"
)

// subjects is each template's subject line.
var subjects = map[string]string{
	VerifyEmail:     "Confirm your email address",
	ResetPassword:   "Reset your password",
	Invite:          "You have been invited",
	ExistingAccount: "You already have an account",
}

// Subject returns the subject line of a template, or "" for an unknown one.
func Subject(name string) string { return subjects[name] }

// VerifyEmailMessage builds the mail that confirms a new registration.
func VerifyEmailMessage(to, token string, expiresAt time.Time, data map[string]string) *mail.Message {
	return message(VerifyEmail, PathVerifyEmail, to, token, expiresAt, data)
}

// ResetPasswordMessage builds the mail behind forgot-password.
func ResetPasswordMessage(to, token string, expiresAt time.Time, data map[string]string) *mail.Message {
	return message(ResetPassword, PathResetPassword, to, token, expiresAt, data)
}

// InviteMessage builds the mail that invites someone into a tenant.
func InviteMessage(to, token string, expiresAt time.Time, data map[string]string) *mail.Message {
	return message(Invite, PathInvite, to, token, expiresAt, data)
}

// ExistingAccountMessage builds the mail sent instead of a registration when
// the address already has an account, so the response cannot reveal which
// addresses exist. It carries no token, only a link to sign in.
func ExistingAccountMessage(to string, data map[string]string) *mail.Message {
	return message(ExistingAccount, PathSignIn, to, "", time.Time{}, data)
}

// message assembles one message. expiresAt is the token's expiry.
func message(name, path, to, token string, expiresAt time.Time, data map[string]string) *mail.Message {
	return &mail.Message{
		To:        to,
		Subject:   Subject(name),
		Template:  name,
		LinkPath:  path,
		Token:     token,
		ExpiresAt: expiresAt,
		Data:      data,
	}
}

// Render returns the body of a template with link and data substituted. A
// real mailer calls it at delivery time; the development logging mailer only
// logs the link.
func Render(name, link string, data map[string]string) (string, error) {
	body, err := FS.ReadFile(name + ".txt")
	if err != nil {
		return "", errorz.NotFound().WithMessage("templates: no template named " + name)
	}
	t, err := template.New(name).Option("missingkey=zero").Parse(string(body))
	if err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("templates: parse " + name)
	}
	vars := map[string]string{"Link": link}
	for k, v := range data {
		vars[k] = v
	}
	var out bytes.Buffer
	if err := t.Execute(&out, vars); err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("templates: render " + name)
	}
	return out.String(), nil
}
