package app

import (
	"context"

	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/mailer"

	"github.com/biairmal/go-identity/internal/module/auth/templates"
	"github.com/biairmal/go-identity/internal/platform/mail"
)

// newMailer returns the Mailer the worker delivers through: SMTP when the
// mail block names a host, else the development logging mailer, which fails
// in production so a deployment without a mail server never starts.
func newMailer(cfg *Config, log logger.Logger) (mail.Mailer, error) {
	baseURL := cfg.Modules.Auth.EmailBaseURL()
	if !cfg.Mail.Enabled() {
		l, err := mail.NewLogging(log, cfg.Service.Environment, baseURL)
		if err != nil {
			return nil, err
		}
		return l, nil
	}
	t, err := mailer.NewSMTPTransport(&cfg.Mail.SMTPConfig)
	if err != nil {
		return nil, err
	}
	return &smtpMailer{mailer: mailer.New(t), from: cfg.Mail.From, baseURL: baseURL}, nil
}

// smtpMailer adapts go-sdk's mailer to the mail.Mailer port: it renders the
// message's template from auth/templates with its link and sends the result
// as a plain-text body.
type smtpMailer struct {
	mailer  *mailer.Mailer
	from    string
	baseURL string
}

// Send renders and delivers m.
func (s *smtpMailer) Send(ctx context.Context, m *mail.Message) error {
	body, err := templates.Render(m.Template, m.Link(s.baseURL), m.Data)
	if err != nil {
		return err
	}
	return s.mailer.Send(ctx, &mailer.Message{
		From:    s.from,
		To:      []string{m.To},
		Subject: m.Subject,
		Text:    body,
	})
}
