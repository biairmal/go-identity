package app

import (
	"errors"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/mail"
)

// TestSendersRegisterMail checks the worker routes the mail topic to a sender,
// and that it refuses to build one in production without an SMTP server,
// where the development logging mailer would print one-time tokens to the log
// instead of emailing them. With the mail block set, production starts.
func TestSendersRegisterMail(t *testing.T) {
	smtp := MailConfig{From: "no-reply@example.com"}
	smtp.Host = "smtp.example.com"
	tests := []struct {
		name        string
		environment string
		frontendURL string
		mail        MailConfig
		wantErr     error
	}{
		{name: "local", environment: EnvLocal, frontendURL: "http://localhost:3000"},
		{name: "staging", environment: EnvStaging, frontendURL: "https://staging.example.com"},
		{
			name:        "production",
			environment: EnvProduction,
			frontendURL: "https://app.example.com",
			wantErr:     mail.ErrProductionEnvironment,
		},
		{name: "production with mail", environment: EnvProduction, frontendURL: "https://app.example.com", mail: smtp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Service: ServiceConfig{Environment: tt.environment}, Mail: tt.mail, Modules: defaultModules()}
			cfg.Modules.Auth.FrontendURLs = []string{tt.frontendURL}

			topics, err := senders(&cfg, nil, nil)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("senders() = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("senders() = %v", err)
			}
			if _, ok := topics[mail.Topic]; !ok {
				t.Errorf("no sender registered for %q", mail.Topic)
			}
		})
	}
}
