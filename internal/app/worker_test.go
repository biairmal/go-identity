package app

import (
	"errors"
	"testing"

	"github.com/biairmal/go-identity/internal/platform/mail"
)

// TestSendersRegisterMail checks the worker routes the mail topic to a sender,
// and that it refuses to build one in production, where the development
// logging mailer would print one-time tokens to the log instead of emailing
// them.
func TestSendersRegisterMail(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		frontendURL string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Service: ServiceConfig{Environment: tt.environment}, Modules: defaultModules()}
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
