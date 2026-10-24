package user

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "defaults: no super admin is valid before first start", cfg: Default()},
		{
			name: "both credentials set",
			cfg:  Config{SuperAdmin: SuperAdminConfig{Email: "root@example.com", Password: "a-long-password"}},
		},
		{
			name:    "email without a password",
			cfg:     Config{SuperAdmin: SuperAdminConfig{Email: "root@example.com"}},
			wantErr: true,
		},
		{
			name:    "password without an email",
			cfg:     Config{SuperAdmin: SuperAdminConfig{Password: "a-long-password"}},
			wantErr: true,
		},
		{
			name:    "email that is not an address",
			cfg:     Config{SuperAdmin: SuperAdminConfig{Email: "root", Password: "a-long-password"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSuperAdminConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  SuperAdminConfig
		want bool
	}{
		{name: "empty", cfg: SuperAdminConfig{}},
		{name: "email only", cfg: SuperAdminConfig{Email: "root@example.com"}},
		{name: "password only", cfg: SuperAdminConfig{Password: "a-long-password"}},
		{name: "blank email", cfg: SuperAdminConfig{Email: "   ", Password: "a-long-password"}},
		{
			name: "both set",
			cfg:  SuperAdminConfig{Email: "root@example.com", Password: "a-long-password"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Configured(); got != tt.want {
				t.Errorf("Configured() = %v, want %v", got, tt.want)
			}
		})
	}
}
