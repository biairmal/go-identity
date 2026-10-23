package app

import (
	"fmt"
	"time"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/config"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/lifecycle"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/metrics"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/tracer"
	"github.com/biairmal/go-sdk/lib/validator"
)

// Environments for ServiceConfig.Environment.
const (
	EnvLocal      = "local"
	EnvStaging    = "staging"
	EnvProduction = "production"
)

// Config is the whole service configuration, loaded from config/config.yaml
// (with ${VAR:default} substitution) plus an optional .env file.
type Config struct {
	Service   ServiceConfig    `mapstructure:"service"`
	HTTP      HTTPConfig       `mapstructure:"http"`
	Log       logger.Options   `mapstructure:"log"`
	Database  sqlkit.Config    `mapstructure:"database"`
	Auth      AuthConfig       `mapstructure:"auth"`
	Tracing   TracingConfig    `mapstructure:"tracing"`
	Metrics   MetricsConfig    `mapstructure:"metrics"`
	Validator validator.Config `mapstructure:"validator"`
	Lifecycle lifecycle.Config `mapstructure:"lifecycle"`
}

// ServiceConfig identifies the running service.
type ServiceConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
}

// HTTPConfig configures the HTTP server.
type HTTPConfig struct {
	Addr              string        `mapstructure:"addr"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
	MaxBodyBytes      int64         `mapstructure:"max_body_bytes"`
	CORS              CORSConfig    `mapstructure:"cors"`
}

// CORSConfig lists the browser origins allowed to call the API.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// AuthConfig toggles token validation; the rest is go-sdk auth.Config.
type AuthConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	auth.Config `mapstructure:",squash"`
}

// TracingConfig toggles tracing; the rest is go-sdk tracer.Config.
type TracingConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	tracer.Config `mapstructure:",squash"`
}

// MetricsConfig toggles metrics and sets the scrape path; the rest is go-sdk metrics.Config.
type MetricsConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Path           string `mapstructure:"path"`
	metrics.Config `mapstructure:",squash"`
}

// section is one named block of configuration that can validate itself.
type section struct {
	name     string
	validate func() error
}

// sections lists every block validated at startup. Adding a module adds its
// config block here, and nothing else.
func (c *Config) sections() []section {
	return []section{
		{"service", c.Service.validate},
		{"http", c.HTTP.validate},
		{"database", c.Database.Validate},
		{"auth", c.validateAuth},
		{"tracing", c.validateTracing},
		{"metrics", c.validateMetrics},
		{"validator", c.Validator.Validate},
		{"lifecycle", c.Lifecycle.Validate},
	}
}

// Validate runs every section's validation and names the first one that fails.
func (c *Config) Validate() error {
	for _, s := range c.sections() {
		if err := s.validate(); err != nil {
			return fmt.Errorf("config %s: %w", s.name, err)
		}
	}
	return nil
}

func (s ServiceConfig) validate() error {
	if s.Name == "" {
		return errorz.BadRequest().WithMessage("name is required")
	}
	switch s.Environment {
	case EnvLocal, EnvStaging, EnvProduction:
		return nil
	default:
		return errorz.BadRequest().WithMessage("environment must be local, staging or production")
	}
}

func (h *HTTPConfig) validate() error {
	if h.Addr == "" {
		return errorz.BadRequest().WithMessage("addr is required")
	}
	if h.MaxBodyBytes <= 0 {
		return errorz.BadRequest().WithMessage("max_body_bytes must be positive")
	}
	return nil
}

func (c *Config) validateAuth() error {
	if !c.Auth.Enabled {
		if c.Service.Environment == EnvProduction {
			return errorz.BadRequest().WithMessage("auth must be enabled in production")
		}
		return nil
	}
	return c.Auth.Validate()
}

func (c *Config) validateTracing() error {
	if !c.Tracing.Enabled {
		return nil
	}
	return c.Tracing.Validate()
}

func (c *Config) validateMetrics() error {
	if !c.Metrics.Enabled {
		return nil
	}
	if c.Metrics.Path == "" {
		return errorz.BadRequest().WithMessage("path is required when metrics are enabled")
	}
	return c.Metrics.Validate()
}

// LoadConfig reads the optional envFile and the YAML file, fills derived
// defaults and validates the result.
func LoadConfig(envFile, file string) (Config, error) {
	var c Config
	if err := config.Load(&c, config.EnvFile(envFile), config.Files(file)); err != nil {
		return c, err
	}
	c.applyDefaults()
	err := c.Validate()
	return c, err
}

// applyDefaults fills values derived from other sections.
func (c *Config) applyDefaults() {
	if c.Tracing.ServiceName == "" {
		c.Tracing.ServiceName = c.Service.Name
	}
	if c.Tracing.ServiceVersion == "" {
		c.Tracing.ServiceVersion = c.Service.Version
	}
	if c.Validator.FieldNameTag == "" {
		c.Validator.FieldNameTag = "json"
	}
}
