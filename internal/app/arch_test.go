package app

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/biairmal/go-identity/internal/"

// TestArchitecture keeps modules independent: no module imports another
// module, and platform imports neither app nor a module.
func TestArchitecture(t *testing.T) {
	out, err := exec.Command("go", "list", "-f",
		`{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}`,
		modulePath+"...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	imports := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		imports[f[0]] = f[1:]
	}
	for _, v := range violations(imports) {
		t.Error(v)
	}
}

// violations lists every forbidden import in pkg → imports.
func violations(imports map[string][]string) []string {
	var out []string
	for pkg, deps := range imports {
		for _, dep := range deps {
			if !allowed(pkg, dep) {
				out = append(out, pkg+" must not import "+dep)
			}
		}
	}
	return out
}

// allowed reports whether pkg may import dep.
func allowed(pkg, dep string) bool {
	area, name := split(pkg)
	depArea, depName := split(dep)
	switch {
	case area == "module" && depArea == "module":
		return name == depName
	case area == "platform":
		return depArea != "app" && depArea != "module"
	default:
		return true
	}
}

// split returns the top-level area under internal/ (app, platform, module) and,
// for modules, the module name. Packages outside internal/ return "".
func split(pkg string) (area, module string) {
	rest, ok := strings.CutPrefix(pkg, modulePath)
	if !ok {
		return "", ""
	}
	parts := strings.Split(rest, "/")
	if parts[0] == "module" && len(parts) > 1 {
		return "module", parts[1]
	}
	return parts[0], ""
}

func TestArchitectureRules(t *testing.T) {
	const m = modulePath + "module/"
	tests := []struct {
		pkg, dep string
		ok       bool
	}{
		{m + "a", m + "b", false},
		{m + "a/sub", m + "b/sub", false},
		{m + "a/sub", m + "a", true},
		{m + "a", m + "a/sub", true},
		{m + "a", modulePath + "platform/httpx", true},
		{modulePath + "platform/httpx", modulePath + "app", false},
		{modulePath + "platform/httpx", m + "a", false},
		{modulePath + "platform/httpx", modulePath + "platform/apierr", true},
		{modulePath + "app", m + "a", true},
		{m + "a", "net/http", true},
	}
	for _, tt := range tests {
		if got := allowed(tt.pkg, tt.dep); got != tt.ok {
			t.Errorf("allowed(%s, %s) = %v, want %v", tt.pkg, tt.dep, got, tt.ok)
		}
	}
}
