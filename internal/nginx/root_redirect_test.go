package nginx

import (
	"strings"
	"testing"

	"github.com/devevghenicernev-png/apigw/internal/config"
)

// TestRender_RootRedirectDefaultsTo404 pins the existing behaviour: nothing
// is mounted on / unless the operator asks for it.
func TestRender_RootRedirectDefaultsTo404(t *testing.T) {
	cfg := config.Defaults()
	serverBody, _, err := NewGenerator().Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(serverBody)
	if !strings.Contains(s, "return 404;") {
		t.Errorf("default config lost its catch-all 404:\n%s", s)
	}
	if strings.Contains(s, "location / {\n        return 301") {
		t.Errorf("unset root_redirect still emitted a redirect:\n%s", s)
	}
}

func TestRender_RootRedirect(t *testing.T) {
	cfg := config.Defaults()
	cfg.RootRedirect = "/dashboard/"
	serverBody, _, err := NewGenerator().Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(serverBody)
	if !strings.Contains(s, "return 301 /dashboard/;") {
		t.Errorf("root_redirect not emitted:\n%s", s)
	}
}

// TestRender_RootRedirectRejectsInjection is the one that matters: the value
// comes from config.yaml, which an operator may hand-edit, and it lands
// inside an nginx directive. A `;` would close the return and let anything
// follow it, so the render must abort rather than write the file.
func TestRender_RootRedirectRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"/x; } location /evil { proxy_pass http://attacker.example;",
		"/x\nreturn 200 pwned;",
		"//evil.example/",     // protocol-relative — sends visitors off-site
		"/x$host",             // nginx variable interpolation
		"javascript:alert(1)", // not a path, not http(s)
		"ftp://example.com/x", // wrong scheme
	} {
		cfg := config.Defaults()
		cfg.RootRedirect = bad
		if _, _, err := NewGenerator().Render(&cfg); err == nil {
			t.Errorf("Render accepted dangerous root_redirect %q", bad)
		}
	}
}

func TestRender_RootRedirectAcceptsValidTargets(t *testing.T) {
	for _, good := range []string{
		"/dashboard/",
		"/a/b/c",
		"https://example.com/",
		"http://example.com:8080/path",
	} {
		cfg := config.Defaults()
		cfg.RootRedirect = good
		if _, _, err := NewGenerator().Render(&cfg); err != nil {
			t.Errorf("Render rejected valid root_redirect %q: %v", good, err)
		}
	}
}
