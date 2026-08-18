package nginx

import (
	"strings"
	"testing"

	"github.com/devevghenicernev-png/apigw/internal/config"
)

// TestRender_PortZeroDeployPublishesNoRoute covers the worker case: a deploy
// registered with --port 0 has no listener, so it must not be given a route.
//
// Before this was handled, the location rendered `proxy_pass
// http://127.0.0.1:0`, which nginx rejects with "invalid port in upstream".
// nginx validates the whole file at once, so a single worker took down every
// later reload — including reloads of unrelated APIs.
func TestRender_PortZeroDeployPublishesNoRoute(t *testing.T) {
	cfg := config.Defaults()
	cfg.Deploys = []config.Deploy{
		{Name: "worker", Path: "/apps/worker", Port: 0, Runtime: "go", Enabled: true},
		{Name: "web", Path: "/apps/web", Port: 3000, Runtime: "node", Enabled: true},
	}
	serverBody, httpBody, err := NewGenerator().Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	all := string(serverBody) + string(httpBody)

	if strings.Contains(all, "127.0.0.1:0") {
		t.Errorf("emitted a proxy_pass to port 0:\n%s", all)
	}
	if strings.Contains(all, "/apps/worker") {
		t.Errorf("worker with no listener still got a route:\n%s", all)
	}
	// The healthy deploy alongside it must be unaffected.
	if !strings.Contains(all, "/apps/web") {
		t.Errorf("port-bearing deploy lost its route:\n%s", all)
	}
}

// TestRender_PortZeroStaticStillServes guards the exemption: "static" runs
// portless by design and serves files through alias, so it keeps its route.
func TestRender_PortZeroStaticStillServes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Deploys = []config.Deploy{
		{Name: "docs", Path: "/docs", Port: 0, Runtime: "static", Enabled: true},
	}
	serverBody, _, err := NewGenerator().Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(serverBody), "/docs") {
		t.Errorf("static deploy lost its route:\n%s", serverBody)
	}
}

// TestRender_PortZeroWithUpstreamPoolKeepsRoute guards the other exemption:
// a pool addresses its backends explicitly, so Port is irrelevant there.
func TestRender_PortZeroWithUpstreamPoolKeepsRoute(t *testing.T) {
	cfg := config.Defaults()
	cfg.Deploys = []config.Deploy{
		{
			Name: "pooled", Path: "/apps/pooled", Port: 0, Runtime: "go", Enabled: true,
			Upstreams: []config.Upstream{{Address: "10.0.0.1:8080"}},
		},
	}
	serverBody, httpBody, err := NewGenerator().Render(&cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	all := string(serverBody) + string(httpBody)
	if !strings.Contains(all, "/apps/pooled") {
		t.Errorf("pooled deploy lost its route:\n%s", all)
	}
	if strings.Contains(all, "127.0.0.1:0") {
		t.Errorf("pooled deploy fell back to port 0:\n%s", all)
	}
}
