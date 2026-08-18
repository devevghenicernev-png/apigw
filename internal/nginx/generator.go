// Package nginx renders apigw's nginx configuration from embedded templates,
// writes it atomically, validates with `nginx -t`, and reloads with rollback
// on failure.
//
// The generated file always starts with a banner that includes the version,
// timestamp, and SHA-256 hash. `apigw doctor` later verifies the hash to
// detect hand-edits.
package nginx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/devevghenicernev-png/apigw/internal/assets"
	"github.com/devevghenicernev-png/apigw/internal/build"
	"github.com/devevghenicernev-png/apigw/internal/config"
	"github.com/devevghenicernev-png/apigw/internal/deploy"
	apitls "github.com/devevghenicernev-png/apigw/internal/tls"
)

// Generator renders Config into nginx config bytes. Stateless and pure;
// safe to call from anywhere, including tests with no filesystem.
type Generator struct{}

func NewGenerator() *Generator { return &Generator{} }

// resolveSampleRate clamps the operator's sample percent into the
// 1-100 range nginx's split_clients can handle. 0 means "default", which
// for log sampling means "no sampling = 100%".
func resolveSampleRate(pct int) int {
	if pct <= 0 {
		return 100
	}
	if pct > 100 {
		return 100
	}
	return pct
}

// templateData is the struct the templates dereference. Keep field names
// stable — they appear in template source under assets/nginx/.
type templateData struct {
	Banner     string
	HTTPPort   int
	HTTPSPort  int
	ServerName string
	APIs       []apiEntry
	Deploys    []deployEntry
	Webhook    config.Webhook
	Dashboard  config.Dashboard

	// RootRedirect, when non-empty, replaces the catch-all 404 on / with a
	// 301 to this target. Validated by sanitizeRedirect before it gets here.
	RootRedirect string

	// TLS-mode fields. Only populated when cfg.TLS.Strategy != "none".
	TLSStrategy           string
	TLSDomains            []string
	CertFile              string
	KeyFile               string
	AcmeWebroot           string
	HSTSIncludeSubDomains bool

	// mTLS at server scope — set if any API has MTLS configured.
	// nginx supports one ssl_client_certificate per server block, so we
	// use ssl_verify_client optional at server scope and let per-location
	// auth_request enforce per-API.
	MTLSAnyEnabled bool
	MTLSCAFile     string

	// OCSPStapling, when true, emits ssl_stapling + ssl_stapling_verify
	// and a resolver directive. Off by default — Let's Encrypt killed
	// their OCSP responders in Aug 2025, so flipping this on for LE
	// certs is worse than useless. Operators with non-LE certs
	// (DigiCert, Sectigo, internal CA) opt in via `apigw tls ocsp enable`.
	OCSPStapling bool

	// Gzip / Brotli at SERVER scope. Stock Debian/Ubuntu nginx.conf
	// already declares `gzip on;` in http{}, so emitting again at http
	// scope causes a duplicate-directive error. Server-scope is valid
	// for both directives and overrides http-scope cleanly, which is
	// what operators expect anyway. We render the same struct as
	// httpData.Gzip / .Brotli — the templates differ only in where the
	// block lives.
	Gzip   gzipEntry
	Brotli brotliEntry
}

// httpData drives the new _http.tmpl that renders into
// /etc/nginx/conf.d/apigw-http.conf — anything that has to live at http{}
// scope (named upstreams, rate-limit zones, CORS origin map). Gzip/Brotli
// used to live here too but moved to server-scope after BUG-1b — see the
// comment block at the top of _http.tmpl.
type httpData struct {
	Banner         string
	Upstreams      []upstreamEntry
	RateLimitZones []rateLimitZone
	CORSOriginMap  []string            // exact-match regex tokens (already escaped)
	SplitClients   []splitClientsEntry // E13 — % traffic distribution

	// v0.2.0
	CacheZones    []cacheZoneEntry
	JSONLogFormat bool
	LogSampleRate int // 1-100

	// IPReputationFeed — when non-empty, emit a global geo
	// $apigw_ip_blocked block that includes the file. Set from
	// Security.IPReputationFeed when at least one API opts in via
	// BotGuard.UseIPReputation; otherwise empty (no emission).
	IPReputationFeed string

	// TLSPatternMaps — one per-API map for BotGuard.BlockTLSPatterns.
	TLSPatternMaps []tlsPatternMapEntry
}

type cacheZoneEntry struct {
	Name    string
	Path    string
	MaxSize string // "256m"
}

// streamData drives the stream{} fragment: TCP/UDP servers + their
// upstreams. Lives in a separate include file so operators who don't
// use any TCP/UDP forwarding don't get a stream{} block at all.
type streamData struct {
	Banner          string
	Streams         []streamEntry
	StreamUpstreams []streamUpstream
}

type streamEntry struct {
	Name         string
	Protocol     string // "tcp" | "udp"
	ListenPort   int
	ProxyTimeout string
	Enabled      bool
}

type streamUpstream struct {
	Name    string
	Servers []string // "host:port"
}

// splitClientsEntry renders one nginx split_clients block AND, when
// Pin is set, an accompanying map that lets clients with
// `$http_<pin_header>: 1` bypass the split and go straight to the
// canary. The combined output is the per-API "target" variable used
// by proxy_pass.
type splitClientsEntry struct {
	Name        string // split-output var; e.g. "apigw_billing_split"
	HashSource  string // typically $request_id (random) or $remote_addr (sticky)
	CanaryPct   int    // 0-100; rest goes to primary
	CanaryName  string // upstream name for canary
	PrimaryName string // upstream name for primary

	// TargetName is the final variable referenced by `proxy_pass
	// http://$<TargetName>`. Equals Name when no Pin is set, or a
	// distinct combined variable when Pin overrides the split.
	TargetName string

	// PinHeader (lowercased, dashes→underscores) names the nginx var
	// the map keys on — e.g. "x_canary" for header "X-Canary". Empty =
	// no pin map emitted.
	PinHeader string

	// Variants holds the N-way pool split when this entry represents
	// API.Variants rather than canary. Empty for canary entries.
	// The last variant gets the "*" wildcard so rounding errors don't
	// drop traffic.
	Variants []variantSplit
}

// variantSplit is one entry in an N-way variant split. The generator
// orders these so the last one (after stable sort by Weight desc) is
// the wildcard catch.
type variantSplit struct {
	Pct          int    // 0-100; 0 for the wildcard entry
	UpstreamName string // e.g. apigw_billing_v2
	Wildcard     bool   // true → emit `*` instead of `N%`
}

type gzipEntry struct {
	Enabled   bool
	Level     int
	MinLength int
	Types     []string
}

type brotliEntry struct {
	Enabled   bool
	Level     int
	MinLength int
	Types     []string
}

type upstreamEntry struct {
	Name        string // sanitised — used both here and in proxy_pass http://apigw_<name>
	LoadBalance string // "" | "least_conn" | "ip_hash" | "random"
	Servers     []upstreamServer
	Keepalive   int

	// KeepaliveTimeout / KeepaliveRequests are emitted only when set
	// (operator-supplied via API.ConnectionPool). Empty strings inherit
	// the nginx defaults (60s, 1000) — keeps the generated config
	// minimal for the common case.
	KeepaliveTimeout  string // e.g. "60s"
	KeepaliveRequests int

	// Legacy single-port view kept until every call site is migrated; unused
	// once buildUpstream is the sole producer.
	Port        int
	MaxFails    int
	FailTimeout string // e.g. "10s"
}

type upstreamServer struct {
	Address     string // host:port
	Weight      int    // 0 = default (1)
	MaxFails    int
	FailTimeout string
	Backup      bool
	Down        bool
}

type rateLimitZone struct {
	Name string // e.g. "hello_ip"
	Key  string // e.g. "$binary_remote_addr"
	RPS  int
}

type apiEntry struct {
	Name         string
	Port         int
	Path         string
	Description  string
	Enabled      bool
	UpstreamName string // "" = no upstream block; we fall back to proxy_pass http://127.0.0.1:port

	// Per-API middleware (F2-F6 fields). Empty values render no extra directives.
	MaxBodySize     string            // F2
	RequestHeaders  map[string]string // F2
	ResponseHeaders map[string]string // F2
	ResponseHide    []string          // F2
	Allow           []string          // F2 (IP rules)
	Deny            []string          // F2
	CORS            *corsEntry        // F2
	BasicAuthRealm  string            // F2 (empty = no basic auth)
	BasicAuthFile   string            // F2 — path to htpasswd file
	RateLimitZone   string            // F4 — zone name
	RateLimitBurst  int               // F4
	ForwardAuth     *forwardAuthEntry // F6
	NextUpstream    string            // F5 — proxy_next_upstream conditions

	// NextUpstreamTries → proxy_next_upstream_tries. 0 = inherit
	// template default (3). NextUpstreamTimeout (in seconds, "0" = no
	// limit) becomes proxy_next_upstream_timeout; ReadTimeout (in
	// seconds) becomes proxy_read_timeout. Empty strings inherit the
	// template defaults.
	NextUpstreamTries   int
	NextUpstreamTimeout string
	ReadTimeout         string

	// Buffering — when non-nil, overrides per-route. Each child field
	// emits only when non-empty / non-default.
	Buffering *bufferingEntry

	// Rewrites — emitted in order at the top of the location block,
	// before any auth_request / proxy_pass. Each rule becomes
	// `rewrite <Match> <Replace> <Flag>;`.
	Rewrites []rewriteEntry

	GRPC             bool   // F9 — emit grpc_pass instead of proxy_pass
	JWT              bool   // F12 — emit auth_request /_apigw_jwt/<api>
	JWTDashboardPort int    // F12 — port the dashboard daemon listens on
	CustomLocation   string // F14 — raw nginx directives, location-scoped
	CustomServer     string // F14 — raw nginx directives, server-scoped (rendered server.tmpl)
	MTLS             bool   // E1 — emit ssl_verify_client + auth_request /_apigw_mtls/<api>
	MTLSCAFile       string // E1 — path to the CA bundle nginx loads
	MTLSOptional     bool   // E1 — ssl_verify_client optional vs on

	// v0.2.0 additions.
	APIKey        bool           // emit auth_request /_apigw_apikey_<name>
	HMAC          bool           // emit auth_request /_apigw_hmac_<name>
	Session       bool           // emit auth_request /_apigw_session_<name>
	OAuth2        bool           // emit auth_request /_apigw_oauth2_<name>
	Mock          bool           // route hits internal mock handler instead of upstream
	Cache         *cacheEntry    // proxy_cache directives
	Timeouts      *timeoutsEntry // per-route timeouts
	Mirror        *mirrorEntry   // shadow traffic copy
	GRPCWeb       bool           // wraps gRPC for browsers via grpc_web_proxy_*
	StickyMode    string         // "ip_hash" or "cookie:<name>"
	BotGuard      *botGuardEntry
	AccessLogMode string // "" (default) | "json" | "combined" | "off"
	AccessLogFile string // "" = nginx default path

	// EarlyHints emits one `add_header Link …` per entry. HTTP2Push
	// emits one `http2_push <path>;` per entry.
	EarlyHints []string
	HTTP2Push  []string

	// Lifecycle drives the state-machine response. Only one of the
	// three booleans is ever true.
	LifecycleDraft          bool   // emit `return 503;`
	LifecycleDeprecated     bool   // emit Deprecation + Sunset headers
	LifecycleSunsetAt       string // RFC1123 timestamp string for Sunset header
	LifecycleRetired        bool   // emit `return 410;` + optional Link
	LifecycleReplacementURL string // populated when retired or deprecated

	// Versions, when non-nil, emits one sub-location per entry BEFORE
	// the main API location. nginx's longest-prefix-match guarantees
	// requests to /<Path>/<Name>/… hit the version-specific block.
	// Strategy is currently always "path" — header/query require map
	// plumbing on top and are accepted in config for forward-compat.
	Versions []versionRoute
}

// versionRoute is one rendered API version. See config.APIVersion for
// the source-of-truth fields.
type versionRoute struct {
	Name           string // "v1"
	FullPath       string // "/api/foo/v1/"
	Upstream       string // host:port — empty means inherit api primary
	State          string // "active" | "deprecated" | "retired"
	SunsetAt       string // RFC1123 (Sunset header format)
	ReplacementURL string // populated when retired
}

type cacheEntry struct {
	Duration     string
	Methods      []string
	Key          string
	BypassHeader string
	VaryHeaders  []string
	ZoneName     string
}

type timeoutsEntry struct {
	Connect string
	Read    string
	Send    string
}

type mirrorEntry struct {
	Path          string // internal location name we proxy_pass to
	UpstreamURL   string
	SamplePercent int
	IgnoreBody    bool
}

type botGuardEntry struct {
	BlockedAgents         []string
	AllowedAgents         []string
	RequireUserAgent      bool
	BlockEmptyReferer     bool
	BlockCommonScanners   bool
	UseIPReputation       bool // emit `if ($apigw_ip_blocked = 1) { return 403; }`
	HasTLSPatterns        bool // emit `if ($apigw_tls_blocked_<name> = 1) { return 403; }`
	ForwardTLSFingerprint bool // emit proxy_set_header X-Apigw-TLS-Profile
}

// tlsPatternMapEntry drives the http{}-scope `map` for per-API TLS
// pattern blocking.
type tlsPatternMapEntry struct {
	APIName  string
	Patterns []string // regex fragments — already operator-supplied, emitted as `~`-prefixed
}

type corsEntry struct {
	Methods     string // pre-joined "GET, POST, OPTIONS"
	Headers     string // pre-joined "Content-Type, Authorization"
	Credentials bool
	MaxAge      int
}

type forwardAuthEntry struct {
	UpstreamName string // location /_apigw_auth_<name>
	Upstream     string // proxy_pass target (URL form)
	SignInURL    string
	SetHeaders   []string // auth_request_set $var $upstream_http_<header>
}

// rewriteEntry is one nginx `rewrite` directive. Flag is sanitised /
// defaulted in the middleware layer.
type rewriteEntry struct {
	Match   string
	Replace string
	Flag    string // "last" | "break" | "redirect" | "permanent"
}

// bufferingEntry mirrors config.Buffering. Request/Response are
// pre-rendered to "", "on", or "off" in the middleware layer so the
// template doesn't need a helper to dereference *bool.
type bufferingEntry struct {
	Request              string // "" | "on" | "off"
	Response             string // "" | "on" | "off"
	ClientBodyBufferSize string
	ProxyBufferSize      string
	ProxyBuffers         string
}

type deployEntry struct {
	Name       string
	Port       int
	Path       string
	Runtime    string
	SHA        string
	CurrentDir string // /var/lib/apigw/<name>/current
	Enabled    bool

	// Mirrors of apiEntry middleware so deploys share the same surface.
	MaxBodySize     string
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	ResponseHide    []string
	Allow           []string
	Deny            []string
	CORS            *corsEntry
	BasicAuthRealm  string
	BasicAuthFile   string
	RateLimitZone   string
	RateLimitBurst  int
	ForwardAuth     *forwardAuthEntry
	UpstreamName    string
	NextUpstream    string

	NextUpstreamTries   int
	NextUpstreamTimeout string
	ReadTimeout         string
	GRPC                bool
	JWT                 bool
	JWTDashboardPort    int
	CustomLocation      string
	CustomServer        string

	// Mirror fields that _locations.tmpl reads but deploys leave at zero
	// (they fall through to plain proxy). Without these the shared
	// template panics: `can't evaluate field LifecycleDraft in type
	// nginx.deployEntry` — broke every `migrate` and `dashboard start`.
	Description             string
	MTLS                    bool
	MTLSCAFile              string
	MTLSOptional            bool
	APIKey                  bool
	HMAC                    bool
	Session                 bool
	OAuth2                  bool
	Mock                    bool
	Cache                   *cacheEntry
	Timeouts                *timeoutsEntry
	Mirror                  *mirrorEntry
	GRPCWeb                 bool
	StickyMode              string
	BotGuard                *botGuardEntry
	AccessLogMode           string
	AccessLogFile           string
	EarlyHints              []string
	HTTP2Push               []string
	LifecycleDraft          bool
	LifecycleDeprecated     bool
	LifecycleSunsetAt       string
	LifecycleRetired        bool
	LifecycleReplacementURL string
	Versions                []versionRoute
	Buffering               *bufferingEntry
	Rewrites                []rewriteEntry
}

// RenderStream produces the TCP/UDP stream{} include. Empty when no
// streams are configured — caller writes "" to the file so the include
// directive parses but yields no servers.
func (g *Generator) RenderStream(cfg *config.Config) ([]byte, error) {
	if len(cfg.Streams) == 0 {
		return nil, nil
	}
	tmpl, err := template.New("stream").ParseFS(assets.Nginx(), "nginx/stream.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse stream template: %w", err)
	}
	sd := streamData{Banner: "MANAGED BY apigw — stream{} scope"}
	for _, s := range cfg.Streams {
		if !s.Enabled {
			continue
		}
		sd.Streams = append(sd.Streams, streamEntry{
			Name:         s.Name,
			Protocol:     s.Protocol,
			ListenPort:   s.ListenPort,
			ProxyTimeout: s.ProxyTimeout,
			Enabled:      true,
		})
		su := streamUpstream{Name: s.Name}
		for _, u := range s.Upstreams {
			su.Servers = append(su.Servers, u.Address)
		}
		sd.StreamUpstreams = append(sd.StreamUpstreams, su)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "stream", sd); err != nil {
		return nil, fmt.Errorf("execute stream: %w", err)
	}
	return buf.Bytes(), nil
}

// Render produces both nginx config files apigw owns: the server-block
// payload (returned as `serverBytes`) and the http-scope payload that lands
// in /etc/nginx/conf.d/apigw-http.conf (returned as `httpBytes`). The
// caller writes both atomically and runs `nginx -t` once per pair.
//
// Template selection for server bytes:
//   - cfg.TLS.Strategy is "" or "none" → server.tmpl (HTTP-only)
//   - otherwise                        → tls-server.tmpl (HTTPS + HTTP redirect)
func (g *Generator) Render(cfg *config.Config) (serverBytes, httpBytes []byte, err error) {
	tmpl, err := template.New("apigw").ParseFS(
		assets.Nginx(),
		"nginx/server.tmpl",
		"nginx/tls-server.tmpl",
		"nginx/_locations.tmpl",
		"nginx/_http.tmpl",
	)
	if err != nil {
		return nil, nil, fmt.Errorf("parse templates: %w", err)
	}

	// Build the master upstream + rate-limit-zone lists FIRST — each
	// API/Deploy below references them by name.
	upstreams := make([]upstreamEntry, 0, len(cfg.APIs)+len(cfg.Deploys))
	rlZones := make([]rateLimitZone, 0)
	corsOriginsSeen := map[string]struct{}{}
	corsOrigins := []string{}

	// Scan once for mTLS server-scope state.
	mtlsAny := false
	mtlsCAFile := ""
	for _, a := range cfg.APIs {
		if a.MTLS != nil && a.MTLS.CAFile != "" {
			mtlsAny = true
			if mtlsCAFile == "" {
				mtlsCAFile = a.MTLS.CAFile
			}
		}
	}

	apis := make([]apiEntry, 0, len(cfg.APIs))
	for _, a := range cfg.APIs {
		if err := sanitizeName(a.Name); err != nil {
			return nil, nil, fmt.Errorf("api: %w", err)
		}
		path := a.Path
		if path == "" {
			path = "/api/" + a.Name
		}
		if err := sanitizePath(path); err != nil {
			return nil, nil, fmt.Errorf("api %s: %w", a.Name, err)
		}
		// Every enabled API with a real port gets a named upstream block so
		// passive health checks (max_fails/fail_timeout) and keepalive can
		// be applied without per-location duplication.
		entry := apiEntry{
			Name:        a.Name,
			Port:        a.Port,
			Path:        path,
			Description: a.Description,
			Enabled:     a.Enabled,
		}
		entry.GRPC = a.GRPC
		// nginx forbids two `auth_request` directives in the same location,
		// so we pick exactly one auth method per route. Priority order:
		// JWT > MTLS > APIKey > HMAC > OAuth2 > Session. When more than one
		// is configured the lower-priority methods are silently dropped at
		// render time — the config remains intact so the operator can
		// toggle priorities by removing the higher one.
		hasJWT := a.JWT != nil
		hasMTLS := a.MTLS != nil
		hasAPIKey := a.APIKey != nil && len(a.APIKey.Keys) > 0
		hasHMAC := a.HMAC != nil && len(a.HMAC.Keys) > 0
		hasOAuth2 := a.OAuth2 != nil && a.OAuth2.IntrospectionURL != ""
		hasSession := a.Session
		switch {
		case hasJWT:
			entry.JWT = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		case hasMTLS:
			entry.MTLS = true
			entry.MTLSCAFile = a.MTLS.CAFile
			entry.MTLSOptional = a.MTLS.Optional
			entry.JWTDashboardPort = cfg.Dashboard.Port
		case hasAPIKey:
			entry.APIKey = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		case hasHMAC:
			entry.HMAC = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		case hasOAuth2:
			entry.OAuth2 = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		case hasSession:
			entry.Session = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		}
		entry.CustomLocation = a.CustomLocation
		entry.CustomServer = a.CustomServer

		// v0.2.0 — populate the new middleware fields.
		if a.Mock != nil {
			entry.Mock = true
			if entry.JWTDashboardPort == 0 {
				entry.JWTDashboardPort = cfg.Dashboard.Port
			}
		}
		if a.Cache != nil && a.Cache.Duration != "" {
			methods := a.Cache.Methods
			if len(methods) == 0 {
				methods = []string{"GET", "HEAD"}
			}
			key := a.Cache.Key
			if key == "" {
				key = "$scheme$request_method$host$request_uri"
			}
			entry.Cache = &cacheEntry{
				Duration: a.Cache.Duration, Methods: methods, Key: key,
				BypassHeader: a.Cache.BypassHeader,
				VaryHeaders:  a.Cache.VaryHeaders,
				ZoneName:     "apigw_cache_" + a.Name,
			}
		}
		if a.Timeouts != nil {
			entry.Timeouts = &timeoutsEntry{
				Connect: a.Timeouts.Connect,
				Read:    a.Timeouts.Read,
				Send:    a.Timeouts.Send,
			}
		}
		if a.Mirror != nil && a.Mirror.Target != "" {
			pct := a.Mirror.SamplePercent
			if pct <= 0 || pct > 100 {
				pct = 100
			}
			entry.Mirror = &mirrorEntry{
				Path:          "/_apigw_mirror_" + a.Name,
				UpstreamURL:   "http://" + a.Mirror.Target,
				SamplePercent: pct,
				IgnoreBody:    a.Mirror.IgnoreBody,
			}
		}
		entry.GRPCWeb = a.GRPCWeb
		entry.StickyMode = a.StickySession
		if a.BotGuard != nil {
			entry.BotGuard = &botGuardEntry{
				BlockedAgents:         a.BotGuard.BlockUserAgents,
				AllowedAgents:         a.BotGuard.AllowUserAgents,
				RequireUserAgent:      a.BotGuard.RequireUserAgent,
				BlockEmptyReferer:     a.BotGuard.BlockEmptyReferer,
				BlockCommonScanners:   a.BotGuard.BlockCommonScanners,
				UseIPReputation:       a.BotGuard.UseIPReputation && cfg.Security.IPReputationFeed != "",
				HasTLSPatterns:        len(a.BotGuard.BlockTLSPatterns) > 0,
				ForwardTLSFingerprint: a.BotGuard.ForwardTLSFingerprint,
			}
		}
		entry.AccessLogMode = a.AccessLog
		entry.AccessLogFile = a.AccessLogFile
		entry.EarlyHints = a.EarlyHints
		entry.HTTP2Push = a.HTTP2Push
		if lc := a.Lifecycle; lc != nil {
			switch lc.State {
			case "draft":
				entry.LifecycleDraft = true
			case "deprecated":
				entry.LifecycleDeprecated = true
				if !lc.SunsetAt.IsZero() {
					entry.LifecycleSunsetAt = lc.SunsetAt.Format(time.RFC1123)
				}
				entry.LifecycleReplacementURL = lc.ReplacementURL
			case "retired":
				entry.LifecycleRetired = true
				entry.LifecycleReplacementURL = lc.ReplacementURL
			}
		}
		// Multi-version routing — emit one location per version BEFORE the
		// main API location. nginx longest-prefix-match guarantees these
		// take precedence over the parent <Path>/.
		if v := a.Versioning; v != nil && len(v.Versions) > 0 {
			base := strings.TrimRight(entry.Path, "/")
			// Fallback upstream when a version doesn't set its own — use
			// the API's primary upstream-name if there's a pool, else
			// 127.0.0.1:<port>. Matches the main-location convention so
			// versions inherit the parent route's destination by default.
			fallback := ""
			if entry.UpstreamName != "" {
				fallback = entry.UpstreamName
			} else if entry.Port > 0 {
				fallback = fmt.Sprintf("127.0.0.1:%d", entry.Port)
			}
			entry.Versions = make([]versionRoute, 0, len(v.Versions))
			for _, ver := range v.Versions {
				state := strings.ToLower(ver.State)
				if state == "" {
					state = "active"
				}
				up := ver.Upstream
				if up == "" {
					up = fallback
				}
				route := versionRoute{
					Name:           ver.Name,
					FullPath:       base + "/" + ver.Name + "/",
					Upstream:       up,
					State:          state,
					ReplacementURL: ver.ReplacementURL,
				}
				if !ver.SunsetAt.IsZero() {
					route.SunsetAt = ver.SunsetAt.Format(time.RFC1123)
				}
				entry.Versions = append(entry.Versions, route)
			}
		}

		// BlueGreen, when set, replaces a.Upstreams as the primary pool.
		// The non-active pool is intentionally NOT emitted as a separate
		// upstream block — keeping the nginx config minimal AND making
		// rollback a one-line swap rather than an upstream/proxy_pass
		// re-rewrite. The other pool lives only in our config.yaml.
		//
		// Variants override entirely: every variant gets its own upstream
		// block and proxy_pass routes through the split var, so the
		// primary apigw_<name> upstream would be dead config. Skip it.
		primaryUpstreams := a.Upstreams
		primaryPort := a.Port
		if bg := a.BlueGreen; bg != nil {
			if active := bg.ActivePool(); len(active) > 0 {
				primaryUpstreams = active
				primaryPort = 0 // legacy single-port unused when BG drives the pool
			}
		}
		skipPrimaryUpstream := variantsActive(a)

		if up, ok := buildUpstream(a.Name, primaryPort, primaryUpstreams, a.LoadBalance, a.HealthCheck); ok && !skipPrimaryUpstream {
			// Wire LB strategy extensions: consistent_hash + sticky cookie
			// override the basic least_conn/ip_hash/random returned by
			// buildUpstream.
			if a.LoadBalance == "consistent_hash" && a.HashKey != "" {
				up.LoadBalance = "hash " + a.HashKey + " consistent"
			} else if strings.HasPrefix(a.StickySession, "cookie:") {
				up.LoadBalance = "hash $cookie_" +
					strings.TrimPrefix(a.StickySession, "cookie:") + " consistent"
			} else if a.StickySession == "ip_hash" {
				up.LoadBalance = "ip_hash"
			}
			applyConnectionPool(&up, a.ConnectionPool)
			entry.UpstreamName = "apigw_" + a.Name
			upstreams = append(upstreams, up)
		}
		// Legacy fallback path retained for safety — replaced once every
		// API/Deploy migrates to the buildUpstream output above.
		if false && a.Port > 0 {
			entry.UpstreamName = "apigw_" + a.Name
			maxFails, failTimeout := 3, "10s"
			if a.HealthCheck != nil {
				if a.HealthCheck.MaxFails > 0 {
					maxFails = a.HealthCheck.MaxFails
				}
				if a.HealthCheck.FailTimeout != "" {
					failTimeout = a.HealthCheck.FailTimeout
				}
			}
			upstreams = append(upstreams, upstreamEntry{
				Name:        a.Name,
				Port:        a.Port,
				MaxFails:    maxFails,
				FailTimeout: failTimeout,
			})
		}
		if err := applyMiddleware(&entry, a, cfg.Listen.MaxBodySize, &rlZones, &corsOriginsSeen, &corsOrigins); err != nil {
			return nil, nil, fmt.Errorf("api %s: %w", a.Name, err)
		}
		apis = append(apis, entry)
	}

	deploys := make([]deployEntry, 0, len(cfg.Deploys))
	for _, d := range cfg.Deploys {
		if err := sanitizeName(d.Name); err != nil {
			return nil, nil, fmt.Errorf("deploy: %w", err)
		}
		path := d.Path
		if path == "" {
			path = "/apps/" + d.Name
		}
		if err := sanitizePath(path); err != nil {
			return nil, nil, fmt.Errorf("deploy %s: %w", d.Name, err)
		}
		// A deploy with no listener and no upstream pool is a worker: still
		// cloned, built and supervised, but there is nothing to proxy to.
		// Publishing a route for it would render `proxy_pass http://127.0.0.1:0`,
		// which nginx rejects — and since validation happens on the whole file,
		// one such worker makes every later reload fail, not just its own route.
		// "static" is exempt: it legitimately runs portless and serves via alias.
		if d.Runtime != "static" && d.Port == 0 && len(d.Upstreams) == 0 {
			continue
		}
		entry := deployEntry{
			Name:       d.Name,
			Port:       d.Port,
			Path:       path,
			Runtime:    d.Runtime,
			SHA:        shortSHA(d.LastSHA),
			CurrentDir: deploy.CurrentSymlink(d.Name),
			Enabled:    d.Enabled,
		}
		entry.GRPC = d.GRPC
		// Deploy-level JWT / Custom fields mirror API. Deploy struct doesn't
		// have them yet — added below in config.go. Read defensively in case
		// koanf zero-values are present.
		if d.JWT != nil {
			entry.JWT = true
			entry.JWTDashboardPort = cfg.Dashboard.Port
		}
		entry.CustomLocation = d.CustomLocation
		entry.CustomServer = d.CustomServer
		if d.Runtime != "static" {
			if up, ok := buildUpstream(d.Name, d.Port, d.Upstreams, d.LoadBalance, d.HealthCheck); ok {
				entry.UpstreamName = "apigw_" + d.Name
				upstreams = append(upstreams, up)
			}
		}
		if err := applyMiddlewareDeploy(&entry, d, cfg.Listen.MaxBodySize, &rlZones, &corsOriginsSeen, &corsOrigins); err != nil {
			return nil, nil, fmt.Errorf("deploy %s: %w", d.Name, err)
		}
		deploys = append(deploys, entry)
	}

	// Pre-pass for variants / canary splits — runs BEFORE the server
	// template renders so the location's proxy_pass uses the rewritten
	// UpstreamName (target variable). Both the side upstream blocks and
	// the split_clients map are read by the http template later; their
	// order doesn't matter to nginx.
	//
	// Precedence when multiple traffic-splitting strategies are set on
	// one API: Variants > BlueGreen > Canary. (BlueGreen runs inline in
	// the apis loop above; this pre-pass handles Variants and Canary.)
	splits := []splitClientsEntry{}
	for ai, a := range cfg.APIs {
		// Variants take precedence over Canary on the same API.
		if len(a.Variants) > 0 {
			vSplit, vUpstreams := buildVariantSplit(a)
			if vSplit != nil {
				splits = append(splits, *vSplit)
				upstreams = append(upstreams, vUpstreams...)
				apis[ai].UpstreamName = "$" + vSplit.TargetName
			}
			continue
		}

		if a.Canary == nil || a.Canary.Weight <= 0 {
			continue
		}
		canaryUp := "apigw_" + a.Name + "_canary"
		if up, ok := buildUpstream(a.Name+"_canary", 0, a.Canary.Upstreams, a.LoadBalance, a.HealthCheck); ok {
			applyConnectionPool(&up, a.ConnectionPool)
			upstreams = append(upstreams, up)
		}
		// Sticky → hash by IP (consistent per-client); non-sticky → hash
		// by request ID (uniform per-request distribution, what you want
		// for canary load-balancing experiments).
		hashSource := "$request_id"
		if a.Canary.Sticky {
			hashSource = "$remote_addr"
		}
		splitName := "apigw_" + a.Name + "_split"
		targetName := splitName
		pinHeader := ""
		if a.Canary.PinHeader != "" {
			// Override target via the combined map; the pin header value
			// "1" pins to canary, "0"/missing falls through to the split.
			targetName = "apigw_" + a.Name + "_target"
			pinHeader = strings.ToLower(strings.ReplaceAll(a.Canary.PinHeader, "-", "_"))
		}
		splits = append(splits, splitClientsEntry{
			Name:        splitName,
			HashSource:  hashSource,
			CanaryPct:   a.Canary.Weight,
			CanaryName:  canaryUp,
			PrimaryName: "apigw_" + a.Name,
			TargetName:  targetName,
			PinHeader:   pinHeader,
		})
		apis[ai].UpstreamName = "$" + targetName
	}

	serverName := nonEmpty(cfg.Listen.ServerName, "_")
	// Validate each token (space-separated) — accepts hostnames, `_` catch-all,
	// and `*` wildcards. Anything else aborts the render.
	for _, n := range strings.Fields(serverName) {
		if err := sanitizeServerName(n); err != nil {
			return nil, nil, fmt.Errorf("listen.server_name: %w", err)
		}
	}

	if cfg.RootRedirect != "" {
		if err := sanitizeRedirect(cfg.RootRedirect); err != nil {
			return nil, nil, fmt.Errorf("root_redirect: %w", err)
		}
	}

	data := templateData{
		RootRedirect:   cfg.RootRedirect,
		HTTPPort:       nonZero(cfg.Listen.HTTPPort, 80),
		HTTPSPort:      nonZero(cfg.Listen.HTTPSPort, 443),
		ServerName:     serverName,
		APIs:           apis,
		Deploys:        deploys,
		Webhook:        cfg.Webhook,
		Dashboard:      cfg.Dashboard,
		AcmeWebroot:    apitls.AcmeWebrootDir(),
		Banner:         "PLACEHOLDER", // substituted post-render
		MTLSAnyEnabled: mtlsAny,
		MTLSCAFile:     mtlsCAFile,
		OCSPStapling:   cfg.TLS.OCSPStapling,
		Gzip:           resolveGzip(cfg),
		Brotli:         resolveBrotli(cfg),
	}

	templateName := "server.tmpl"
	strategy := apitls.Strategy(cfg.TLS.Strategy)
	if strategy != "" && strategy != apitls.StrategyNone {
		templateName = "tls-server.tmpl"
		domains := cfg.TLS.Domains
		if len(domains) == 0 {
			return nil, nil, fmt.Errorf("tls strategy %q but no domains configured", strategy)
		}
		primary := domains[0]
		certFile, keyFile, _ := apitls.CertPaths(primary)
		data.TLSStrategy = string(strategy)
		data.TLSDomains = domains
		data.CertFile = certFile
		data.KeyFile = keyFile
		data.AcmeWebroot = apitls.AcmeWebrootDir()
		// DuckDNS: omit includeSubDomains — we don't own siblings under
		// *.duckdns.org. Same trap noted in ARCHITECTURE.md §"HSTS trap".
		data.HSTSIncludeSubDomains = strategy != apitls.StrategyDuckDNS
		if data.ServerName == "_" {
			data.ServerName = strings.Join(domains, " ")
		}
	}

	var body bytes.Buffer
	if err := tmpl.ExecuteTemplate(&body, templateName, data); err != nil {
		return nil, nil, fmt.Errorf("execute %s: %w", templateName, err)
	}

	// Hash the canonical body (banner-stripped) and substitute into the banner.
	canonical := stripBanner(body.Bytes())
	sum := sha256.Sum256(canonical)
	hash := hex.EncodeToString(sum[:])[:16]
	banner := fmt.Sprintf("MANAGED BY apigw — do not edit. version=%s commit=%s generated=%s hash=%s",
		build.Version, build.Commit, time.Now().UTC().Format(time.RFC3339), hash)
	serverBytes = bytes.Replace(body.Bytes(),
		[]byte("# PLACEHOLDER"),
		[]byte("# "+banner),
		1,
	)

	// Now render the http-scope payload — splits/canary upstreams/
	// UpstreamName rewrites happen earlier (around the apis pre-pass)
	// so both server and http templates see the same view.

	// Collect cache zones from any API with response caching configured.
	var cacheZones []cacheZoneEntry
	for _, a := range apis {
		if a.Cache != nil {
			cacheZones = append(cacheZones, cacheZoneEntry{
				Name: a.Cache.ZoneName,
				Path: "/var/cache/nginx/" + a.Cache.ZoneName,
				MaxSize: func() string {
					return "256m"
				}(),
			})
		}
	}
	// Collect TLS pattern maps + decide if the IP reputation block should
	// emit. The feed only renders when at least one API opts in — empty
	// http{} otherwise.
	var tlsMaps []tlsPatternMapEntry
	ipRepNeeded := false
	for _, a := range cfg.APIs {
		if a.BotGuard == nil {
			continue
		}
		if a.BotGuard.UseIPReputation && cfg.Security.IPReputationFeed != "" {
			ipRepNeeded = true
		}
		if len(a.BotGuard.BlockTLSPatterns) > 0 {
			tlsMaps = append(tlsMaps, tlsPatternMapEntry{
				APIName:  a.Name,
				Patterns: a.BotGuard.BlockTLSPatterns,
			})
		}
	}
	ipFeed := ""
	if ipRepNeeded {
		ipFeed = cfg.Security.IPReputationFeed
	}

	// Emit the `log_format apigw_json` directive when ANY consumer needs
	// it — either the global logging.format is json, or any per-API
	// access_log_mode is "json". Without this gate, `apigw api log set
	// <name> --format json` produces `access_log ... apigw_json;` in the
	// server block but the format itself is missing in http-scope, and
	// `nginx -t` dies with `unknown log format "apigw_json"`.
	wantJSON := cfg.Logging.Format == "json"
	if !wantJSON {
		for i := range cfg.APIs {
			if cfg.APIs[i].AccessLog == "json" {
				wantJSON = true
				break
			}
		}
	}
	hd := httpData{
		Banner:           "PLACEHOLDER",
		Upstreams:        upstreams,
		RateLimitZones:   rlZones,
		CORSOriginMap:    corsOrigins,
		SplitClients:     splits,
		CacheZones:       cacheZones,
		JSONLogFormat:    wantJSON,
		LogSampleRate:    resolveSampleRate(cfg.Logging.SamplePercent),
		IPReputationFeed: ipFeed,
		TLSPatternMaps:   tlsMaps,
	}
	var httpBuf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&httpBuf, "_http.tmpl", hd); err != nil {
		return nil, nil, fmt.Errorf("execute _http.tmpl: %w", err)
	}
	hSum := sha256.Sum256(stripBanner(httpBuf.Bytes()))
	hHash := hex.EncodeToString(hSum[:])[:16]
	hBanner := fmt.Sprintf("MANAGED BY apigw — http{} scope. version=%s commit=%s generated=%s hash=%s",
		build.Version, build.Commit, time.Now().UTC().Format(time.RFC3339), hHash)
	httpBytes = bytes.Replace(httpBuf.Bytes(),
		[]byte("# PLACEHOLDER"),
		[]byte("# "+hBanner),
		1,
	)
	return serverBytes, httpBytes, nil
}

// resolveGzip merges cfg.Listen.Gzip with sane production defaults so an
// empty config still ships a useful gzip block. Set cfg.Listen.Gzip.Enabled
// to false explicitly to suppress.
func resolveGzip(cfg *config.Config) gzipEntry {
	def := gzipEntry{
		Enabled:   true,
		Level:     5,
		MinLength: 1024,
		Types: []string{
			"text/plain", "text/css", "text/xml",
			"application/json", "application/javascript", "application/xml",
			"application/xml+rss", "image/svg+xml",
		},
	}
	g := cfg.Listen.Gzip
	// Zero-value Listen.Gzip means "user didn't touch it" → ship defaults.
	if !g.Enabled && g.Level == 0 && g.MinLength == 0 && len(g.Types) == 0 {
		return def
	}
	out := gzipEntry{
		Enabled:   g.Enabled,
		Level:     g.Level,
		MinLength: g.MinLength,
		Types:     g.Types,
	}
	if out.Level == 0 {
		out.Level = def.Level
	}
	if out.MinLength == 0 {
		out.MinLength = def.MinLength
	}
	if len(out.Types) == 0 {
		out.Types = def.Types
	}
	return out
}

// resolveBrotli mirrors resolveGzip but for ngx_brotli. Disabled by
// default (the module isn't on every nginx build). Operators flip
// Enabled=true after installing nginx-module-brotli.
func resolveBrotli(cfg *config.Config) brotliEntry {
	b := cfg.Listen.Brotli
	if !b.Enabled {
		return brotliEntry{} // emits nothing
	}
	out := brotliEntry{
		Enabled:   true,
		Level:     b.Level,
		MinLength: b.MinLength,
		Types:     b.Types,
	}
	if out.Level == 0 {
		out.Level = 4
	}
	if out.MinLength == 0 {
		out.MinLength = 1024
	}
	if len(out.Types) == 0 {
		out.Types = []string{
			"text/plain", "text/css", "text/xml",
			"application/json", "application/javascript", "application/xml",
			"application/xml+rss", "image/svg+xml",
		}
	}
	return out
}

// stripBanner returns the body with the leading "# MANAGED BY ..." line
// removed so a second renderer with a different timestamp/version produces
// the same canonical bytes. Used for hashing only.
func stripBanner(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 && bytes.HasPrefix(b, []byte("# ")) {
		return b[i+1:]
	}
	return b
}

func nonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
func nonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func shortSHA(s string) string {
	if len(s) <= 7 {
		return s
	}
	return s[:7]
}
