// Package config owns the apigw configuration: typed Go struct, atomic save
// with flock, koanf-based load with documented precedence.
//
// Precedence (last wins): defaults → /etc/apigw/config.yaml (or XDG) → env
// (APIGW_*) → flags (wired by the cobra command).
//
// Atomic save: write tmp file, fsync, rename onto live path. The flock guards
// against concurrent writers (two `apigw api add` racing the same /etc/apigw).
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/devevghenicernev-png/apigw/internal/cmdutil"
	"github.com/devevghenicernev-png/apigw/internal/paths"
)

// SchemaVersion is bumped on every breaking change to the on-disk format.
// Migrations live in migrate.go, keyed on this number.
const SchemaVersion = 1

// Config is the canonical in-memory representation of apigw's state.
// Each field maps 1:1 to a top-level key in config.yaml.
type Config struct {
	Version   int       `koanf:"version" yaml:"version"`
	Listen    Listen    `koanf:"listen" yaml:"listen"`
	APIs      []API     `koanf:"apis" yaml:"apis"`
	Deploys   []Deploy  `koanf:"deployments" yaml:"deployments"`
	Webhook   Webhook   `koanf:"webhook" yaml:"webhook"`
	Dashboard Dashboard `koanf:"dashboard" yaml:"dashboard"`
	TLS       TLS       `koanf:"tls" yaml:"tls"`

	// RootRedirect turns the catch-all `location /` from a bare 404 into a
	// redirect. Nothing is mounted on / by default, so hitting the bare
	// hostname looks like the gateway is down when it is merely empty.
	// Accepts an absolute path ("/dashboard/") or a full URL. Empty keeps
	// the 404, so existing installs are unaffected.
	RootRedirect string `koanf:"root_redirect" yaml:"root_redirect"`

	// E1+ enterprise features. All optional; zero-value = feature off.
	Security Security `koanf:"security" yaml:"security,omitempty"`
	Tenants  []Tenant `koanf:"tenants" yaml:"tenants,omitempty"`
	Alerts   Alerts   `koanf:"alerts" yaml:"alerts,omitempty"`
	GitOps   GitOps   `koanf:"gitops" yaml:"gitops,omitempty"`
	Cluster  Cluster  `koanf:"cluster" yaml:"cluster,omitempty"`

	// v0.2.0 — beyond-HTTP and shared infra.
	Streams []Stream      `koanf:"streams" yaml:"streams,omitempty"`
	Logging Logging       `koanf:"logging" yaml:"logging,omitempty"`
	Metrics MetricsExport `koanf:"metrics" yaml:"metrics,omitempty"`

	// v0.3 — main-context nginx tuning. Rendered via `apigw tuning apply`
	// into /etc/nginx/nginx.conf inside a marker block (`# >>> apigw tuning >>>`).
	// Not auto-emitted on `WriteAndReload` because main-context directives
	// can't live in conf.d/* — see internal/cmd/tuning for the surface.
	Tuning Tuning `koanf:"tuning" yaml:"tuning,omitempty"`

	// path is where this config was loaded from / will be saved to. Not in yaml.
	path string `koanf:"-" yaml:"-"`
}

// Security bundles RBAC, audit, OPA-policy, approvals, and admin-API auth.
// Empty Security = legacy mode: admin API requires no auth (preserved for
// upgrade paths), and audit/policy/approvals are inert.
type Security struct {
	// AdminTokens is the static API-token allow-list for /api/admin/*.
	// Each token grants the listed roles (subject to the RBAC engine below).
	// Tokens are matched in constant time against the request's
	// `Authorization: Bearer <token>` header.
	//
	// At least one entry with role "owner" is required to fully enable
	// security mode — otherwise nobody can ever modify config.
	AdminTokens []AdminToken `koanf:"admin_tokens" yaml:"admin_tokens,omitempty"`

	// RBAC enforcement. enforce=false (default for soft-rollout) means every
	// denied permission is still logged via audit but the request goes
	// through. Flip to true once you've watched the audit log for a week.
	RBACEnforce bool         `koanf:"rbac_enforce" yaml:"rbac_enforce,omitempty"`
	Roles       []Role       `koanf:"roles" yaml:"roles,omitempty"`
	Assignments []Assignment `koanf:"assignments" yaml:"assignments,omitempty"`

	// OPA policy directory. Each *.rego file is loaded and evaluated on every
	// config mutation. Empty = no policies = fail-open.
	PolicyDir string `koanf:"policy_dir" yaml:"policy_dir,omitempty"`

	// Approvals threshold for "dangerous" actions. 0 = no approvals required.
	// >0 = the action is parked, ID is returned, and N other operators must
	// approve via `apigw approvals approve <id>`.
	ApprovalsThreshold int `koanf:"approvals_threshold" yaml:"approvals_threshold,omitempty"`

	// StateDir is where audit.db / approvals.db live. Defaults to
	// /var/lib/apigw when empty.
	StateDir string `koanf:"state_dir" yaml:"state_dir,omitempty"`

	// CSRFSecret is the HMAC key used to sign anti-CSRF tokens issued to the
	// embedded dashboard. Empty = generated on first start and cached in
	// StateDir. Rotate by removing the cache file.
	CSRFSecret string `koanf:"csrf_secret" yaml:"csrf_secret,omitempty"`

	// MaxRequestBytes caps the body size accepted by /api/admin/* endpoints
	// (defence-in-depth against memory-DoS). 0 = 1 MiB default.
	MaxRequestBytes int64 `koanf:"max_request_bytes" yaml:"max_request_bytes,omitempty"`

	// AuditReads, when true, logs even successful read-only operations
	// (list / show / query / status). Default false — these are noisy
	// and SOX/PCI/SOC2 care about mutations and denials, not lookups.
	// Flip to true for highest-paranoia / breach-investigation mode.
	AuditReads bool `koanf:"audit_reads" yaml:"audit_reads,omitempty"`

	// IPReputationFeed is an absolute path to a file with one IP or
	// CIDR per line (comments with #). When set, APIs with
	// BotGuard.UseIPReputation=true reject requests whose $remote_addr
	// matches. The file is read at config generation time and emitted
	// into a global nginx `geo` block — reload via `apigw api reload`
	// after updating the file. Live hot-reload (without nginx reload)
	// is out of scope; a 10K-IP feed renders into ~200KB of nginx
	// config which the kernel `include` handles fine.
	IPReputationFeed string `koanf:"ip_reputation_feed" yaml:"ip_reputation_feed,omitempty"`

	// ChangeWindows is a list of recurring time ranges during which
	// mutating admin actions (api.add / deploy.run / config.* writes)
	// are rejected with HTTP 423 Locked. Read-only actions are
	// unaffected. Operators use this for production freeze periods —
	// e.g. block any change Friday 14:00 → Monday 09:00 unless an
	// override flag is set on the request. Empty list = no freeze.
	ChangeWindows []ChangeWindow `koanf:"change_windows" yaml:"change_windows,omitempty"`

	// Teams group users for RBAC. After Identify resolves a user, the
	// dashboard adds a synthetic `team:<name>` to the user's Groups
	// list for every team they're listed in — Assignment.Group can
	// then reference `team:ops` to grant a whole team a role at once.
	Teams []Team `koanf:"teams" yaml:"teams,omitempty"`

	// SSO configures interactive single sign-on for the admin dashboard.
	// When set, /api/admin/sso/login redirects operators to the IdP;
	// /api/admin/sso/callback exchanges the auth code, validates the
	// ID token, maps the resulting identity to one or more apigw RBAC
	// roles via RoleMapping, and issues a session cookie via the
	// existing Sessions store. Sessions must also be configured.
	//
	// Nil = no SSO (admin still works via static AdminTokens).
	SSO *SSO `koanf:"sso" yaml:"sso,omitempty"`

	// Sessions configures the cookie-based session store. Nil = sessions
	// disabled (per-API API.Session is then ignored). State lives in
	// StateDir/sessions.db (bbolt). Issuing happens via the
	// /api/admin/sessions POST endpoint — there's no built-in login
	// flow; an upstream auth proxy / OAuth2 callback / SAML callback
	// calls that endpoint with the verified identity and gets back a
	// cookie to set on the user's browser.
	Sessions *Sessions `koanf:"sessions" yaml:"sessions,omitempty"`

	// Consumers is the registry of identities the gateway knows about,
	// bundled into Groups for policy application. After an auth method
	// succeeds, the handler maps the credential to a Consumer (key.ConsumerID
	// for APIKey/HMAC, subject for JWT/OAuth2/Session, CN for mTLS) and
	// surfaces X-Apigw-Consumer-Id + X-Apigw-Consumer-Groups to the upstream.
	// Per-route ACL with match=consumer-id or match=consumer-group then
	// filters based on this resolved identity.
	Consumers []Consumer `koanf:"consumers" yaml:"consumers,omitempty"`

	// ConsumerGroups documents the named groups Consumers reference.
	// Pure-metadata today — populated for `apigw consumer group list` and
	// for future per-group features (rate limits, plugins). A group named
	// here that's referenced by a Consumer is fine even if the inverse is
	// true (Consumer references an undefined group), so this list isn't
	// authoritative — it's documentation + a place to hang descriptions.
	ConsumerGroups []ConsumerGroup `koanf:"consumer_groups" yaml:"consumer_groups,omitempty"`
}

// Team groups users by name. Membership is by user identity
// (the same string Identify uses — typically the bearer-token's
// User field or X-Apigw-Subject).
type Team struct {
	Name        string   `koanf:"name" yaml:"name"`
	Members     []string `koanf:"members" yaml:"members"`
	Description string   `koanf:"description" yaml:"description,omitempty"`
}

// ChangeWindow is a recurring weekly time range during which mutating
// admin actions are rejected. Server time is used (typically UTC for
// installs; operators set the right timezone in the systemd unit if
// they want local).
//
// Days is a comma-friendly list of lowercase 3-letter day names: any
// combination of mon/tue/wed/thu/fri/sat/sun. Empty list = every day.
//
// StartHour / EndHour are 0-23. The window is "[StartHour:00,
// EndHour:00)" same-day; for windows that cross midnight (e.g.
// Fri 14:00 → Mon 09:00), declare two ChangeWindow entries
// (Fri 14-24 + Mon 0-9) — keeps the matcher one-liner.
//
// Reason is a short free-form string surfaced in the 423 response so
// the caller knows why their write was blocked.
type ChangeWindow struct {
	Name      string   `koanf:"name" yaml:"name,omitempty"`
	Days      []string `koanf:"days" yaml:"days,omitempty"`
	StartHour int      `koanf:"start_hour" yaml:"start_hour"`
	EndHour   int      `koanf:"end_hour" yaml:"end_hour"`
	Reason    string   `koanf:"reason" yaml:"reason,omitempty"`
}

// Consumer is one identity in the registry. ID is the canonical
// reference used by ACLs and credential mappings; Groups list the
// named groups the consumer belongs to.
type Consumer struct {
	ID          string   `koanf:"id" yaml:"id"`
	Name        string   `koanf:"name" yaml:"name,omitempty"`
	Groups      []string `koanf:"groups" yaml:"groups,omitempty"`
	Description string   `koanf:"description" yaml:"description,omitempty"`
}

// ConsumerGroup is metadata-only for now: a named bucket that
// Consumer.Groups references. Future enhancements (per-group rate
// limits, per-group plugins, per-group quotas) will hang fields here.
type ConsumerGroup struct {
	Name        string `koanf:"name" yaml:"name"`
	Description string `koanf:"description" yaml:"description,omitempty"`
}

// Sessions is the dashboard's cookie-based session store config.
type Sessions struct {
	// CookieName is the Set-Cookie name returned to the browser. Default
	// "apigw_session".
	CookieName string `koanf:"cookie_name" yaml:"cookie_name,omitempty"`

	// TTL is how long a freshly-issued session is valid. Default 24h.
	TTL time.Duration `koanf:"ttl" yaml:"ttl,omitempty"`

	// SlidingWindow, when true, resets ExpiresAt to now+TTL on every
	// successful Lookup — sessions never expire while the user is
	// active. False = absolute expiry from IssuedAt.
	SlidingWindow bool `koanf:"sliding_window" yaml:"sliding_window,omitempty"`

	// Domain sets the Domain attribute on Set-Cookie. Empty = host-only
	// cookie (the issuing host, no subdomains).
	Domain string `koanf:"domain" yaml:"domain,omitempty"`

	// SameSite picks the SameSite attribute: "lax" (default), "strict",
	// "none". "none" requires Secure=true and is for cross-site
	// embedded flows.
	SameSite string `koanf:"same_site" yaml:"same_site,omitempty"`

	// Secure (default true) sets the Secure attribute on Set-Cookie so
	// browsers refuse to send the cookie over plain HTTP. Flip to false
	// only for local dev.
	Secure bool `koanf:"secure" yaml:"secure"`

	// HTTPOnly (default true) blocks JS from reading the cookie via
	// document.cookie. There's no good reason to disable this.
	HTTPOnly bool `koanf:"http_only" yaml:"http_only"`
}

// SSO configures interactive single sign-on for the admin dashboard.
// Only OIDC is wired today; SAML is on the same struct for forward-compat
// but the SAML handlers print "not yet implemented" until crewjam/saml is
// plumbed (a separate follow-up; OIDC covers Google/Okta/Auth0/Keycloak —
// the bulk of real-world IdP deployments).
type SSO struct {
	// Provider — "oidc" (today) | "saml" (placeholder).
	Provider string `koanf:"provider" yaml:"provider"`

	// IssuerURL is the bare IdP base — apigw appends
	// /.well-known/openid-configuration to discover endpoints.
	IssuerURL string `koanf:"issuer_url" yaml:"issuer_url"`

	// ClientID + ClientSecret are the OAuth2 application credentials
	// minted in the IdP admin UI. ClientSecret is a SecretRef so it
	// can live in vault://, aws-sm://, file://… (string form treated
	// as inline secret).
	ClientID     string `koanf:"client_id" yaml:"client_id"`
	ClientSecret string `koanf:"client_secret" yaml:"client_secret,omitempty"`

	// RedirectURL is the absolute callback URL registered with the IdP.
	// Must match exactly; the IdP rejects mismatches at the authorize
	// step. Typically "https://<dashboard>/api/admin/sso/callback".
	RedirectURL string `koanf:"redirect_url" yaml:"redirect_url"`

	// Scopes is the space-separated list of OIDC scopes to request.
	// Default "openid profile email". Add "groups" or your IdP's
	// equivalent if you wire RoleMapping below.
	Scopes []string `koanf:"scopes" yaml:"scopes,omitempty"`

	// GroupClaim picks which ID-token claim carries group/role names.
	// Common values: "groups" (Keycloak, Okta), "roles" (Auth0). When
	// empty no claim is examined and every authenticated user gets the
	// DefaultRole below.
	GroupClaim string `koanf:"group_claim" yaml:"group_claim,omitempty"`

	// RoleMapping translates IdP groups to apigw RBAC roles. A user is
	// granted the union of mapped roles for every group they're in.
	// Unmatched groups are ignored. Empty mapping = use DefaultRole.
	RoleMapping map[string]string `koanf:"role_mapping" yaml:"role_mapping,omitempty"`

	// DefaultRole is the fallback when no GroupClaim is configured OR
	// when none of the user's groups match RoleMapping. Empty = deny
	// (login succeeds but the operator can do nothing — useful to
	// audit "who tried to log in" before granting access).
	DefaultRole string `koanf:"default_role" yaml:"default_role,omitempty"`
}

// AdminToken associates an opaque secret with a user identity + role set.
// Tokens are stored verbatim — file mode 0o600 on /etc/apigw/config.yaml
// is the protection. Rotate via `apigw auth rotate-token`.
type AdminToken struct {
	Name   string   `koanf:"name" yaml:"name"`   // human label, e.g. "ops-deploy-bot"
	User   string   `koanf:"user" yaml:"user"`   // RBAC subject identity
	Token  string   `koanf:"token" yaml:"token"` // bearer secret; min 32 chars
	Groups []string `koanf:"groups" yaml:"groups,omitempty"`
}

// Role mirrors rbac.Role for YAML loading. Kept here to avoid a config →
// rbac import cycle.
type Role struct {
	Name        string   `koanf:"name" yaml:"name"`
	Description string   `koanf:"description" yaml:"description,omitempty"`
	Permissions []string `koanf:"permissions" yaml:"permissions"`
}

// Assignment mirrors rbac.Assignment.
type Assignment struct {
	User  string   `koanf:"user" yaml:"user,omitempty"`
	Group string   `koanf:"group" yaml:"group,omitempty"`
	Roles []string `koanf:"roles" yaml:"roles"`
}

// Tenant mirrors tenant.Tenant.
type Tenant struct {
	ID          string   `koanf:"id" yaml:"id"`
	Name        string   `koanf:"name" yaml:"name"`
	Description string   `koanf:"description" yaml:"description,omitempty"`
	PathPrefix  string   `koanf:"path_prefix" yaml:"path_prefix,omitempty"`
	Admins      []string `koanf:"admins" yaml:"admins,omitempty"`
	Enabled     bool     `koanf:"enabled" yaml:"enabled"`
	MaxAPIs     int      `koanf:"max_apis" yaml:"max_apis,omitempty"`
	MaxDeploys  int      `koanf:"max_deploys" yaml:"max_deploys,omitempty"`
}

// Alerts wires Slack/Teams/PagerDuty/Webhook/SMTP notifiers. Every notifier
// is optional; missing = silently disabled.
type Alerts struct {
	Slack     string        `koanf:"slack_webhook" yaml:"slack_webhook,omitempty"`
	Teams     string        `koanf:"teams_webhook" yaml:"teams_webhook,omitempty"`
	PagerDuty string        `koanf:"pagerduty_key" yaml:"pagerduty_key,omitempty"`
	Webhook   AlertsWebhook `koanf:"webhook" yaml:"webhook,omitempty"`
	Email     AlertsEmail   `koanf:"email" yaml:"email,omitempty"`

	// TLSExpiryWarnDays — fires cert.expiring N days before NotAfter (default 30).
	TLSExpiryWarnDays int `koanf:"tls_expiry_warn_days" yaml:"tls_expiry_warn_days,omitempty"`
}

type AlertsWebhook struct {
	URL     string            `koanf:"url" yaml:"url"`
	Headers map[string]string `koanf:"headers" yaml:"headers,omitempty"`
}

type AlertsEmail struct {
	Host     string   `koanf:"host" yaml:"host"`
	Port     int      `koanf:"port" yaml:"port,omitempty"`
	Username string   `koanf:"username" yaml:"username,omitempty"`
	Password string   `koanf:"password" yaml:"password,omitempty"`
	From     string   `koanf:"from" yaml:"from"`
	To       []string `koanf:"to" yaml:"to"`
}

// GitOps configures the pull-mode reconciler. Empty RepoURL = disabled.
type GitOps struct {
	RepoURL     string `koanf:"repo_url" yaml:"repo_url,omitempty"`
	Branch      string `koanf:"branch" yaml:"branch,omitempty"`
	Path        string `koanf:"path" yaml:"path,omitempty"`
	IntervalSec int    `koanf:"interval_sec" yaml:"interval_sec,omitempty"`
	HTTPToken   string `koanf:"http_token" yaml:"http_token,omitempty"`
	SSHKeyFile  string `koanf:"ssh_key_file" yaml:"ssh_key_file,omitempty"`
	SSHKeyPass  string `koanf:"ssh_key_pass" yaml:"ssh_key_pass,omitempty"`
}

// Cluster turns on Raft-replicated config. Empty NodeID = disabled.
type Cluster struct {
	NodeID      string `koanf:"node_id" yaml:"node_id,omitempty"`
	BindAddr    string `koanf:"bind_addr" yaml:"bind_addr,omitempty"`
	DataDir     string `koanf:"data_dir" yaml:"data_dir,omitempty"`
	Bootstrap   bool   `koanf:"bootstrap" yaml:"bootstrap,omitempty"`
	Peers       []Peer `koanf:"peers" yaml:"peers,omitempty"`
	HeartbeatMS int    `koanf:"heartbeat_ms" yaml:"heartbeat_ms,omitempty"`
}

type Peer struct {
	NodeID  string `koanf:"node_id" yaml:"node_id"`
	Address string `koanf:"address" yaml:"address"`
}

// Logging configures the nginx access log format + sampling. JSON logs
// are SIEM-friendly out of the box; sampling tames byte-volume on
// high-traffic gateways without losing security signal (denials are
// always logged regardless of sample rate).
type Logging struct {
	Format        string `koanf:"format" yaml:"format,omitempty"`                 // "" (combined) | "json"
	SamplePercent int    `koanf:"sample_percent" yaml:"sample_percent,omitempty"` // 1-100; default 100
	S3Bucket      string `koanf:"s3_bucket" yaml:"s3_bucket,omitempty"`
	S3Region      string `koanf:"s3_region" yaml:"s3_region,omitempty"`
	S3AccessKey   string `koanf:"s3_access_key" yaml:"s3_access_key,omitempty"`
	S3SecretKey   string `koanf:"s3_secret_key" yaml:"s3_secret_key,omitempty"`
}

// Tuning controls nginx's MAIN-context directives — the ones that live at
// the top of /etc/nginx/nginx.conf, before any http {} block. Because
// apigw can't legally include these from conf.d/* (that include lives
// INSIDE http {}), the snippet is rendered to a marker-delimited region of
// nginx.conf by `apigw tuning apply`. The wrap-with-markers approach lets
// re-runs replace the block idempotently and `apigw tuning revert` strip
// it cleanly.
//
// Defaults are conservative: WorkerProcesses == "" emits `auto`, which
// is also nginx's own default — so an empty Tuning struct is a true no-op.
type Tuning struct {
	// WorkerProcesses — "" (=auto) | "auto" | a positive integer string.
	WorkerProcesses string `koanf:"worker_processes" yaml:"worker_processes,omitempty"`

	// CPUAffinity — "" (omit) | "auto" | one or more CPU masks separated
	// by whitespace (e.g. "0001 0010 0100 1000" for a 4-core split).
	// "auto" lets nginx pin one worker per available core; mask form
	// is for fine-tuning (e.g. reserve socket 0 for kernel networking).
	CPUAffinity string `koanf:"cpu_affinity" yaml:"cpu_affinity,omitempty"`

	// WorkerRLimitNofile — 0 (omit) | positive int. Raises the FD limit
	// per worker process. 65535 is the common production value;
	// proxy_pass with thousands of upstream sockets needs the headroom.
	WorkerRLimitNofile int `koanf:"worker_rlimit_nofile" yaml:"worker_rlimit_nofile,omitempty"`
}

// MetricsExport wires the in-process Prometheus registry to external
// time-series databases. Zero value = Prometheus pull only.
type MetricsExport struct {
	DogStatsDAddr string `koanf:"dogstatsd_addr" yaml:"dogstatsd_addr,omitempty"`
	StatsDAddr    string `koanf:"statsd_addr" yaml:"statsd_addr,omitempty"`
	GraphiteAddr  string `koanf:"graphite_addr" yaml:"graphite_addr,omitempty"`
	// InfluxDBAddr is a UDP `host:port` for InfluxDB line-protocol
	// fire-and-forget shipping. Empty = off.
	InfluxDBAddr string `koanf:"influxdb_addr" yaml:"influxdb_addr,omitempty"`
	Prefix       string `koanf:"prefix" yaml:"prefix,omitempty"`
	FlushSeconds int    `koanf:"flush_seconds" yaml:"flush_seconds,omitempty"`
}

// Listen describes the public-facing nginx listener.
type Listen struct {
	HTTPPort   int    `koanf:"http_port" yaml:"http_port"`
	HTTPSPort  int    `koanf:"https_port" yaml:"https_port"`
	ServerName string `koanf:"server_name" yaml:"server_name"`

	// MaxBodySize is the global default `client_max_body_size`. nginx's
	// default is 1m; we mirror that. Per-API/Deploy values override.
	MaxBodySize string `koanf:"max_body_size" yaml:"max_body_size,omitempty"`

	// Gzip configures the http{}-scope compression block. Defaults are
	// production-sane (level 5, min_length 1024, common MIME types).
	Gzip Gzip `koanf:"gzip" yaml:"gzip"`

	// Brotli enables the http{}-scope `brotli on;` block. Requires the
	// ngx_brotli module installed in nginx (`nginx-module-brotli` on
	// Debian/Ubuntu, `nginx-mod-http-brotli` on RHEL). Without the
	// module nginx refuses to start with "unknown directive 'brotli'" —
	// `apigw doctor` warns. Off by default.
	Brotli Brotli `koanf:"brotli" yaml:"brotli,omitempty"`
}

// Brotli mirrors ngx_brotli's directives. Compression level 4 is the
// usual sweet-spot for HTTP (smaller responses than gzip-5 with
// similar CPU cost). MinLength 1024 matches the gzip default.
type Brotli struct {
	Enabled   bool     `koanf:"enabled" yaml:"enabled"`
	Level     int      `koanf:"level" yaml:"level,omitempty"`           // 0-11; default 4
	MinLength int      `koanf:"min_length" yaml:"min_length,omitempty"` // bytes; default 1024
	Types     []string `koanf:"types" yaml:"types,omitempty"`           // MIME list; default same as gzip
}

// Gzip mirrors nginx's gzip module directives. Empty = "use defaults"; set
// Enabled=false to suppress the block entirely.
type Gzip struct {
	Enabled   bool     `koanf:"enabled" yaml:"enabled"`
	Level     int      `koanf:"level" yaml:"level,omitempty"`           // 1-9; default 5
	MinLength int      `koanf:"min_length" yaml:"min_length,omitempty"` // bytes; default 1024
	Types     []string `koanf:"types" yaml:"types,omitempty"`           // MIME list; default text/* + json + xml + svg
}

// API is an upstream service registered with apigw.
//
// The bash version stored these in apis.json; the migration step (Phase 8)
// converts that to this struct. Middleware fields (RateLimit, CORS,
// Headers, …) are all optional — when nil/empty the generator emits no
// extra nginx directives.
type API struct {
	Name        string `koanf:"name" yaml:"name"`
	Port        int    `koanf:"port" yaml:"port"`
	Path        string `koanf:"path" yaml:"path"`               // mount point, default /api/<name>
	Description string `koanf:"description" yaml:"description"` // free-form, shown in `api list`
	Enabled     bool   `koanf:"enabled" yaml:"enabled"`

	// Multi-upstream pool. When non-empty, overrides Port.
	Upstreams   []Upstream `koanf:"upstreams" yaml:"upstreams,omitempty"`
	LoadBalance string     `koanf:"load_balance" yaml:"load_balance,omitempty"` // round_robin (default) | least_conn | ip_hash | random
	// GRPC switches the location to grpc_pass instead of proxy_pass. Requires
	// HTTP/2 on the listener — apigw's tls-server.tmpl sets `listen ... ssl http2;`.
	GRPC bool `koanf:"grpc" yaml:"grpc,omitempty"`

	// Middleware — all optional.
	MaxBodySize    string          `koanf:"max_body_size" yaml:"max_body_size,omitempty"` // "10m", "1g"; default = global
	Headers        *Headers        `koanf:"headers" yaml:"headers,omitempty"`
	IPRules        *IPRules        `koanf:"ip_rules" yaml:"ip_rules,omitempty"`
	CORS           *CORS           `koanf:"cors" yaml:"cors,omitempty"`
	BasicAuth      *BasicAuth      `koanf:"basic_auth" yaml:"basic_auth,omitempty"`
	RateLimit      *RateLimit      `koanf:"rate_limit" yaml:"rate_limit,omitempty"`
	ForwardAuth    *ForwardAuth    `koanf:"forward_auth" yaml:"forward_auth,omitempty"`
	HealthCheck    *HealthCheck    `koanf:"health_check" yaml:"health_check,omitempty"`
	Retry          *Retry          `koanf:"retry" yaml:"retry,omitempty"`
	JWT            *JWT            `koanf:"jwt" yaml:"jwt,omitempty"`
	MTLS           *MTLS           `koanf:"mtls" yaml:"mtls,omitempty"`
	Canary         *Canary         `koanf:"canary" yaml:"canary,omitempty"`
	BlueGreen      *BlueGreen      `koanf:"blue_green" yaml:"blue_green,omitempty"`
	Variants       []Variant       `koanf:"variants" yaml:"variants,omitempty"`
	ConnectionPool *ConnectionPool `koanf:"connection_pool" yaml:"connection_pool,omitempty"`
	Buffering      *Buffering      `koanf:"buffering" yaml:"buffering,omitempty"`
	Rewrites       []RewriteRule   `koanf:"rewrites" yaml:"rewrites,omitempty"`
	SLO            *SLO            `koanf:"slo" yaml:"slo,omitempty"`
	Lifecycle      *Lifecycle      `koanf:"lifecycle" yaml:"lifecycle,omitempty"`
	Transform      *Transform      `koanf:"transform" yaml:"transform,omitempty"`
	Versioning     *Versioning     `koanf:"versioning" yaml:"versioning,omitempty"`

	// New in v0.2.0 — fills the long tail of competitive features.
	APIKey *APIKeyAuth `koanf:"api_key" yaml:"api_key,omitempty"`
	HMAC   *HMACAuth   `koanf:"hmac" yaml:"hmac,omitempty"`
	ACL    *ACL        `koanf:"acl" yaml:"acl,omitempty"`
	OAuth2 *OAuth2     `koanf:"oauth2" yaml:"oauth2,omitempty"`
	// Session, when true, accepts the dashboard's session cookie as a
	// valid identity proof — requires Security.Sessions to be configured.
	// nginx auth_request /auth/session/<api> looks up the cookie value
	// in the session store and surfaces X-Apigw-Subject on success.
	Session  bool      `koanf:"session" yaml:"session,omitempty"`
	Cache    *Cache    `koanf:"cache" yaml:"cache,omitempty"`
	Mock     *Mock     `koanf:"mock" yaml:"mock,omitempty"`
	Timeouts *Timeouts `koanf:"timeouts" yaml:"timeouts,omitempty"`
	Mirror   *Mirror   `koanf:"mirror" yaml:"mirror,omitempty"`
	BotGuard *BotGuard `koanf:"bot_guard" yaml:"bot_guard,omitempty"`
	// GRPCWeb wraps standard gRPC in the grpc-web framing so browsers can
	// call it. Mutually exclusive with non-gRPC upstreams.
	GRPCWeb bool `koanf:"grpc_web" yaml:"grpc_web,omitempty"`
	// StickySession picks one of: "" (none), "ip_hash", "cookie:<name>".
	StickySession string `koanf:"sticky_session" yaml:"sticky_session,omitempty"`
	// HashKey is consumed when LoadBalance == "consistent_hash". Usually
	// "$remote_addr" or "$http_x_session_id".
	HashKey string `koanf:"hash_key" yaml:"hash_key,omitempty"`
	// AccessLog overrides the global log format for this route.
	// "json" emits the structured log_format; "combined" emits the
	// stock combined format; "off" disables logging for the route.
	// Empty = inherit Logging.Format.
	AccessLog string `koanf:"access_log" yaml:"access_log,omitempty"`

	// AccessLogFile, when non-empty, directs this route's access log
	// to a dedicated file path (must be writable by nginx). Combine
	// with AccessLog to control the format. Empty = use the nginx
	// default (/var/log/nginx/access.log).
	AccessLogFile string `koanf:"access_log_file" yaml:"access_log_file,omitempty"`

	// EarlyHints emits `add_header Link "<value>" always;` per entry —
	// a `Link: rel=preload` hint browsers consume even before the real
	// response. Closest stock-nginx approximation of HTTP 103; true
	// 103 needs the `early_hints` directive (nginx 1.27+).
	// Format each entry as a complete Link value:
	//   "</static/app.css>; rel=preload; as=style"
	EarlyHints []string `koanf:"early_hints" yaml:"early_hints,omitempty"`

	// HTTP2Push lists request paths nginx should server-push on
	// HTTP/2 (`http2_push <path>;`). Browser support is deprecated
	// (Chrome 106 dropped it) but Firefox + curl still consume.
	// Empty = no push.
	HTTP2Push []string `koanf:"http2_push" yaml:"http2_push,omitempty"`

	// CustomLocation / CustomServer (F14) inject raw nginx directives into
	// the generated config. CustomLocation lands inside the `location {…}`
	// block; CustomServer lands at server scope (after listen, before
	// includes). Useful for nginx features we don't model — `access_log`
	// per API, `proxy_intercept_errors`, custom `error_page`, etc.
	//
	// Sanitization: we block `}` to prevent escaping the location/server
	// block, but otherwise pass directives verbatim. `nginx -t` will catch
	// syntax errors at apply time.
	CustomLocation string `koanf:"custom_location" yaml:"custom_location,omitempty"`
	CustomServer   string `koanf:"custom_server" yaml:"custom_server,omitempty"`
}

// APIKeyAuth turns the route into key-gated. Clients send the secret in
// the header named by Header (default `X-API-Key`). Each key may carry
// its own per-second rate limit and an expiry; revoked or expired keys
// are rejected by the dashboard's /auth/apikey/<api> auth_request.
type APIKeyAuth struct {
	Header       string   `koanf:"header" yaml:"header,omitempty"`
	QueryParam   string   `koanf:"query_param" yaml:"query_param,omitempty"`
	Keys         []APIKey `koanf:"keys" yaml:"keys"`
	HashedAtRest bool     `koanf:"hashed_at_rest" yaml:"hashed_at_rest,omitempty"`
}

// APIKey is one credential. The secret is stored verbatim today;
// HashedAtRest is reserved for a v0.3 migration to argon2id at rest.
type APIKey struct {
	ID        string    `koanf:"id" yaml:"id"`
	Secret    string    `koanf:"secret" yaml:"secret"`
	Owner     string    `koanf:"owner" yaml:"owner,omitempty"`
	RPS       int       `koanf:"rps" yaml:"rps,omitempty"`
	ExpiresAt time.Time `koanf:"expires_at" yaml:"expires_at,omitempty"`
	Disabled  bool      `koanf:"disabled" yaml:"disabled,omitempty"`
	Scopes    []string  `koanf:"scopes" yaml:"scopes,omitempty"`
	// ConsumerID maps this credential to a Security.Consumers entry.
	// Empty = use the key ID itself as the consumer ID (1:1 mapping).
	// Multiple credentials can share a ConsumerID — e.g. a long-lived
	// "ci-bot" consumer with rotated keys all pointing at it.
	ConsumerID string `koanf:"consumer_id" yaml:"consumer_id,omitempty"`
}

// HMACAuth turns the route into HMAC-signed. Each request must carry
// `Authorization: HMAC <key-id>:<base64-sig>` plus `X-Apigw-Date` and
// `X-Apigw-Nonce`. The signature covers method, path, query, date,
// nonce, and an optional client-supplied SHA-256 of the body — so a
// MITM can't tamper without the shared secret. Replay is blocked by an
// in-memory nonce cache (window = 2 × ClockSkew).
//
// Body integrity is enforced by the client-supplied content hash
// (signed into the signature). The auth subrequest does *not* read the
// body — fast path. Set RequireBodyHash=true on write endpoints to
// force clients to include the hash.
type HMACAuth struct {
	// Algorithms is the allow-list of HMAC hash functions. Each key may
	// override; otherwise the first algorithm wins.
	// Default: ["hmac-sha256", "hmac-sha512"].
	Algorithms []string `koanf:"algorithms" yaml:"algorithms,omitempty"`
	// ClockSkew is the maximum tolerated drift between the X-Apigw-Date
	// header and server time. Default: 5m.
	ClockSkew time.Duration `koanf:"clock_skew" yaml:"clock_skew,omitempty"`
	// RequireBodyHash makes X-Apigw-Content-SHA256 mandatory and rejects
	// the UNSIGNED-PAYLOAD sentinel. Use on write endpoints.
	RequireBodyHash bool `koanf:"require_body_hash" yaml:"require_body_hash,omitempty"`
	// NonceCacheSize is the LRU capacity for nonce replay protection.
	// Default: 10000.
	NonceCacheSize int       `koanf:"nonce_cache_size" yaml:"nonce_cache_size,omitempty"`
	Keys           []HMACKey `koanf:"keys" yaml:"keys"`
}

// ACL is a per-route allow / deny gate that runs AFTER authentication
// succeeds. The authenticated identity (key ID, JWT subject, mTLS CN,
// etc.) is matched against Allow / Deny lists; precedence is
// deny-wins. Empty Allow = no allow constraint (default allow). Empty
// Deny = no explicit blocks.
//
// Match selects which identity field this ACL applies to. The
// corresponding auth handler is the only one that runs the check; if
// the API uses a different auth method, the ACL is silently no-op.
// Valid values:
//
//	"apikey-id" — matches against APIKey.Keys[].ID
//	"hmac-id"   — matches against HMAC.Keys[].ID
//	"subject"   — matches against the JWT/OAuth2 subject claim (sub)
//	"mtls-cn"   — matches against the mTLS client cert Common Name
type ACL struct {
	Match string   `koanf:"match" yaml:"match"`
	Allow []string `koanf:"allow" yaml:"allow,omitempty"`
	Deny  []string `koanf:"deny" yaml:"deny,omitempty"`
}

// HMACKey is one HMAC-signing credential. The Secret is stored verbatim
// in config.yaml (mode 0o600 enforced by the atomic save). Algorithm
// overrides HMACAuth.Algorithms[0] for this key only.
type HMACKey struct {
	ID        string    `koanf:"id" yaml:"id"`
	Secret    string    `koanf:"secret" yaml:"secret"`
	Algorithm string    `koanf:"algorithm" yaml:"algorithm,omitempty"`
	Owner     string    `koanf:"owner" yaml:"owner,omitempty"`
	ExpiresAt time.Time `koanf:"expires_at" yaml:"expires_at,omitempty"`
	Disabled  bool      `koanf:"disabled" yaml:"disabled,omitempty"`
	Scopes    []string  `koanf:"scopes" yaml:"scopes,omitempty"`
	// ConsumerID maps this credential to a Security.Consumers entry.
	// See APIKey.ConsumerID — same semantics.
	ConsumerID string `koanf:"consumer_id" yaml:"consumer_id,omitempty"`
}

// OAuth2 turns on RFC 7662 token introspection — opaque bearer tokens
// (the common case for confidential clients) are validated against the
// IdP on every request, with results cached per token for CacheSeconds.
type OAuth2 struct {
	IntrospectionURL string   `koanf:"introspection_url" yaml:"introspection_url"`
	ClientID         string   `koanf:"client_id" yaml:"client_id"`
	ClientSecret     string   `koanf:"client_secret" yaml:"client_secret"`
	RequiredScopes   []string `koanf:"required_scopes" yaml:"required_scopes,omitempty"`
	CacheSeconds     int      `koanf:"cache_seconds" yaml:"cache_seconds,omitempty"`
}

// Cache turns on nginx proxy_cache for the route. Operators can purge
// keys via POST /api/admin/cache/purge with a header pattern.
type Cache struct {
	Duration     string   `koanf:"duration" yaml:"duration,omitempty"`           // 1m, 1h — nginx proxy_cache_valid 200
	Methods      []string `koanf:"methods" yaml:"methods,omitempty"`             // default GET, HEAD
	Key          string   `koanf:"key" yaml:"key,omitempty"`                     // nginx proxy_cache_key; default scheme$request_method$host$request_uri
	BypassHeader string   `koanf:"bypass_header" yaml:"bypass_header,omitempty"` // request bypasses cache if this header is non-empty
	MaxSizeMB    int      `koanf:"max_size_mb" yaml:"max_size_mb,omitempty"`     // shared zone size; default 256
	VaryHeaders  []string `koanf:"vary_headers" yaml:"vary_headers,omitempty"`
}

// Mock returns a canned response without calling any upstream. Useful
// for development, contract tests, and "API not ready yet" staging.
type Mock struct {
	StatusCode int               `koanf:"status_code" yaml:"status_code,omitempty"`
	Body       string            `koanf:"body" yaml:"body,omitempty"`
	Headers    map[string]string `koanf:"headers" yaml:"headers,omitempty"`
	DelayMS    int               `koanf:"delay_ms" yaml:"delay_ms,omitempty"`
}

// Timeouts overrides nginx defaults at route scope. Empty values fall
// back to global; the strings accept the standard nginx suffix (s, ms).
type Timeouts struct {
	Connect string `koanf:"connect" yaml:"connect,omitempty"`
	Read    string `koanf:"read" yaml:"read,omitempty"`
	Send    string `koanf:"send" yaml:"send,omitempty"`
}

// Mirror sends a copy of every Nth request to a secondary upstream for
// shadow testing — nginx `mirror` directive. The mirrored request does
// NOT block the primary response and its body is silently consumed.
type Mirror struct {
	Target        string `koanf:"target" yaml:"target"`                           // host:port of mirror
	SamplePercent int    `koanf:"sample_percent" yaml:"sample_percent,omitempty"` // 1–100; default 100
	IgnoreBody    bool   `koanf:"ignore_body" yaml:"ignore_body,omitempty"`       // skip request_body on the mirror
}

// BotGuard is a quick allow/deny based on common signals. For real
// production protection operators should still front apigw with a WAF.
type BotGuard struct {
	BlockUserAgents     []string `koanf:"block_user_agents" yaml:"block_user_agents,omitempty"`
	AllowUserAgents     []string `koanf:"allow_user_agents" yaml:"allow_user_agents,omitempty"`
	RequireUserAgent    bool     `koanf:"require_user_agent" yaml:"require_user_agent,omitempty"`
	BlockEmptyReferer   bool     `koanf:"block_empty_referer" yaml:"block_empty_referer,omitempty"`
	BlockCommonScanners bool     `koanf:"block_common_scanners" yaml:"block_common_scanners,omitempty"`

	// UseIPReputation, when true, blocks requests whose $remote_addr
	// matches Security.IPReputationFeed. Per-API opt-in so the feed
	// applies only to public routes — internal admin paths and mTLS
	// upstreams usually shouldn't be filtered.
	UseIPReputation bool `koanf:"use_ip_reputation" yaml:"use_ip_reputation,omitempty"`

	// ForwardTLSFingerprint, when true, surfaces the synthetic TLS
	// profile to the upstream via X-Apigw-TLS-Profile header. The
	// value is `<protocol>/<cipher>/<curves>/<ciphers>` — not a JA3
	// hash (real JA3 needs the ngx_ssl_ja3 module, which isn't in
	// stock nginx). Still useful for upstream-side anomaly detection.
	ForwardTLSFingerprint bool `koanf:"forward_tls_fingerprint" yaml:"forward_tls_fingerprint,omitempty"`

	// BlockTLSPatterns rejects requests whose synthetic TLS profile
	// matches any regex pattern. Cheap nginx-level filter for blocking
	// legacy TLS versions, headless-browser cipher orderings, or
	// specific tool fingerprints without involving the dashboard.
	BlockTLSPatterns []string `koanf:"block_tls_patterns" yaml:"block_tls_patterns,omitempty"`
}

// Stream is a TCP or UDP proxy entry, served via nginx stream {}.
// Multiplexed via SNI (TCP) or by listening port (UDP).
type Stream struct {
	Name         string     `koanf:"name" yaml:"name"`
	Protocol     string     `koanf:"protocol" yaml:"protocol"` // "tcp" | "udp"
	ListenPort   int        `koanf:"listen_port" yaml:"listen_port"`
	Upstreams    []Upstream `koanf:"upstreams" yaml:"upstreams"`
	ProxyTimeout string     `koanf:"proxy_timeout" yaml:"proxy_timeout,omitempty"`
	Enabled      bool       `koanf:"enabled" yaml:"enabled"`
	Description  string     `koanf:"description" yaml:"description,omitempty"`
}

// Upstream is one server in the API/Deploy upstream pool. Weight, Backup,
// MaxFails, FailTimeout map onto nginx `server` directive parameters.
type Upstream struct {
	Address     string `koanf:"address" yaml:"address"`         // host:port — required
	Weight      int    `koanf:"weight" yaml:"weight,omitempty"` // weighted round-robin; default 1
	Backup      bool   `koanf:"backup" yaml:"backup,omitempty"` // only used when others are down
	MaxFails    int    `koanf:"max_fails" yaml:"max_fails,omitempty"`
	FailTimeout string `koanf:"fail_timeout" yaml:"fail_timeout,omitempty"`
	Down        bool   `koanf:"down" yaml:"down,omitempty"` // marks server permanently down
}

// Headers describes per-route header manipulation. Empty maps render no
// directives.
type Headers struct {
	// RequestSet emits `proxy_set_header K V;`. Values support nginx
	// variables ($host, $remote_addr, ...) — they pass through verbatim.
	RequestSet map[string]string `koanf:"request_set" yaml:"request_set,omitempty"`
	// ResponseAdd emits `add_header K V always;`. The `always` flag means
	// nginx adds the header on every response, including 4xx/5xx.
	ResponseAdd map[string]string `koanf:"response_add" yaml:"response_add,omitempty"`
	// ResponseHide emits `proxy_hide_header K;` — strips backend-set
	// headers like `X-Powered-By` or `Server`.
	ResponseHide []string `koanf:"response_hide" yaml:"response_hide,omitempty"`
}

// IPRules controls per-route allow/deny.
//
// Order: emit Allow entries first, then `deny all;` as implicit fall-through
// when Allow is non-empty. Deny entries always emit verbatim.
type IPRules struct {
	Allow []string `koanf:"allow" yaml:"allow,omitempty"` // CIDRs or single IPs
	Deny  []string `koanf:"deny" yaml:"deny,omitempty"`
}

// CORS configures cross-origin requests. Multiple origins use a map at
// http{} scope to echo back the exact request origin (nginx can't send a
// list in Access-Control-Allow-Origin).
type CORS struct {
	Origins     []string `koanf:"origins" yaml:"origins"`           // exact match; "*" allowed for non-credentialed
	Methods     []string `koanf:"methods" yaml:"methods,omitempty"` // default GET, POST, OPTIONS
	Headers     []string `koanf:"headers" yaml:"headers,omitempty"` // default Content-Type, Authorization
	Credentials bool     `koanf:"credentials" yaml:"credentials"`   // incompatible with Origins=["*"]
	MaxAge      int      `koanf:"max_age" yaml:"max_age,omitempty"` // preflight cache seconds; default 86400
}

// BasicAuth configures HTTP Basic auth via nginx `auth_basic_user_file`.
// The htpasswd file lives at /etc/apigw/htpasswd.<api-name> with mode 0640.
type BasicAuth struct {
	Realm string `koanf:"realm" yaml:"realm"`
	// File overrides the default path. Empty = /etc/apigw/htpasswd.<name>.
	File string `koanf:"file" yaml:"file,omitempty"`
}

// RateLimit applies nginx `limit_req` with a per-API zone.
type RateLimit struct {
	RPS   int    `koanf:"rps" yaml:"rps"`               // sustained rate
	Burst int    `koanf:"burst" yaml:"burst,omitempty"` // default 2*RPS
	Key   string `koanf:"key" yaml:"key,omitempty"`     // "ip" (default) | "header:<name>"
}

// ForwardAuth proxies the inbound request through an external auth service
// (Authelia, oauth2-proxy, Pomerium) before forwarding to the upstream.
type ForwardAuth struct {
	Address    string   `koanf:"address" yaml:"address"`                   // full URL of the auth check endpoint
	SignInURL  string   `koanf:"sign_in_url" yaml:"sign_in_url,omitempty"` // 401 → redirect here
	SetHeaders []string `koanf:"set_headers" yaml:"set_headers,omitempty"` // upstream response headers to copy forward (X-Remote-User, …)
}

// HealthCheck is currently passive (nginx OSS): MaxFails + FailTimeout on
// the upstream block. Active probing (HTTP GET every Interval) is added by
// the dashboard daemon.
type HealthCheck struct {
	Path        string `koanf:"path" yaml:"path,omitempty"`                 // active probe path; "" disables active probing
	Interval    string `koanf:"interval" yaml:"interval,omitempty"`         // active probe period; "10s"
	MaxFails    int    `koanf:"max_fails" yaml:"max_fails,omitempty"`       // nginx default 1; we default 3
	FailTimeout string `koanf:"fail_timeout" yaml:"fail_timeout,omitempty"` // nginx default 10s
}

// Retry maps to nginx `proxy_next_upstream` + `proxy_next_upstream_tries`
// + `proxy_next_upstream_timeout` + `proxy_read_timeout`. Default set
// (when Retry is non-nil but Conditions empty): retries on connect/read
// errors + 502/503/504. Attempts defaults to 3 when unset.
//
// Backoff and Jitter knobs aren't here on purpose — stock nginx
// retries the next upstream immediately, without inter-attempt
// sleep. Real exponential backoff would require Lua / njs or an
// out-of-process retry sidecar; documenting it as a separate
// future feature when we add the plugin runtime.
type Retry struct {
	// Conditions is the raw proxy_next_upstream list. Overrides the
	// safe default when set.
	Conditions []string `koanf:"conditions" yaml:"conditions,omitempty"`

	// OnStatus extends Conditions with `http_NNN` entries — operator-
	// friendly shorthand for "retry on these HTTP statuses". Merged
	// (de-duplicated) with Conditions at render time.
	OnStatus []int `koanf:"on_status" yaml:"on_status,omitempty"`

	// Attempts is the number of upstreams to try per request, including
	// the first. 0 = nginx default (1 = no retry); apigw forces ≥1.
	// Most APIs want 3 — one primary + two retries.
	Attempts int `koanf:"attempts" yaml:"attempts,omitempty"`

	// PerTry caps the time spent on each upstream attempt
	// (proxy_read_timeout). 0 = inherit the generator default (300s).
	// proxy_next_upstream_timeout (total wall-clock budget for all
	// tries) is derived as PerTry × Attempts when both are set.
	PerTry time.Duration `koanf:"per_try" yaml:"per_try,omitempty"`
}

// Canary describes a percentage-based traffic split — N% of requests go
// to CanaryUpstreams, the rest to the primary Upstreams pool. Used for
// blue/green and progressive rollouts at the gateway layer.
//
// Pinning: when PinHeader is set, clients with that header (e.g.
// `X-Canary: 1`) always hit the canary regardless of percentage.
//
// nginx implementation: split_clients $client_id $upstream_pick — the
// generator emits a split_clients map + uses $upstream_pick in proxy_pass.
// Lifecycle tracks an API's state through draft → published →
// deprecated → retired. Apigw acts on the state at request time:
//
//   - draft     : disabled at the router level (returns 503).
//   - published : normal routing, no annotations.
//   - deprecated: routing works but every response carries
//     `Deprecation: true` + `Sunset: <SunsetAt>` (RFC 8594 + draft-
//     deprecation-header). Clients that read these gracefully
//     migrate before the cutover.
//   - retired   : router returns 410 Gone with the configured
//     ReplacementURL (when set) as a Link header.
//
// State changes are atomic config saves; nginx reload picks them up.
// `apigw api promote/deprecate/retire` are the CLI verbs.
type Lifecycle struct {
	State          string    `koanf:"state" yaml:"state"` // draft | published | deprecated | retired
	SunsetAt       time.Time `koanf:"sunset_at" yaml:"sunset_at,omitempty"`
	ReplacementURL string    `koanf:"replacement_url" yaml:"replacement_url,omitempty"`
}

// SLO declares the service-level objectives for one API. The SLA
// evaluator (internal/sla) periodically samples observed metrics and
// classifies the API as in-bounds or breaching. Breaches fire alerts
// + audit entries.
//
// Each field is optional; zero values disable that dimension.
// Period bounds the wall-clock window over which Availability is
// computed (rolling). LatencyP95Ms is evaluated point-in-time
// against the most recent metrics scrape.
type SLO struct {
	// LatencyP95Ms — alert when the request p95 latency exceeds this
	// many milliseconds. 0 = no latency SLO.
	LatencyP95Ms int `koanf:"latency_p95_ms" yaml:"latency_p95_ms,omitempty"`

	// AvailabilityPercent — alert when (success / total) over the
	// rolling Period falls below this fraction (0.0-100.0). 0 = no
	// availability SLO.
	AvailabilityPercent float64 `koanf:"availability_percent" yaml:"availability_percent,omitempty"`

	// PeriodHours is the rolling window for the availability
	// calculation. 0 = default 1h.
	PeriodHours int `koanf:"period_hours" yaml:"period_hours,omitempty"`
}

// RewriteRule maps to nginx's `rewrite <match> <replace> <flag>`
// directive. Multiple rules are emitted in order; nginx evaluates
// them sequentially until a `last` / `redirect` / `permanent` flag
// short-circuits.
//
// Match is a regex with capture groups; Replace can reference them
// via $1, $2, etc.
//
// Valid Flag values:
//   - "last"       — re-search location after rewrite (most common)
//   - "break"      — stop rewrite chain, keep current location
//   - "redirect"   — 302 to Replace (Replace must be a URL)
//   - "permanent"  — 301 to Replace
//
// Empty Flag defaults to "last".
type RewriteRule struct {
	Match   string `koanf:"match" yaml:"match"`
	Replace string `koanf:"replace" yaml:"replace"`
	Flag    string `koanf:"flag" yaml:"flag,omitempty"`
}

// Buffering controls nginx's request + response buffering for one
// route. The default (nil) keeps nginx's own defaults — request body
// buffered to memory/disk, response buffered for HTTP/1.1. Two big
// reasons to override:
//
//  1. Streaming uploads: Request=false sets proxy_request_buffering
//     off so nginx forwards the body as it arrives, instead of
//     spooling the whole thing first. Required for very large
//     uploads, multi-GB tarballs, log shipping.
//  2. Streaming responses: Response=false sets proxy_buffering off
//     for SSE / chunked / long-poll endpoints that need the bytes
//     to flow to the client without buffering.
//
// Tuning fields (empty = nginx default):
//   - ClientBodyBufferSize  → client_body_buffer_size
//   - ProxyBufferSize       → proxy_buffer_size  (1st response chunk)
//   - ProxyBuffers          → proxy_buffers      ("<count> <size>")
type Buffering struct {
	// Request, when explicitly set to false, disables
	// proxy_request_buffering. Default (nil-checked separately) is
	// nginx's "on". Use *bool here so YAML `request: false` is
	// distinguishable from omitted.
	Request *bool `koanf:"request" yaml:"request,omitempty"`

	// Response, when explicitly set to false, disables proxy_buffering.
	Response *bool `koanf:"response" yaml:"response,omitempty"`

	// ClientBodyBufferSize sets client_body_buffer_size (e.g. "16k",
	// "1m"). Empty = nginx default (8k/16k depending on platform).
	ClientBodyBufferSize string `koanf:"client_body_buffer_size" yaml:"client_body_buffer_size,omitempty"`

	// ProxyBufferSize sets the size of the buffer used for the first
	// part of the response (headers + initial body). E.g. "8k", "64k".
	// Bump for upstream that emits large response headers.
	ProxyBufferSize string `koanf:"proxy_buffer_size" yaml:"proxy_buffer_size,omitempty"`

	// ProxyBuffers sets the number + size of buffers nginx allocates
	// per request for buffering responses. Format: "<count> <size>",
	// e.g. "8 16k".
	ProxyBuffers string `koanf:"proxy_buffers" yaml:"proxy_buffers,omitempty"`
}

// ConnectionPool tunes nginx's upstream keepalive — the pool of
// idle TCP connections to upstream servers nginx maintains for
// reuse. Defaults are fine for most workloads; bump
// KeepaliveConns for hot-path APIs whose upstream count > 16, or
// KeepaliveRequests for very long-lived connections.
//
//	upstream apigw_<name> {
//	    server …;
//	    keepalive          <KeepaliveConns>;
//	    keepalive_timeout  <KeepaliveTimeout>;
//	    keepalive_requests <KeepaliveRequests>;
//	}
type ConnectionPool struct {
	// KeepaliveConns is the max number of idle connections per worker.
	// Default (when unset): 16 (the legacy hard-coded value).
	KeepaliveConns int `koanf:"keepalive_conns" yaml:"keepalive_conns,omitempty"`

	// KeepaliveTimeout caps how long an idle connection stays in the
	// pool. 0 = nginx default (60s). Drop below upstream's idle
	// timeout to avoid receiving FINs on borrowed connections.
	KeepaliveTimeout time.Duration `koanf:"keepalive_timeout" yaml:"keepalive_timeout,omitempty"`

	// KeepaliveRequests caps how many requests one connection serves
	// before nginx closes it. 0 = nginx default (1000). Lift for
	// extremely long-lived clients (gRPC streams, websockets); lower
	// to encourage rotation.
	KeepaliveRequests int `koanf:"keepalive_requests" yaml:"keepalive_requests,omitempty"`
}

// Variant is one entry in an N-way weighted traffic split. Used for
// version-based routing ("send 20% to v2, 10% to v3, rest to v1")
// — a generalization of Canary that scales to more than two pools.
// Mutually exclusive with Canary and BlueGreen on the same API: if
// any is set, the others are ignored (generator picks Variants > BG
// > Canary in priority).
//
// Weights are percentages 0-100; sum SHOULD equal 100 but isn't
// enforced — the last variant catches whatever's left via the nginx
// `split_clients "*"` wildcard, so rounding errors don't drop
// traffic.
type Variant struct {
	Name      string     `koanf:"name" yaml:"name"`
	Weight    int        `koanf:"weight" yaml:"weight"`
	Upstreams []Upstream `koanf:"upstreams" yaml:"upstreams"`
}

// BlueGreen describes an atomic two-pool deployment. Unlike Canary,
// both pools live in config simultaneously; Active picks which one
// receives 100% of traffic. The other pool is staging — operators
// deploy + smoke-test against it, then `apigw api blue-green swap`
// to flip Active and reload nginx.
//
// Rollback after a swap is one more swap. Both pools remain
// declared, so reverting takes zero re-config.
//
// When BlueGreen is set, the active pool replaces API.Upstreams as
// the primary apigw_<name> upstream block — i.e. BlueGreen is
// mutually exclusive with the legacy Upstreams field. Canary still
// works on top: Canary.Weight% siphoned from the BlueGreen-active
// pool to Canary.Upstreams.
type BlueGreen struct {
	Blue   []Upstream `koanf:"blue" yaml:"blue"`
	Green  []Upstream `koanf:"green" yaml:"green"`
	Active string     `koanf:"active" yaml:"active"` // "blue" | "green"
}

// ActivePool returns the slice currently serving traffic, or nil if
// Active is unset/invalid (caller treats as misconfiguration).
func (b *BlueGreen) ActivePool() []Upstream {
	if b == nil {
		return nil
	}
	switch b.Active {
	case "blue":
		return b.Blue
	case "green":
		return b.Green
	}
	return nil
}

type Canary struct {
	// Weight is the percentage (0-100) of traffic that hits Upstreams
	// (the canary pool). Rest goes to API.Upstreams (the primary).
	Weight int `koanf:"weight" yaml:"weight"`

	// PinHeader, when set, names a request header (e.g. "X-Canary").
	// When a client sends that header with value "1", the request
	// pins to the canary pool regardless of Weight — operators use
	// this for forced QA traffic.
	PinHeader string `koanf:"pin_header" yaml:"pin_header,omitempty"`

	// Sticky, when true, hashes the routing decision on $remote_addr
	// so the same client consistently sees the same pool across
	// requests. False (default) hashes on $request_id — every request
	// is independently distributed, which is what you want for
	// load tests and what you DON'T want for real users (cart on
	// canary, checkout on primary → bug reports).
	Sticky bool `koanf:"sticky" yaml:"sticky,omitempty"`

	// Upstreams is the canary pool. Same shape as API.Upstreams.
	Upstreams []Upstream `koanf:"upstreams" yaml:"upstreams"`
}

// Transform describes per-API request/response body manipulation. We
// support a small set of JSON field operations evaluated in the dashboard
// daemon via /transform/<api>. For richer logic operators wire forward_auth
// to a real service.
type Transform struct {
	// RequestSetJSON injects/overrides a top-level JSON field on the request
	// body before forwarding to upstream. Map of jq-style path → value.
	// Example: {".user_id": "$claims.sub"}.
	RequestSetJSON map[string]string `koanf:"request_set_json" yaml:"request_set_json,omitempty"`

	// RequestStripJSON removes top-level fields. Example: [".password"].
	RequestStripJSON []string `koanf:"request_strip_json" yaml:"request_strip_json,omitempty"`

	// ResponseStripJSON removes top-level fields from the upstream response.
	ResponseStripJSON []string `koanf:"response_strip_json" yaml:"response_strip_json,omitempty"`
}

// Versioning sets how a /v1/x vs /v2/x split is routed. Strategy:
//
//	path    — /v1/api → upstream-v1, /v2/api → upstream-v2 (default)
//	header  — Accept-Version: v2 → upstream-v2
//	query   — ?version=v2 → upstream-v2
//
// SunsetDate, when set, emits an RFC 8594 Sunset header on every
// response so clients see deprecation.
type Versioning struct {
	Strategy   string `koanf:"strategy" yaml:"strategy"`                 // path | header | query
	SunsetDate string `koanf:"sunset_date" yaml:"sunset_date,omitempty"` // RFC 3339

	// Versions is the per-version routing table. When non-empty, the
	// gateway emits one sub-location per entry under <API.Path>/<Name>/
	// (path strategy — header/query require additional map plumbing and
	// are accepted as data but only path-strategy renders today).
	// Active versions proxy to Upstream normally; deprecated versions
	// add `Sunset` + `Deprecation: true` headers; retired versions
	// short-circuit with 410 and a `Link: <ReplacementURL>;
	// rel="successor-version"` header for clients that follow the
	// RFC 8594 / draft-deprecation-header dance.
	Versions []APIVersion `koanf:"versions" yaml:"versions,omitempty"`
}

// APIVersion is one entry in Versioning.Versions.
type APIVersion struct {
	// Name is the URL-safe identifier ("v1", "v2", "2025-01"). Used as
	// the path suffix when Strategy == "path".
	Name string `koanf:"name" yaml:"name"`

	// Upstream is the host:port (or named upstream) this version routes
	// to. Empty = inherit the API's primary upstream (matches behaviour
	// before multi-version was wired).
	Upstream string `koanf:"upstream" yaml:"upstream,omitempty"`

	// State — "active" (default), "deprecated", "retired". Empty means
	// active. Mirrors Lifecycle.State semantics but per-version.
	State string `koanf:"state" yaml:"state,omitempty"`

	// SunsetAt is the cutover date. Emitted as the Sunset response
	// header (RFC 8594) on deprecated versions, and embedded in the
	// retired-version Link header.
	SunsetAt time.Time `koanf:"sunset_at" yaml:"sunset_at,omitempty"`

	// ReplacementURL is the URL of the successor — sent as
	// `Link: <url>; rel="successor-version"` when this version is
	// retired or (optionally) deprecated.
	ReplacementURL string `koanf:"replacement_url" yaml:"replacement_url,omitempty"`
}

// MTLS configures per-API mutual TLS (client cert auth). nginx terminates
// the handshake with ssl_verify_client; the dashboard re-validates against
// per-API allow-lists (CN, SAN, sha256 fingerprint) via auth_request.
//
// CAFile is required — it's the bundle of CAs nginx trusts. AllowCNs /
// AllowSANs / AllowFingerprints are AND-of-OR: provide any combination,
// and a cert passes if it matches at least one rule from each provided list.
type MTLS struct {
	CAFile            string   `koanf:"ca_file" yaml:"ca_file"`
	AllowCNs          []string `koanf:"allow_cns" yaml:"allow_cns,omitempty"`
	AllowSANs         []string `koanf:"allow_sans" yaml:"allow_sans,omitempty"`
	AllowFingerprints []string `koanf:"allow_fingerprints" yaml:"allow_fingerprints,omitempty"`
	Optional          bool     `koanf:"optional" yaml:"optional,omitempty"`

	// OCSPCheck turns on revocation checking against the client cert's
	// AuthorityInfoAccess OCSP responder. Defense-in-depth on top of
	// nginx's chain verification: catches certs that were revoked AFTER
	// being issued (e.g. a stolen key). Off by default — most public CAs
	// (LE in particular) no longer run OCSP responders, but corporate /
	// Smallstep / Vault PKI usually do.
	OCSPCheck bool `koanf:"ocsp_check" yaml:"ocsp_check,omitempty"`

	// OCSPSoftFail accepts the request when the responder is unreachable
	// or returns "unknown". Default (false) is hard-fail (403). Soft-fail
	// is the right choice when responder uptime is worse than your traffic
	// tolerance for spurious 403s.
	OCSPSoftFail bool `koanf:"ocsp_soft_fail" yaml:"ocsp_soft_fail,omitempty"`

	// OCSPCacheTTL caps how long a cached OCSP response is trusted, even
	// if the responder said nextUpdate is further out. 0 = 12h default.
	OCSPCacheTTL time.Duration `koanf:"ocsp_cache_ttl" yaml:"ocsp_cache_ttl,omitempty"`
}

// JWT configures per-API JWT validation. The dashboard daemon serves an
// internal /auth/jwt/<api> endpoint; nginx auth_request calls it on every
// request. Algorithm + (HMACSecret OR JWKSURL) is the minimum.
//
// See internal/auth/jwt.go for the verifier implementation. The same struct
// is mirrored as internal/auth.JWTConfig — they're kept in sync deliberately
// (config = serialized form, auth = in-process form).
type JWT struct {
	Algorithm     string            `koanf:"algorithm" yaml:"algorithm"`               // HS256/RS256/ES256/EdDSA/...
	HMACSecret    string            `koanf:"hmac_secret" yaml:"hmac_secret,omitempty"` // required for HS*
	JWKSURL       string            `koanf:"jwks_url" yaml:"jwks_url,omitempty"`       // required for RS*/ES*/EdDSA
	Issuer        string            `koanf:"issuer" yaml:"issuer,omitempty"`           // optional iss check
	Audience      string            `koanf:"audience" yaml:"audience,omitempty"`       // optional aud check
	RequireClaims map[string]string `koanf:"require_claims" yaml:"require_claims,omitempty"`
}

// Mirror of the API middleware on Deploy — when both are set they apply at
// the deploy's nginx location. Keeping the shape identical means apigw api
// and apigw deploy share the same docs + generator logic.

// Deploy is a git-backed deployment.
//
// The actual on-disk layout lives in /var/lib/apigw/<name>/{releases/<sha>,current}
// — see internal/deploy/swap.go. The fields here are configuration; runtime
// state (last SHA, last deploy time, status) is recorded after each successful
// pass so `apigw deploy list` doesn't have to shell out to git/journald.
type Deploy struct {
	Name        string `koanf:"name" yaml:"name"`
	Repo        string `koanf:"repo" yaml:"repo"`
	Branch      string `koanf:"branch" yaml:"branch"`
	Port        int    `koanf:"port" yaml:"port"`       // upstream port nginx proxies to
	Path        string `koanf:"path" yaml:"path"`       // nginx mount, default /apps/<name>
	Runtime     string `koanf:"runtime" yaml:"runtime"` // auto|node|python|go|docker|static
	Build       string `koanf:"build" yaml:"build"`     // override build cmd (empty = runtime default)
	Start       string `koanf:"start" yaml:"start"`     // override start cmd
	Description string `koanf:"description" yaml:"description"`
	Enabled     bool   `koanf:"enabled" yaml:"enabled"`

	// HealthPath, when set, switches deploy health probes to STRICT HTTP
	// mode: a successful TCP connect plus GET <HealthPath> returning 2xx
	// is required for the deploy to be considered live. Empty preserves
	// the legacy lenient TCP-only probe so existing apps don't regress.
	HealthPath string `koanf:"health_path" yaml:"health_path,omitempty"`

	// Shared lists paths (relative to the release root) that must survive
	// across releases. apigw materialises each as
	// <StateDir>/<name>/shared/<path> on first use and symlinks the
	// release-local copy into the persistent location on every deploy.
	// First-time migration copies any existing content already inside the
	// release into shared/ so operators can flip a long-running deploy to
	// shared dirs without losing data. Example:
	//   shared: [backend/uploads, backend/logs, data/sqlite.db]
	Shared []string `koanf:"shared" yaml:"shared,omitempty"`

	// Recorded after each pass.
	LastSHA    string `koanf:"last_sha" yaml:"last_sha"`
	LastDeploy string `koanf:"last_deploy" yaml:"last_deploy"` // RFC3339
	LastStatus string `koanf:"last_status" yaml:"last_status"` // ok|failed|building|stopped
	LastError  string `koanf:"last_error" yaml:"last_error,omitempty"`

	// Multi-upstream + LB mirror of API.
	Upstreams   []Upstream `koanf:"upstreams" yaml:"upstreams,omitempty"`
	LoadBalance string     `koanf:"load_balance" yaml:"load_balance,omitempty"`
	GRPC        bool       `koanf:"grpc" yaml:"grpc,omitempty"`

	// Middleware mirror of API. See API field comments for semantics.
	MaxBodySize string        `koanf:"max_body_size" yaml:"max_body_size,omitempty"`
	Headers     *Headers      `koanf:"headers" yaml:"headers,omitempty"`
	IPRules     *IPRules      `koanf:"ip_rules" yaml:"ip_rules,omitempty"`
	CORS        *CORS         `koanf:"cors" yaml:"cors,omitempty"`
	BasicAuth   *BasicAuth    `koanf:"basic_auth" yaml:"basic_auth,omitempty"`
	RateLimit   *RateLimit    `koanf:"rate_limit" yaml:"rate_limit,omitempty"`
	ForwardAuth *ForwardAuth  `koanf:"forward_auth" yaml:"forward_auth,omitempty"`
	HealthCheck *HealthCheck  `koanf:"health_check" yaml:"health_check,omitempty"`
	Retry       *Retry        `koanf:"retry" yaml:"retry,omitempty"`
	JWT         *JWT          `koanf:"jwt" yaml:"jwt,omitempty"`
	MTLS        *MTLS         `koanf:"mtls" yaml:"mtls,omitempty"`
	Rewrites    []RewriteRule `koanf:"rewrites" yaml:"rewrites,omitempty"`

	CustomLocation string `koanf:"custom_location" yaml:"custom_location,omitempty"`
	CustomServer   string `koanf:"custom_server" yaml:"custom_server,omitempty"`
}

type Webhook struct {
	Enabled bool   `koanf:"enabled" yaml:"enabled"`
	Port    int    `koanf:"port" yaml:"port"`
	Path    string `koanf:"path" yaml:"path"` // default /webhook
}

type Dashboard struct {
	Enabled bool   `koanf:"enabled" yaml:"enabled"`
	Port    int    `koanf:"port" yaml:"port"`
	Path    string `koanf:"path" yaml:"path"` // default /dashboard
}

type TLS struct {
	Strategy     string   `koanf:"strategy" yaml:"strategy"` // none|letsencrypt|duckdns|self-signed
	Domains      []string `koanf:"domains" yaml:"domains"`
	Email        string   `koanf:"email" yaml:"email"`
	Staging      bool     `koanf:"staging" yaml:"staging"`
	DuckDNSToken string   `koanf:"duckdns_token" yaml:"duckdns_token"`

	// DNSPropagationTimeoutSeconds caps how long DNS-01 challenges wait for
	// the TXT record to propagate before failing. 0 = library default
	// (120s for DuckDNS). Bump to 180-300 on slow registrars to avoid
	// spurious renewal failures during LE rate-limit retries.
	DNSPropagationTimeoutSeconds int `koanf:"dns_propagation_timeout_seconds" yaml:"dns_propagation_timeout_seconds,omitempty"`

	// OCSPStapling turns on `ssl_stapling on; ssl_stapling_verify on;`
	// for our own server cert. Off by default because Let's Encrypt
	// killed their OCSP responders in Aug 2025 — turning stapling on
	// for an LE cert just yields warnings. Flip on for non-LE
	// strategies (DigiCert, Sectigo, internal CAs) where the responder
	// is still alive.
	OCSPStapling bool `koanf:"ocsp_stapling" yaml:"ocsp_stapling,omitempty"`
}

// Defaults returns a config preloaded with sensible defaults. Save-only fields
// (path) are left empty; the caller sets them.
func Defaults() Config {
	return Config{
		Version: SchemaVersion,
		Listen: Listen{
			HTTPPort:   80,
			HTTPSPort:  443,
			ServerName: "_",
		},
		APIs:    []API{},
		Deploys: []Deploy{},
		Webhook: Webhook{
			Enabled: false,
			Port:    9000,
			Path:    "/webhook",
		},
		Dashboard: Dashboard{
			Enabled: true,
			Port:    9080,
			Path:    "/dashboard",
		},
		TLS: TLS{Strategy: "none"},
	}
}

// SearchPaths is the ordered list of locations Load() probes. First hit wins.
// XDG first (per-user), then system-wide /etc.
func SearchPaths() []string {
	out := []string{}
	// APIGW_CONFIG_DIR (via paths.ConfigDir) wins so a custom layout — set in
	// the systemd unit, a CI sandbox, or a rootless install — is honored
	// consistently with every other APIGW_* override. Without this, Load()
	// silently fell back to defaults (empty security!) whenever the operator
	// pointed APIGW_CONFIG_DIR somewhere other than /etc/apigw.
	out = append(out, filepath.Join(paths.ConfigDir(), "config.yaml"))
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		out = append(out, filepath.Join(xdg, "apigw", "config.yaml"))
	} else if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".config", "apigw", "config.yaml"))
	}
	out = append(out, "/etc/apigw/config.yaml")
	return out
}

// Load reads config from the first SearchPaths() entry that exists, applies
// env overrides (APIGW_*), and returns a populated Config.
//
// If no config file exists, returns Defaults() with path set to the preferred
// XDG location — apigw install then writes /etc/apigw/config.yaml.
func Load() (cmdutil.Config, error) {
	return LoadFrom("")
}

// LoadFrom is Load with an explicit path; used by --config flag.
func LoadFrom(explicit string) (cmdutil.Config, error) {
	k := koanf.New(".")
	def := Defaults()

	// 1. defaults
	if err := k.Load(structs.Provider(def, "koanf"), nil); err != nil {
		return nil, cmdutil.NewConfigError(fmt.Errorf("load defaults: %w", err))
	}

	// 2. file
	path := explicit
	if path == "" {
		for _, p := range SearchPaths() {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, cmdutil.NewConfigError(fmt.Errorf("read %s: %w", path, err))
		}
	} else {
		// No file present — use the system-wide path for future Save().
		path = "/etc/apigw/config.yaml"
	}

	// 3. env (APIGW_LISTEN_HTTP_PORT=8080 -> listen.http_port)
	if err := k.Load(env.Provider("APIGW_", ".", envMap), nil); err != nil {
		return nil, cmdutil.NewConfigError(fmt.Errorf("load env: %w", err))
	}

	cfg := Defaults()
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, cmdutil.NewConfigError(fmt.Errorf("decode: %w", err))
	}
	cfg.path = path
	return &cfg, nil
}

// envMap turns APIGW_LISTEN_HTTP_PORT into listen.http_port.
func envMap(s string) string {
	// strip APIGW_ prefix
	s = s[len("APIGW_"):]
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
			out = append(out, '.')
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// Path returns the on-disk location this config will be saved to.
func (c *Config) Path() string { return c.path }

// SetPath overrides the save target. Used by `apigw install` when it decides
// between XDG and /etc.
func (c *Config) SetPath(p string) { c.path = p }

// Save writes the config atomically: tmp + fsync + rename, under a flock.
//
// Always writes the schema version + a managed-by banner via YAML doc comment
// in the future — for now a clean YAML dump is sufficient.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config has no path; call SetPath first")
	}
	if c.Version == 0 {
		c.Version = SchemaVersion
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	lock := flock.New(filepath.Join(dir, ".lock"))
	if err := lock.Lock(); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	tmp, err := os.CreateTemp(dir, "config.yaml.*.tmp")
	if err != nil {
		return fmt.Errorf("tmp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // best-effort cleanup if anything below fails

	// Encode via koanf-yaml for stable formatting.
	k := koanf.New(".")
	if err := k.Load(structs.Provider(*c, "koanf"), nil); err != nil {
		tmp.Close()
		return fmt.Errorf("marshal: %w", err)
	}
	b, err := k.Marshal(yaml.Parser())
	if err != nil {
		tmp.Close()
		return fmt.Errorf("encode yaml: %w", err)
	}
	banner := fmt.Sprintf("# MANAGED BY apigw — do not edit.\n"+
		"# Use `apigw api add|remove` or run `apigw install`.\n"+
		"# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	if _, err := tmp.WriteString(banner); err != nil {
		tmp.Close()
		return fmt.Errorf("write banner: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Snapshot returns the current YAML bytes — used by `apigw backup`.
func (c *Config) Snapshot() ([]byte, error) {
	k := koanf.New(".")
	if err := k.Load(structs.Provider(*c, "koanf"), nil); err != nil {
		return nil, err
	}
	return k.Marshal(yaml.Parser())
}

// FindAPI returns a pointer to the named API entry, or nil if absent.
func (c *Config) FindAPI(name string) *API {
	for i := range c.APIs {
		if c.APIs[i].Name == name {
			return &c.APIs[i]
		}
	}
	return nil
}

// AddAPI registers a new API; returns an error if a duplicate name exists.
func (c *Config) AddAPI(a API) error {
	if c.FindAPI(a.Name) != nil {
		return fmt.Errorf("api %q already exists", a.Name)
	}
	c.APIs = append(c.APIs, a)
	return nil
}

// RemoveAPI deletes the named API; returns an error if not found.
func (c *Config) RemoveAPI(name string) error {
	for i := range c.APIs {
		if c.APIs[i].Name == name {
			c.APIs = append(c.APIs[:i], c.APIs[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("api %q not found", name)
}

// SetEnabled toggles an API on or off; returns an error if not found.
func (c *Config) SetEnabled(name string, enabled bool) error {
	a := c.FindAPI(name)
	if a == nil {
		return fmt.Errorf("api %q not found", name)
	}
	a.Enabled = enabled
	return nil
}
