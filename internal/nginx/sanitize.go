package nginx

import (
	"fmt"
	"regexp"
	"strings"
)

// safeNameRE constrains entity names — these flow into log identifiers,
// directory names, and (via templates) systemd unit specifiers. The CLI
// add-commands validate against a similar regex; we re-check here as
// defense-in-depth so a hand-edited config.yaml can't break out.
var safeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// safePathRE keeps URL paths to characters nginx can interpret safely.
// Allows: lowercase + digits, /, -, _, dot. Rejects: ; { } \r \n " ' \
// space (the canonical nginx-config-injection vectors).
var safePathRE = regexp.MustCompile(`^/[a-zA-Z0-9._/-]*$`)

// sanitizeName returns an error if `name` contains characters nginx will
// either misinterpret or treat as a directive boundary.
func sanitizeName(name string) error {
	if !safeNameRE.MatchString(name) {
		return fmt.Errorf("name %q is invalid: must match %s", name, safeNameRE.String())
	}
	return nil
}

// sanitizePath enforces a strict allowlist on URL paths emitted into
// `location` directives. Any character that could close the directive
// (`;`, `{`, `}`) or inject a new one (`\n`) is rejected outright.
//
// The check happens at generator time, not at CLI parse time, so a
// malicious user who edited /etc/apigw/config.yaml directly still trips
// this gate before nginx ever sees the bad config.
func sanitizePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path %q must start with /", path)
	}
	// Cheap explicit blacklist for the highest-signal characters — keeps
	// the rejection message specific even when the regex would catch them.
	for _, bad := range []rune{';', '{', '}', '\n', '\r', '"', '\'', '\\', 0} {
		if strings.ContainsRune(path, bad) {
			return fmt.Errorf("path %q contains illegal character %q", path, bad)
		}
	}
	if !safePathRE.MatchString(path) {
		return fmt.Errorf("path %q is invalid: must match %s", path, safePathRE.String())
	}
	return nil
}

// safeRedirectURLRE constrains absolute redirect targets. Deliberately
// narrower than a real URL grammar: no userinfo, no spaces, no quotes —
// just scheme, host and an ordinary path/query.
var safeRedirectURLRE = regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[a-zA-Z0-9._/~%&=?+-]*)?$`)

// sanitizeRedirect validates a redirect target before it is interpolated
// into a `return 301 <target>;` directive. The value reaches us from
// config.yaml, which an operator may have hand-edited, so an unchecked
// value here is a straight nginx-config injection: a `;` would close the
// return and let anything follow it.
//
// Accepts either an absolute path ("/dashboard/") or a full http(s) URL.
func sanitizeRedirect(target string) error {
	if target == "" {
		return fmt.Errorf("redirect target is empty")
	}
	// '$' is in the list because nginx would expand it as a variable
	// reference inside the directive, not because it can close it.
	for _, bad := range []rune{';', '{', '}', '\n', '\r', '"', '\'', '\\', ' ', '$', 0} {
		if strings.ContainsRune(target, bad) {
			return fmt.Errorf("redirect target %q contains illegal character %q", target, bad)
		}
	}
	if strings.HasPrefix(target, "/") {
		// Reject "//host" — browsers read it as protocol-relative and would
		// send the visitor off-site.
		if strings.HasPrefix(target, "//") {
			return fmt.Errorf("redirect target %q is protocol-relative; use a full URL instead", target)
		}
		return nil
	}
	if !safeRedirectURLRE.MatchString(target) {
		return fmt.Errorf("redirect target %q must be an absolute path or an http(s) URL", target)
	}
	return nil
}

// sanitizeServerName accepts a single nginx server_name value (no spaces;
// "_" is a valid catch-all). Multiple names are joined by the caller; we
// validate each token.
func sanitizeServerName(name string) error {
	if name == "_" {
		return nil
	}
	if name == "" {
		return fmt.Errorf("server_name is empty")
	}
	// hostname-like: letters, digits, dot, hyphen.
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '*'
		if !ok {
			return fmt.Errorf("server_name %q contains illegal character %q", name, r)
		}
	}
	return nil
}
