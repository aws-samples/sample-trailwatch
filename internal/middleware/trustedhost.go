package middleware

import (
	"log/slog"
	"net/http"

	"cloudtrail-analyzer/internal/config"
)

// TrustedHost returns middleware that rejects requests whose Host header is not
// in the configured allowlist. This closes the DNS-rebinding attack class: even
// though the server binds loopback by default, a malicious website the user is
// visiting could otherwise point a DNS name at 127.0.0.1 and have the victim's
// browser issue authenticated same-origin requests to this server (reading
// CloudTrail data, POSTing AWS credentials to /api/settings). Browsers send the
// attacker's hostname in the Host header, so validating it blocks the rebind.
//
// localhost / 127.0.0.1 / [::1] are always allowed; operators add extra
// hostnames via config.TrustedHosts (e.g. when fronting with an authenticating
// reverse proxy). A TrustedHosts entry of "*" disables the check.
func TrustedHost(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.TrustedHostAllowed(r.Host) {
				slog.Warn("rejected request with untrusted Host header",
					"component", "cloudtrail-analyzer",
					"host", r.Host,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":"UNTRUSTED_HOST","message":"Request rejected: the Host header is not in the trusted-hosts allowlist. Access this tool via localhost, or add your hostname to trusted_hosts in config.json."}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
