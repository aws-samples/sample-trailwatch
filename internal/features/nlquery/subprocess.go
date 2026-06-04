package nlquery

import (
	"os"
	"strings"
)

// awsCredEnvPrefixes are the environment variable name prefixes that carry AWS
// credentials or credential-bearing configuration. The server holds live STS
// session credentials in its own environment (set by the Credentials UI), and a
// child process spawned via exec.Command inherits the parent environment by
// default. The DuckDB query/index subprocesses and the Ollama subprocesses do
// not need AWS credentials, so leaking them into those processes is needless
// exposure (N23). scrubbedEnv strips these before exec.
var awsCredEnvPrefixes = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_SECURITY_TOKEN",
	"AWS_CREDENTIAL",   // AWS_CREDENTIAL_EXPIRATION, AWS_CREDENTIALS_*
	"AWS_PROFILE",      // could resolve to on-disk credentials
	"AWS_WEB_IDENTITY", // AWS_WEB_IDENTITY_TOKEN_FILE
	"AWS_CONTAINER",    // AWS_CONTAINER_CREDENTIALS_*
	"AWS_SHARED_CREDENTIALS_FILE",
}

// scrubbedEnv returns a copy of the current process environment with AWS
// credential variables removed, suitable for assigning to exec.Cmd.Env when
// launching a subprocess (DuckDB, Ollama) that has no business reading the
// operator's AWS credentials. Non-credential AWS settings such as AWS_REGION
// are intentionally preserved.
func scrubbedEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, kv := range src {
		eq := strings.IndexByte(kv, '=')
		name := kv
		if eq >= 0 {
			name = kv[:eq]
		}
		if isAWSCredEnv(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func isAWSCredEnv(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range awsCredEnvPrefixes {
		if upper == p || strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}
