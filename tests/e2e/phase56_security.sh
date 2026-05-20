#!/bin/bash
# Phase 5 & 6: Authentication, Authorization & Security Testing
BASE_URL="http://localhost:7070"
PASS=0
FAIL=0
RESULTS=""

log_result() {
    local status=$1
    local test_id=$2
    local description=$3
    local detail=$4
    if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
        RESULTS="${RESULTS}PASS | ${test_id} | ${description}\n"
    else
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}FAIL | ${test_id} | ${description} | ${detail}\n"
    fi
}

echo "=== PHASE 5 & 6: SECURITY TESTING ==="
echo ""

# TC-5-AUTH-001: No authentication required (single-user local tool)
echo "Testing: API accessible without auth..."
resp=$(curl -s -w "%{http_code}" "${BASE_URL}/api/health")
if echo "$resp" | grep -q "200"; then
    log_result "PASS" "TC-5-AUTH-001" "API accessible without auth (expected for local tool)"
else
    log_result "FAIL" "TC-5-AUTH-001" "API should be accessible" "Health check failed"
fi

# TC-6-SEC-001: No sensitive data in health response
echo "Testing: No secrets in health response..."
resp=$(curl -s "${BASE_URL}/api/health")
if echo "$resp" | grep -qi "password\|secret\|token\|key"; then
    log_result "FAIL" "TC-6-SEC-001" "Health response should not contain secrets" "Found sensitive keywords"
else
    log_result "PASS" "TC-6-SEC-001" "No secrets in health response"
fi

# TC-6-SEC-002: No AWS credentials in settings response
echo "Testing: No AWS secrets in settings response..."
resp=$(curl -s "${BASE_URL}/api/settings")
has_secret=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
auth = d.get('auth', {})
# Check that secret_access_key and session_token are empty/absent
sak = auth.get('secret_access_key', '')
st = auth.get('session_token', '')
if sak or st:
    print('EXPOSED')
else:
    print('SAFE')
" 2>/dev/null)
if [ "$has_secret" = "SAFE" ]; then
    log_result "PASS" "TC-6-SEC-002" "No AWS secrets exposed in settings API"
else
    log_result "FAIL" "TC-6-SEC-002" "AWS secrets should not be in settings response" "Found credentials"
fi

# TC-6-SEC-003: Error responses don't leak stack traces
echo "Testing: Error responses don't leak internals..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d 'invalid' "${BASE_URL}/api/nlquery/execute")
if echo "$resp" | grep -qi "goroutine\|panic\|stack\|/Users/\|/home/"; then
    log_result "FAIL" "TC-6-SEC-003" "Error response leaks internal paths/stack" "Found internal info"
else
    log_result "PASS" "TC-6-SEC-003" "Error responses don't leak internals"
fi

# TC-6-SEC-004: CORS headers restrict origins
echo "Testing: CORS restricts origins..."
resp=$(curl -s -D - -o /dev/null -H "Origin: http://evil.com" "${BASE_URL}/api/health")
if echo "$resp" | grep -q "Access-Control-Allow-Origin: http://evil.com"; then
    log_result "FAIL" "TC-6-SEC-004" "CORS allows arbitrary origins" "evil.com was allowed"
else
    log_result "PASS" "TC-6-SEC-004" "CORS does not allow arbitrary origins"
fi

# TC-6-SEC-005: CORS allows legitimate origin
echo "Testing: CORS allows localhost:5173..."
resp=$(curl -s -D - -o /dev/null -H "Origin: http://localhost:5173" "${BASE_URL}/api/health")
if echo "$resp" | grep -q "Access-Control-Allow-Origin: http://localhost:5173"; then
    log_result "PASS" "TC-6-SEC-005" "CORS allows localhost:5173"
else
    log_result "FAIL" "TC-6-SEC-005" "CORS should allow localhost:5173" "Header not found"
fi

# TC-6-SEC-006: Server binds to localhost only
echo "Testing: Server binds to localhost..."
resp=$(curl -s "${BASE_URL}/api/settings")
host=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('host',''))" 2>/dev/null)
if [ "$host" = "127.0.0.1" ]; then
    log_result "PASS" "TC-6-SEC-006" "Server binds to 127.0.0.1 (localhost only)"
else
    log_result "FAIL" "TC-6-SEC-006" "Server should bind to 127.0.0.1" "Got: $host"
fi

# TC-6-SEC-007: No directory listing
echo "Testing: No directory listing..."
resp=$(curl -s -w "\n%{http_code}" "${BASE_URL}/data/")
status=$(echo "$resp" | tail -1)
if [ "$status" = "404" ] || [ "$status" = "200" ]; then
    body=$(curl -s "${BASE_URL}/data/")
    if echo "$body" | grep -qi "index of\|directory listing\|\.json\.gz"; then
        log_result "FAIL" "TC-6-SEC-007" "Directory listing exposed" "Found file listing"
    else
        log_result "PASS" "TC-6-SEC-007" "No directory listing exposed"
    fi
else
    log_result "PASS" "TC-6-SEC-007" "No directory listing (status: $status)"
fi

# TC-6-SEC-008: API returns JSON content type
echo "Testing: API returns proper content type..."
content_type=$(curl -s -D - -o /dev/null "${BASE_URL}/api/health" | grep -i "content-type")
if echo "$content_type" | grep -qi "application/json"; then
    log_result "PASS" "TC-6-SEC-008" "API returns application/json content type"
else
    log_result "FAIL" "TC-6-SEC-008" "API should return application/json" "Got: $content_type"
fi

# TC-6-SEC-009: No sensitive headers leaked
echo "Testing: No server version headers..."
headers=$(curl -s -D - -o /dev/null "${BASE_URL}/api/health")
if echo "$headers" | grep -qi "X-Powered-By\|Server: "; then
    log_result "FAIL" "TC-6-SEC-009" "Server leaks version headers" "Found server identification"
else
    log_result "PASS" "TC-6-SEC-009" "No server version headers leaked"
fi

# TC-6-SEC-010: SQL injection in investigate param
echo "Testing: SQL injection in investigate param..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"scenario_id\":\"access-denied-by-identity\",\"param\":\"' OR '1'='1; DROP TABLE events;--\"}" \
    "${BASE_URL}/api/investigate/run")
# The param should be safely embedded in the SQL (quoted/escaped)
if echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
sql = d.get('sql','')
# Check that the injection is properly quoted/escaped in the SQL
# It should NOT appear as raw unquoted SQL
if 'DROP TABLE' in sql and \"''\" not in sql and \"'\" + \" OR \" not in sql.replace(\"''\",\"\"):
    print('VULNERABLE')
else:
    print('SAFE')
" 2>/dev/null | grep -q "SAFE"; then
    log_result "PASS" "TC-6-SEC-010" "SQL injection in param is safely handled"
else
    log_result "FAIL" "TC-6-SEC-010" "SQL injection in param may be vulnerable" "Check SQL escaping"
fi

# TC-6-SEC-011: Session credentials not persisted
echo "Testing: Session credentials scrubbed from config..."
config_content=$(cat config.json 2>/dev/null)
if echo "$config_content" | python3 -c "
import sys,json
d=json.load(sys.stdin)
auth = d.get('auth', {})
if auth.get('secret_access_key') or auth.get('session_token'):
    print('PERSISTED')
else:
    print('CLEAN')
" 2>/dev/null | grep -q "CLEAN"; then
    log_result "PASS" "TC-6-SEC-011" "No credentials persisted in config.json"
else
    log_result "FAIL" "TC-6-SEC-011" "Credentials should not be in config.json" "Found persisted creds"
fi

# TC-6-SEC-012: Validate-credentials endpoint doesn't expose secrets in response
echo "Testing: Validate-credentials response safety..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{}' "${BASE_URL}/api/settings/validate-credentials")
if echo "$resp" | grep -qi "secret_access_key\|session_token"; then
    log_result "FAIL" "TC-6-SEC-012" "Validate-credentials leaks secrets" "Found secret in response"
else
    log_result "PASS" "TC-6-SEC-012" "Validate-credentials doesn't leak secrets"
fi

# TC-6-SEC-013: Rate limiting check (informational)
echo "Testing: Rate limiting (informational)..."
start_time=$(python3 -c "import time; print(time.time())")
for i in $(seq 1 100); do
    curl -s -o /dev/null "${BASE_URL}/api/health"
done
end_time=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end_time - $start_time, 2))")
# No rate limiting expected for local tool, but document it
log_result "PASS" "TC-6-SEC-013" "100 requests in ${duration}s (no rate limiting - acceptable for local tool)"

# TC-6-SEC-014: Check for X-Content-Type-Options header
echo "Testing: X-Content-Type-Options header..."
headers=$(curl -s -D - -o /dev/null "${BASE_URL}/api/health")
if echo "$headers" | grep -qi "X-Content-Type-Options"; then
    log_result "PASS" "TC-6-SEC-014" "X-Content-Type-Options header present"
else
    log_result "FAIL" "TC-6-SEC-014" "Missing X-Content-Type-Options header" "Security header not set"
fi

# TC-6-SEC-015: Check for X-Frame-Options header
echo "Testing: X-Frame-Options header..."
if echo "$headers" | grep -qi "X-Frame-Options\|frame-ancestors"; then
    log_result "PASS" "TC-6-SEC-015" "X-Frame-Options/frame-ancestors present"
else
    log_result "FAIL" "TC-6-SEC-015" "Missing X-Frame-Options header" "Clickjacking protection missing"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
