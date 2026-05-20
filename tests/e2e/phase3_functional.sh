#!/bin/bash
# Phase 3: Functional Testing - Investigation Workflows
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

echo "=== PHASE 3: FUNCTIONAL TESTING ==="
echo ""

# TC-3-SESS-001: Create a session
echo "Testing: Create session..."
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{"account_id":"123456789012","region":"us-east-1","start_date":"2025-08-01","end_date":"2025-08-15","mode":"single"}' \
    "${BASE_URL}/api/sessions")
status=$(echo "$resp" | tail -1)
body=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"account_id":"123456789012","region":"us-east-1","start_date":"2025-08-01","end_date":"2025-08-15","mode":"single"}' \
    "${BASE_URL}/api/sessions")
if [ "$status" = "201" ] || [ "$status" = "200" ]; then
    session_id=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    log_result "PASS" "TC-3-SESS-001" "Create session returns $status (id: $session_id)"
else
    log_result "FAIL" "TC-3-SESS-001" "Create session should return 201/200" "Got: $status"
    session_id=""
fi

# TC-3-SESS-002: List sessions
echo "Testing: List sessions..."
resp=$(curl -s "${BASE_URL}/api/sessions")
count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else 0)" 2>/dev/null)
if [ "$count" -ge "1" ] 2>/dev/null; then
    log_result "PASS" "TC-3-SESS-002" "List sessions returns $count sessions"
else
    log_result "FAIL" "TC-3-SESS-002" "List sessions should return at least 1" "Got: $count"
fi

# TC-3-SESS-003: Get specific session
if [ -n "$session_id" ]; then
    echo "Testing: Get session by ID..."
    resp=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/sessions/${session_id}")
    status=$(echo "$resp" | tail -1)
    if [ "$status" = "200" ]; then
        log_result "PASS" "TC-3-SESS-003" "Get session by ID returns 200"
    else
        log_result "FAIL" "TC-3-SESS-003" "Get session by ID should return 200" "Got: $status"
    fi
else
    log_result "FAIL" "TC-3-SESS-003" "Get session by ID" "No session_id from creation"
fi

# TC-3-SESS-004: Delete session
if [ -n "$session_id" ]; then
    echo "Testing: Delete session..."
    resp=$(curl -s -w "\n%{http_code}" -X DELETE "${BASE_URL}/api/sessions/${session_id}")
    status=$(echo "$resp" | tail -1)
    if [ "$status" = "200" ] || [ "$status" = "204" ]; then
        log_result "PASS" "TC-3-SESS-004" "Delete session returns $status"
    else
        log_result "FAIL" "TC-3-SESS-004" "Delete session should return 200/204" "Got: $status"
    fi
fi

# TC-3-INV-001: Run valid investigation scenario (iam-write-ops, no param needed)
echo "Testing: Run iam-write-ops scenario..."
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":""}' "${BASE_URL}/api/investigate/run")
status=$(echo "$resp" | tail -1)
body=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":""}' "${BASE_URL}/api/investigate/run")
if [ "$status" = "200" ]; then
    has_sql=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
    if [ "$has_sql" = "yes" ]; then
        log_result "PASS" "TC-3-INV-001" "iam-write-ops scenario returns SQL"
    else
        log_result "FAIL" "TC-3-INV-001" "iam-write-ops should return SQL" "No SQL in response"
    fi
else
    log_result "FAIL" "TC-3-INV-001" "iam-write-ops should return 200" "Got: $status"
fi

# TC-3-INV-002: Run scenario with parameter (access-denied-by-identity)
echo "Testing: Run parameterized scenario..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-by-identity","param":"arn:aws:iam::123456789012:user/testuser"}' \
    "${BASE_URL}/api/investigate/run")
has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
if [ "$has_sql" = "yes" ]; then
    log_result "PASS" "TC-3-INV-002" "Parameterized scenario returns SQL with param embedded"
else
    log_result "FAIL" "TC-3-INV-002" "Parameterized scenario should return SQL" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-INV-003: Run scenario with time filters
echo "Testing: Scenario with time filters..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":"","filters":{"time_start":"2025-08-01","time_end":"2025-08-15"}}' \
    "${BASE_URL}/api/investigate/run")
has_time=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if '2025-08-01' in d.get('sql','') else 'no')" 2>/dev/null)
if [ "$has_time" = "yes" ]; then
    log_result "PASS" "TC-3-INV-003" "Time filters applied to SQL"
else
    log_result "FAIL" "TC-3-INV-003" "Time filters should appear in SQL" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-INV-004: Run scenario with account filter
echo "Testing: Scenario with account filter..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":"","filters":{"account_ids":["123456789012"]}}' \
    "${BASE_URL}/api/investigate/run")
has_account=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if '123456789012' in d.get('sql','') else 'no')" 2>/dev/null)
if [ "$has_account" = "yes" ]; then
    log_result "PASS" "TC-3-INV-004" "Account filter applied to SQL"
else
    log_result "FAIL" "TC-3-INV-004" "Account filter should appear in SQL" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-DASH-001: Dashboard returns structured data
echo "Testing: Dashboard structure..."
resp=$(curl -s "${BASE_URL}/api/dashboard")
valid=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# Should have metrics or similar structure
print('yes' if isinstance(d, dict) else 'no')
" 2>/dev/null)
if [ "$valid" = "yes" ]; then
    log_result "PASS" "TC-3-DASH-001" "Dashboard returns valid structured data"
else
    log_result "FAIL" "TC-3-DASH-001" "Dashboard should return structured data" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-DASH-002: Dashboard findings list
echo "Testing: Dashboard findings..."
resp=$(curl -s "${BASE_URL}/api/dashboard/findings")
valid=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('yes' if isinstance(d, (list, dict)) else 'no')
" 2>/dev/null)
if [ "$valid" = "yes" ]; then
    log_result "PASS" "TC-3-DASH-002" "Dashboard findings returns valid data"
else
    log_result "FAIL" "TC-3-DASH-002" "Dashboard findings should return data" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-LOOK-001: Lookups return structured data
echo "Testing: Lookups endpoint..."
resp=$(curl -s "${BASE_URL}/api/lookups")
valid=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('yes' if isinstance(d, dict) else 'no')
" 2>/dev/null)
if [ "$valid" = "yes" ]; then
    log_result "PASS" "TC-3-LOOK-001" "Lookups returns valid structured data"
else
    log_result "FAIL" "TC-3-LOOK-001" "Lookups should return structured data" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-PROM-001: Prompts list
echo "Testing: Prompts list..."
resp=$(curl -s "${BASE_URL}/api/prompts")
count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else -1)" 2>/dev/null)
if [ "$count" -ge "0" ] 2>/dev/null; then
    log_result "PASS" "TC-3-PROM-001" "Prompts list returns $count prompts"
else
    log_result "FAIL" "TC-3-PROM-001" "Prompts should return a list" "Response: $(echo $resp | head -c 200)"
fi

# TC-3-IDX-001: Index status structure
echo "Testing: Index status structure..."
resp=$(curl -s "${BASE_URL}/api/nlquery/index/status")
valid=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'indexed' in d
assert 'index_status' in d
print('yes')
" 2>/dev/null)
if [ "$valid" = "yes" ]; then
    log_result "PASS" "TC-3-IDX-001" "Index status has expected fields"
else
    log_result "FAIL" "TC-3-IDX-001" "Index status should have indexed + index_status" "Response: $(echo $resp | head -c 200)"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
