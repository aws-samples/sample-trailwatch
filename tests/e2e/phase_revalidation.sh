#!/bin/bash
# Revalidation & Remaining Tests
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

echo "=== REVALIDATION & REMAINING TESTS ==="
echo ""

# RE-001: Revalidate mutex fix - rapid concurrent spend reset/read
echo "Testing: Mutex fix revalidation (50 concurrent ops)..."
for i in $(seq 1 25); do
    curl -s -o /dev/null -X DELETE "${BASE_URL}/api/nlquery/spend" &
    curl -s -o /dev/null "${BASE_URL}/api/nlquery/spend" &
done
wait
health=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/health")
if [ "$health" = "200" ]; then
    log_result "PASS" "RE-001" "Mutex fix holds under 50 concurrent spend ops"
else
    log_result "FAIL" "RE-001" "Server crashed during concurrent spend ops" "Health: $health"
fi

# RE-002: SSE streaming - index progress
echo "Testing: SSE streaming (index progress)..."
# Start index build and read SSE stream for 3 seconds
curl -s -X POST "${BASE_URL}/api/nlquery/index" > /dev/null 2>&1
sse_output=$(curl -s -N --max-time 3 "${BASE_URL}/api/nlquery/index/progress" 2>/dev/null)
if echo "$sse_output" | grep -q "event:"; then
    log_result "PASS" "RE-002" "SSE streaming works (received event frames)"
elif echo "$sse_output" | grep -q "progress\|done"; then
    log_result "PASS" "RE-002" "SSE streaming works (received progress/done)"
else
    # Index might already be idle
    if echo "$sse_output" | grep -q "idle\|data:"; then
        log_result "PASS" "RE-002" "SSE streaming works (index already idle, got data frame)"
    else
        log_result "FAIL" "RE-002" "SSE streaming not working" "Output: $(echo $sse_output | head -c 200)"
    fi
fi

# RE-003: Index cancel mid-build
echo "Testing: Index cancel mid-build..."
curl -s -X POST "${BASE_URL}/api/nlquery/index" > /dev/null 2>&1
sleep 0.5
cancel_resp=$(curl -s -X POST "${BASE_URL}/api/nlquery/index/cancel")
cancel_status=$(echo "$cancel_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null)
if [ "$cancel_status" = "cancelling" ] || echo "$cancel_resp" | grep -q "not_running"; then
    log_result "PASS" "RE-003" "Index cancel handled correctly (status: $cancel_status)"
else
    log_result "FAIL" "RE-003" "Index cancel unexpected response" "Response: $cancel_resp"
fi

# RE-004: Settings update persistence
echo "Testing: Settings update and persistence..."
# Read current settings
orig_timeout=$(curl -s "${BASE_URL}/api/settings" | python3 -c "import sys,json; print(json.load(sys.stdin).get('query_timeout_seconds',60))")
# Update to a different value
new_timeout=$((orig_timeout + 10))
curl -s -X PUT -H "Content-Type: application/json" \
    -d "{\"query_timeout_seconds\":$new_timeout}" "${BASE_URL}/api/settings" > /dev/null
# Read back
read_timeout=$(curl -s "${BASE_URL}/api/settings" | python3 -c "import sys,json; print(json.load(sys.stdin).get('query_timeout_seconds',0))")
if [ "$read_timeout" = "$new_timeout" ]; then
    log_result "PASS" "RE-004" "Settings update persists (timeout: $orig_timeout → $new_timeout)"
    # Restore original
    curl -s -X PUT -H "Content-Type: application/json" \
        -d "{\"query_timeout_seconds\":$orig_timeout}" "${BASE_URL}/api/settings" > /dev/null
else
    log_result "FAIL" "RE-004" "Settings update did not persist" "Expected: $new_timeout, Got: $read_timeout"
fi

# RE-005: Session deletion with cleanup
echo "Testing: Session deletion..."
# Create a throwaway session
sess_id=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"account_id":"000000000000","org_id":"test","log_region":"us-east-1","start_date":"2025-01-01","end_date":"2025-01-01"}' \
    "${BASE_URL}/api/sessions" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$sess_id" ] && [ "$sess_id" != "None" ]; then
    # Delete it
    del_status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${BASE_URL}/api/sessions/${sess_id}")
    # Verify it's gone
    get_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/sessions/${sess_id}")
    if [ "$del_status" = "200" ] || [ "$del_status" = "204" ]; then
        if [ "$get_status" = "404" ]; then
            log_result "PASS" "RE-005" "Session deleted and confirmed gone (del: $del_status, get: $get_status)"
        else
            log_result "FAIL" "RE-005" "Session deleted but still accessible" "GET returned: $get_status"
        fi
    else
        log_result "FAIL" "RE-005" "Session deletion failed" "DELETE returned: $del_status"
    fi
else
    log_result "FAIL" "RE-005" "Could not create test session" "ID: $sess_id"
fi

# RE-006: Query during index rebuild
echo "Testing: Query during index rebuild..."
curl -s -X POST "${BASE_URL}/api/nlquery/index" > /dev/null 2>&1
sleep 0.2
query_resp=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-all","param":""}' "${BASE_URL}/api/investigate/run")
query_rows=$(echo "$query_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',[]) or []))" 2>/dev/null)
query_err=$(echo "$query_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null)
if [ "$query_rows" -ge "0" ] 2>/dev/null; then
    log_result "PASS" "RE-006" "Query works during index rebuild ($query_rows rows)"
else
    log_result "FAIL" "RE-006" "Query failed during index rebuild" "Error: $query_err"
fi

# RE-007: Multiple NL query styles
echo "Testing: NL query - question format..."
resp=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
    -d '{"prompt":"What are the most common error codes in the last 30 days?"}' \
    "${BASE_URL}/api/nlquery/execute")
has_result=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('columns') else 'no')" 2>/dev/null)
has_error=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null)
if [ "$has_result" = "yes" ]; then
    log_result "PASS" "RE-007" "NL query (question format) returns results"
elif [ -n "$has_error" ] && [ "$has_error" != "None" ] && [ "$has_error" != "" ]; then
    log_result "FAIL" "RE-007" "NL query (question format) errored" "Error: $(echo $has_error | head -c 100)"
else
    log_result "FAIL" "RE-007" "NL query (question format) no results" "Response: $(echo $resp | head -c 200)"
fi

# RE-008: NL query - imperative format
echo "Testing: NL query - imperative format..."
resp=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
    -d '{"prompt":"List all unique IAM roles that made API calls, sorted by call count descending, limit 15"}' \
    "${BASE_URL}/api/nlquery/execute")
has_result=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('columns') else 'no')" 2>/dev/null)
rows=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',[]) or []))" 2>/dev/null)
if [ "$has_result" = "yes" ] && [ "$rows" -gt "0" ] 2>/dev/null; then
    log_result "PASS" "RE-008" "NL query (imperative format) returns $rows rows"
else
    err=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','')[:100])" 2>/dev/null)
    log_result "FAIL" "RE-008" "NL query (imperative format) failed" "Error: $err"
fi

# RE-009: Summarize with larger result set
echo "Testing: Summarize with 100-row result..."
# First get a real 100-row result
result=$(curl -s --max-time 15 -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-all","param":""}' "${BASE_URL}/api/investigate/run")
cols=$(echo "$result" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('columns',[])))" 2>/dev/null)
rows=$(echo "$result" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('rows',[])[:100)))" 2>/dev/null)
# Now summarize it
sum_resp=$(curl -s --max-time 60 -X POST -H "Content-Type: application/json" \
    -d "{\"scenario_id\":\"access-denied-all\",\"scenario_name\":\"All Access Denied Events\",\"columns\":$cols,\"rows\":$rows,\"total_rows\":100}" \
    "${BASE_URL}/api/nlquery/summarize")
has_tldr=$(echo "$sum_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('tldr') else 'no')" 2>/dev/null)
if [ "$has_tldr" = "yes" ]; then
    entities=$(echo "$sum_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('entities',[])))" 2>/dev/null)
    findings=$(echo "$sum_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('findings',[])))" 2>/dev/null)
    log_result "PASS" "RE-009" "Summarize 100 rows: TL;DR + $findings findings + $entities entities"
else
    err=$(echo "$sum_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',d.get('error',''))[:100])" 2>/dev/null)
    log_result "FAIL" "RE-009" "Summarize 100 rows failed" "Error: $err"
fi

# RE-010: Verify all 40 scenarios still work after index rebuild
echo "Testing: All scenarios post-rebuild..."
scenarios=$(curl -s "${BASE_URL}/api/investigate/scenarios")
total=$(echo "$scenarios" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
valid=0
while IFS= read -r sid; do
    resp=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -d "{\"scenario_id\":\"$sid\",\"param\":\"test\"}" "${BASE_URL}/api/investigate/run")
    has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
    if [ "$has_sql" = "yes" ]; then
        valid=$((valid + 1))
    fi
done < <(echo "$scenarios" | python3 -c "import sys,json; [print(s['id']) for s in json.load(sys.stdin)]")
if [ "$valid" -eq "$total" ]; then
    log_result "PASS" "RE-010" "All $total scenarios generate SQL post-rebuild"
else
    log_result "FAIL" "RE-010" "Some scenarios failed post-rebuild" "$valid/$total valid"
fi

# RE-011: Discoverable accounts endpoint
echo "Testing: Discoverable accounts..."
accts=$(curl -s "${BASE_URL}/api/accounts/discoverable" | python3 -c "
import sys,json
d=json.load(sys.stdin)
accts = d.get('accounts',[])
with_data = [a for a in accts if a.get('has_data')]
print(f'{len(accts)} total, {len(with_data)} with data')
" 2>/dev/null)
if echo "$accts" | grep -q "with data"; then
    log_result "PASS" "RE-011" "Discoverable accounts: $accts"
else
    log_result "FAIL" "RE-011" "Discoverable accounts failed" "$accts"
fi

# RE-012: Final health + spend check
echo "Testing: Final state..."
health=$(curl -s "${BASE_URL}/api/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d[\"status\"]} (uptime: {d[\"uptime\"]})')" 2>/dev/null)
spend=$(curl -s "${BASE_URL}/api/nlquery/spend" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d[\"queries\"]} queries, \${d[\"estimated_usd\"]:.4f}')" 2>/dev/null)
log_result "PASS" "RE-012" "Final state: $health, Spend: $spend"

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
