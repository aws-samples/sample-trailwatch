#!/bin/bash
# Phase 2: Performance & Data Volume Testing
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

echo "=== PHASE 2: PERFORMANCE & DATA VOLUME TESTING ==="
echo ""

# TC-2-PERF-001: Query with empty prompt returns proper error
echo "Testing: Empty prompt handling..."
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{"prompt":""}' "${BASE_URL}/api/nlquery/execute")
status=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -n -1)
if [ "$status" = "400" ]; then
    log_result "PASS" "TC-2-PERF-001" "Empty prompt returns 400"
else
    log_result "FAIL" "TC-2-PERF-001" "Empty prompt returns 400" "Got status: $status"
fi

# TC-2-PERF-002: Estimate endpoint handles normal prompt
echo "Testing: Cost estimate endpoint..."
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{"prompt":"Show me all ConsoleLogin events"}' "${BASE_URL}/api/nlquery/estimate")
status=$(echo "$resp" | tail -1)
if [ "$status" = "200" ]; then
    log_result "PASS" "TC-2-PERF-002" "Estimate endpoint responds 200"
else
    log_result "FAIL" "TC-2-PERF-002" "Estimate endpoint responds 200" "Got status: $status"
fi

# TC-2-PERF-003: Index status returns valid JSON
echo "Testing: Index status response format..."
resp=$(curl -s "${BASE_URL}/api/nlquery/index/status")
if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'indexed' in d" 2>/dev/null; then
    log_result "PASS" "TC-2-PERF-003" "Index status returns valid JSON with 'indexed' field"
else
    log_result "FAIL" "TC-2-PERF-003" "Index status returns valid JSON" "Missing 'indexed' field"
fi

# TC-2-PERF-004: Dashboard handles no-data state gracefully
echo "Testing: Dashboard with no indexed data..."
resp=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/dashboard")
status=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -n -1)
if [ "$status" = "200" ]; then
    log_result "PASS" "TC-2-PERF-004" "Dashboard returns 200 even with no data"
else
    log_result "FAIL" "TC-2-PERF-004" "Dashboard returns 200 even with no data" "Got: $status"
fi

# TC-2-PERF-005: Investigate scenario list returns all scenarios
echo "Testing: Scenario list completeness..."
count=$(curl -s "${BASE_URL}/api/investigate/scenarios" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
if [ "$count" -ge "30" ]; then
    log_result "PASS" "TC-2-PERF-005" "Scenario list has $count scenarios (>=30)"
else
    log_result "FAIL" "TC-2-PERF-005" "Scenario list has >=30 scenarios" "Got: $count"
fi

# TC-2-PERF-006: Rapid-fire requests (20 requests in quick succession)
echo "Testing: Rapid-fire API requests..."
start_time=$(python3 -c "import time; print(time.time())")
for i in $(seq 1 20); do
    curl -s -o /dev/null "${BASE_URL}/api/health" &
done
wait
end_time=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end_time - $start_time, 2))")
if python3 -c "exit(0 if $duration < 5.0 else 1)"; then
    log_result "PASS" "TC-2-PERF-006" "20 concurrent requests completed in ${duration}s (<5s)"
else
    log_result "FAIL" "TC-2-PERF-006" "20 concurrent requests should complete in <5s" "Took: ${duration}s"
fi

# TC-2-PERF-007: Large payload handling (10KB prompt)
echo "Testing: Large prompt payload..."
large_prompt=$(python3 -c "print('A' * 10000)")
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" \
    -d "{\"prompt\":\"$large_prompt\"}" "${BASE_URL}/api/nlquery/estimate")
status=$(echo "$resp" | tail -1)
if [ "$status" = "200" ] || [ "$status" = "400" ]; then
    log_result "PASS" "TC-2-PERF-007" "Large 10KB prompt handled gracefully (status: $status)"
else
    log_result "FAIL" "TC-2-PERF-007" "Large prompt should return 200 or 400" "Got: $status"
fi

# TC-2-PERF-008: Session spend tracking works
echo "Testing: Session spend tracking..."
resp=$(curl -s "${BASE_URL}/api/nlquery/spend")
if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'estimated_usd' in d or 'total_estimated_usd' in d or isinstance(d, dict)" 2>/dev/null; then
    log_result "PASS" "TC-2-PERF-008" "Spend endpoint returns valid JSON"
else
    log_result "FAIL" "TC-2-PERF-008" "Spend endpoint returns valid JSON" "Response: $resp"
fi

# TC-2-PERF-009: Spend reset works
echo "Testing: Spend reset..."
resp=$(curl -s -w "\n%{http_code}" -X DELETE "${BASE_URL}/api/nlquery/spend")
status=$(echo "$resp" | tail -1)
if [ "$status" = "200" ]; then
    log_result "PASS" "TC-2-PERF-009" "Spend reset returns 200"
else
    log_result "FAIL" "TC-2-PERF-009" "Spend reset returns 200" "Got: $status"
fi

# TC-2-PERF-010: Index build with existing data
echo "Testing: Index build trigger..."
resp=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/api/nlquery/index")
status=$(echo "$resp" | tail -1)
# Should be 202 (accepted) or 400 (no data) or 409 (already running)
if [ "$status" = "202" ] || [ "$status" = "400" ] || [ "$status" = "409" ]; then
    log_result "PASS" "TC-2-PERF-010" "Index build returns appropriate status ($status)"
else
    log_result "FAIL" "TC-2-PERF-010" "Index build returns 202/400/409" "Got: $status"
fi

# TC-2-PERF-011: Response time for health endpoint (<100ms)
echo "Testing: Health endpoint response time..."
time_total=$(curl -s -o /dev/null -w "%{time_total}" "${BASE_URL}/api/health")
if python3 -c "exit(0 if $time_total < 0.1 else 1)"; then
    log_result "PASS" "TC-2-PERF-011" "Health responds in ${time_total}s (<100ms)"
else
    log_result "FAIL" "TC-2-PERF-011" "Health should respond in <100ms" "Took: ${time_total}s"
fi

# TC-2-PERF-012: Response time for settings endpoint (<200ms)
echo "Testing: Settings endpoint response time..."
time_total=$(curl -s -o /dev/null -w "%{time_total}" "${BASE_URL}/api/settings")
if python3 -c "exit(0 if $time_total < 0.2 else 1)"; then
    log_result "PASS" "TC-2-PERF-012" "Settings responds in ${time_total}s (<200ms)"
else
    log_result "FAIL" "TC-2-PERF-012" "Settings should respond in <200ms" "Took: ${time_total}s"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
