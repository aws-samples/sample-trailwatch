#!/bin/bash
# Phase 2b: Data Volume Testing with Real Indexed Data
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

echo "=== PHASE 2b: DATA QUERY PERFORMANCE (Real Data) ==="
echo ""

# TC-2b-001: Run iam-write-ops against real data - measure time
echo "Testing: IAM write ops query performance..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":""}' "${BASE_URL}/api/investigate/run")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
row_count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',[])) if d.get('rows') else 0)" 2>/dev/null)
error=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null)
if [ -n "$error" ] && [ "$error" != "None" ] && [ "$error" != "" ]; then
    log_result "FAIL" "TC-2b-001" "IAM write ops query failed" "Error: $error (${duration}s)"
elif python3 -c "exit(0 if $duration < 15 else 1)"; then
    log_result "PASS" "TC-2b-001" "IAM write ops: $row_count rows in ${duration}s"
else
    log_result "FAIL" "TC-2b-001" "IAM write ops too slow" "${duration}s for $row_count rows"
fi

# TC-2b-002: Access denied query
echo "Testing: Access denied query performance..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-all","param":""}' "${BASE_URL}/api/investigate/run")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
row_count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',[])) if d.get('rows') else 0)" 2>/dev/null)
error=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null)
if [ -n "$error" ] && [ "$error" != "None" ] && [ "$error" != "" ]; then
    log_result "FAIL" "TC-2b-002" "Access denied query failed" "Error: $error (${duration}s)"
elif python3 -c "exit(0 if $duration < 15 else 1)"; then
    log_result "PASS" "TC-2b-002" "Access denied: $row_count rows in ${duration}s"
else
    log_result "FAIL" "TC-2b-002" "Access denied too slow" "${duration}s for $row_count rows"
fi

# TC-2b-003: Dashboard performance with real data
echo "Testing: Dashboard performance..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 "${BASE_URL}/api/dashboard")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
if python3 -c "exit(0 if $duration < 5 else 1)"; then
    log_result "PASS" "TC-2b-003" "Dashboard loads in ${duration}s (<5s)"
else
    log_result "FAIL" "TC-2b-003" "Dashboard too slow" "${duration}s"
fi

# TC-2b-004: Dashboard findings performance
echo "Testing: Dashboard findings performance..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 "${BASE_URL}/api/dashboard/findings")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
finding_count=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if isinstance(d, list):
    print(len(d))
elif isinstance(d, dict) and 'findings' in d:
    print(len(d['findings']))
else:
    print(0)
" 2>/dev/null)
if python3 -c "exit(0 if $duration < 5 else 1)"; then
    log_result "PASS" "TC-2b-004" "Findings: $finding_count findings in ${duration}s"
else
    log_result "FAIL" "TC-2b-004" "Findings too slow" "${duration}s for $finding_count findings"
fi

# TC-2b-005: Lookups performance (auto-populate dropdowns)
echo "Testing: Lookups performance..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 "${BASE_URL}/api/lookups")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
if python3 -c "exit(0 if $duration < 5 else 1)"; then
    log_result "PASS" "TC-2b-005" "Lookups loads in ${duration}s (<5s)"
else
    log_result "FAIL" "TC-2b-005" "Lookups too slow" "${duration}s"
fi

# TC-2b-006: Concurrent scenario queries
echo "Testing: Concurrent scenario queries..."
start=$(python3 -c "import time; print(time.time())")
curl -s --max-time 30 -o /dev/null -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":""}' "${BASE_URL}/api/investigate/run" &
curl -s --max-time 30 -o /dev/null -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-all","param":""}' "${BASE_URL}/api/investigate/run" &
curl -s --max-time 30 -o /dev/null -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-users-created","param":""}' "${BASE_URL}/api/investigate/run" &
wait
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
# Verify server still alive
health=$(curl -s -w "%{http_code}" "${BASE_URL}/api/health")
if echo "$health" | grep -q "200"; then
    log_result "PASS" "TC-2b-006" "3 concurrent queries completed in ${duration}s, server healthy"
else
    log_result "FAIL" "TC-2b-006" "Server crashed during concurrent queries"
fi

# TC-2b-007: Query with time filter on real data
echo "Testing: Time-filtered query..."
start=$(python3 -c "import time; print(time.time())")
resp=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":"","filters":{"time_start":"2025-08-01","time_end":"2025-08-05"}}' \
    "${BASE_URL}/api/investigate/run")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
row_count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',[])) if d.get('rows') else 0)" 2>/dev/null)
if python3 -c "exit(0 if $duration < 15 else 1)"; then
    log_result "PASS" "TC-2b-007" "Time-filtered query: $row_count rows in ${duration}s"
else
    log_result "FAIL" "TC-2b-007" "Time-filtered query too slow" "${duration}s"
fi

# TC-2b-008: Index size check
echo "Testing: Index size..."
resp=$(curl -s "${BASE_URL}/api/nlquery/index/status")
size_bytes=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('size_bytes', 0))" 2>/dev/null)
size_mb=$(python3 -c "print(round($size_bytes / 1024 / 1024, 1))")
total_files=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_files_indexed', 0))" 2>/dev/null)
log_result "PASS" "TC-2b-008" "Index: ${size_mb}MB, ${total_files} files indexed"

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
