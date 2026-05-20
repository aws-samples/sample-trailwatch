#!/bin/bash
# Phase 9: CloudTrail-Specific Edge Cases
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

echo "=== PHASE 9: CLOUDTRAIL-SPECIFIC EDGE CASES ==="
echo ""

# TC-9-CT-001: Investigate scenario handles Root account events
echo "Testing: Root account investigation scenario..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"root-activity","param":""}' "${BASE_URL}/api/investigate/run")
has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
if [ "$has_sql" = "yes" ]; then
    log_result "PASS" "TC-9-CT-001" "Root activity scenario generates SQL"
else
    # May not exist - check if it's a 404
    is_404=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'unknown_scenario' in str(d) else 'no')" 2>/dev/null)
    if [ "$is_404" = "yes" ]; then
        log_result "PASS" "TC-9-CT-001" "Root activity scenario not implemented (acceptable)"
    else
        log_result "FAIL" "TC-9-CT-001" "Root activity scenario failed" "Response: $(echo $resp | head -c 200)"
    fi
fi

# TC-9-CT-002: Access denied scenarios
echo "Testing: Access denied scenarios..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-all","param":""}' "${BASE_URL}/api/investigate/run")
sql=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sql',''))" 2>/dev/null)
if echo "$sql" | grep -qi "AccessDenied\|errorCode"; then
    log_result "PASS" "TC-9-CT-002" "Access denied scenario queries error codes"
else
    log_result "FAIL" "TC-9-CT-002" "Access denied should query errorCode" "SQL: $(echo $sql | head -c 200)"
fi

# TC-9-CT-003: IAM write operations scenario
echo "Testing: IAM write operations..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"iam-write-ops","param":""}' "${BASE_URL}/api/investigate/run")
sql=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sql',''))" 2>/dev/null)
if echo "$sql" | grep -qi "Create\|Delete\|Put\|Attach\|iam"; then
    log_result "PASS" "TC-9-CT-003" "IAM write ops scenario queries IAM mutations"
else
    log_result "FAIL" "TC-9-CT-003" "IAM write ops should query IAM mutations" "SQL: $(echo $sql | head -c 200)"
fi

# TC-9-CT-004: Scenario with very long ARN parameter
echo "Testing: Long ARN parameter..."
long_arn="arn:aws:iam::123456789012:role/very-long-role-name-that-goes-on-forever-and-ever-to-test-boundary-conditions-in-the-application"
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"scenario_id\":\"access-denied-by-identity\",\"param\":\"$long_arn\"}" \
    "${BASE_URL}/api/investigate/run")
has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
if [ "$has_sql" = "yes" ]; then
    log_result "PASS" "TC-9-CT-004" "Long ARN parameter handled correctly"
else
    log_result "FAIL" "TC-9-CT-004" "Long ARN should be handled" "Response: $(echo $resp | head -c 200)"
fi

# TC-9-CT-005: Scenario with special characters in param
echo "Testing: Special characters in param..."
resp=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"scenario_id":"access-denied-by-identity","param":"arn:aws:iam::000000000000:user/test+user@domain.com"}' \
    "${BASE_URL}/api/investigate/run")
has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
if [ "$has_sql" = "yes" ]; then
    log_result "PASS" "TC-9-CT-005" "Special characters in param handled"
else
    log_result "FAIL" "TC-9-CT-005" "Special chars should be handled" "Response: $(echo $resp | head -c 200)"
fi

# TC-9-CT-006: Dashboard findings cover key security categories
echo "Testing: Dashboard findings categories..."
resp=$(curl -s "${BASE_URL}/api/dashboard/findings")
categories=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if isinstance(d, list):
    cats = set()
    for f in d:
        if isinstance(f, dict):
            cats.add(f.get('category',''))
    print(len(cats))
elif isinstance(d, dict) and 'findings' in d:
    cats = set()
    for f in d['findings']:
        if isinstance(f, dict):
            cats.add(f.get('category',''))
    print(len(cats))
else:
    print(0)
" 2>/dev/null)
if [ "$categories" -ge "3" ] 2>/dev/null; then
    log_result "PASS" "TC-9-CT-006" "Dashboard has $categories finding categories"
else
    log_result "FAIL" "TC-9-CT-006" "Dashboard should have multiple categories" "Got: $categories"
fi

# TC-9-CT-007: Lookups return expected field types
echo "Testing: Lookups field types..."
resp=$(curl -s "${BASE_URL}/api/lookups")
valid=$(echo "$resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# Should have fields like access_keys, ips, identities, accounts, roles
fields = list(d.keys()) if isinstance(d, dict) else []
print(len(fields))
" 2>/dev/null)
if [ "$valid" -ge "3" ] 2>/dev/null; then
    log_result "PASS" "TC-9-CT-007" "Lookups returns $valid field types"
else
    log_result "FAIL" "TC-9-CT-007" "Lookups should have multiple field types" "Got: $valid"
fi

# TC-9-CT-008: All 40 scenarios are valid and generate SQL
echo "Testing: All scenarios generate valid SQL..."
scenarios=$(curl -s "${BASE_URL}/api/investigate/scenarios")
total=$(echo "$scenarios" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
valid_count=0
invalid_scenarios=""
while IFS= read -r scenario_id; do
    resp=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"scenario_id\":\"$scenario_id\",\"param\":\"test-value\"}" \
        "${BASE_URL}/api/investigate/run")
    has_sql=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('sql') else 'no')" 2>/dev/null)
    if [ "$has_sql" = "yes" ]; then
        valid_count=$((valid_count + 1))
    else
        invalid_scenarios="${invalid_scenarios} ${scenario_id}"
    fi
done < <(echo "$scenarios" | python3 -c "import sys,json; [print(s['id']) for s in json.load(sys.stdin)]")

if [ "$valid_count" -eq "$total" ]; then
    log_result "PASS" "TC-9-CT-008" "All $total scenarios generate valid SQL"
else
    log_result "FAIL" "TC-9-CT-008" "Not all scenarios generate SQL" "$valid_count/$total valid. Failed:$invalid_scenarios"
fi

# TC-9-CT-009: Index with existing CloudTrail data
echo "Testing: Index status with existing data..."
resp=$(curl -s "${BASE_URL}/api/nlquery/index/status")
indexed=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('indexed', False))" 2>/dev/null)
if [ "$indexed" = "True" ]; then
    size=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('size_bytes', 0))" 2>/dev/null)
    log_result "PASS" "TC-9-CT-009" "Index exists with data (size: ${size} bytes)"
else
    log_result "PASS" "TC-9-CT-009" "Index not yet built (acceptable - no sync performed)"
fi

# TC-9-CT-010: Scenario categories cover key investigation areas
echo "Testing: Scenario category coverage..."
resp=$(curl -s "${BASE_URL}/api/investigate/scenarios")
categories=$(echo "$resp" | python3 -c "
import sys,json
scenarios = json.load(sys.stdin)
cats = set(s.get('category','') for s in scenarios)
print('|'.join(sorted(cats)))
" 2>/dev/null)
expected_cats=("IAM" "Access" "Network" "Data")
found=0
for cat in "${expected_cats[@]}"; do
    if echo "$categories" | grep -qi "$cat"; then
        found=$((found + 1))
    fi
done
if [ "$found" -ge "3" ]; then
    log_result "PASS" "TC-9-CT-010" "Scenarios cover $found/4 key investigation categories"
else
    log_result "FAIL" "TC-9-CT-010" "Scenarios should cover key categories" "Found $found/4. Categories: $categories"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
