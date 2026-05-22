#!/bin/bash
# Phase 0: Codebase Discovery - Validate API endpoints exist and respond
BASE_URL="http://localhost:7070"
PASS=0
FAIL=0
RESULTS=""

test_endpoint() {
    local method=$1
    local path=$2
    local expected_status=$3
    local description=$4
    local body=$5
    
    if [ "$method" = "GET" ]; then
        actual_status=$(curl -s -o /tmp/e2e_response.json -w "%{http_code}" "${BASE_URL}${path}")
    else
        actual_status=$(curl -s -o /tmp/e2e_response.json -w "%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$body" "${BASE_URL}${path}")
    fi
    
    if [ "$actual_status" = "$expected_status" ]; then
        PASS=$((PASS + 1))
        RESULTS="${RESULTS}PASS | ${method} ${path} | ${description}\n"
    else
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}FAIL | ${method} ${path} | ${description} | Expected: ${expected_status}, Got: ${actual_status}\n"
    fi
}

echo "=== PHASE 0: API ENDPOINT DISCOVERY ==="
echo ""

# Health
test_endpoint "GET" "/api/health" "200" "Health endpoint"

# Settings
test_endpoint "GET" "/api/settings" "200" "Get settings"

# Sessions
test_endpoint "GET" "/api/sessions" "200" "List sessions"

# Prompts
test_endpoint "GET" "/api/prompts" "200" "List prompts"

# NL Query endpoints
test_endpoint "GET" "/api/nlquery/index/status" "200" "Index status"
test_endpoint "GET" "/api/nlquery/spend" "200" "Session spend"

# Dashboard
test_endpoint "GET" "/api/dashboard" "200" "Dashboard data"
test_endpoint "GET" "/api/dashboard/findings" "200" "Dashboard findings"

# Lookups
test_endpoint "GET" "/api/lookups" "200" "Lookups"

# Investigate
test_endpoint "GET" "/api/investigate/scenarios" "200" "Investigation scenarios"

# Accounts
test_endpoint "GET" "/api/accounts/status" "200" "Account status"

# Unknown API path returns 404 JSON
test_endpoint "GET" "/api/nonexistent" "404" "Unknown API path returns 404"

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
