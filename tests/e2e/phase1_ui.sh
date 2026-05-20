#!/bin/bash
# Phase 1: UI/UX Testing - HTML/CSS analysis of the frontend
FRONTEND_URL="http://localhost:5173"
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

echo "=== PHASE 1: UI/UX TESTING (Static Analysis) ==="
echo ""

# TC-1-UI-001: Frontend loads successfully
echo "Testing: Frontend loads..."
resp=$(curl -s -w "\n%{http_code}" "${FRONTEND_URL}/")
status=$(echo "$resp" | tail -1)
if [ "$status" = "200" ]; then
    log_result "PASS" "TC-1-UI-001" "Frontend loads successfully (200)"
else
    log_result "FAIL" "TC-1-UI-001" "Frontend should load" "Got: $status"
fi

# TC-1-UI-002: HTML contains root div for React
echo "Testing: HTML has React root..."
html=$(curl -s "${FRONTEND_URL}/")
if echo "$html" | grep -q 'id="root"'; then
    log_result "PASS" "TC-1-UI-002" "HTML contains React root div"
else
    log_result "FAIL" "TC-1-UI-002" "HTML should have id=root" "Not found"
fi

# TC-1-UI-003: CSS bundle loads
echo "Testing: CSS bundle loads..."
css_path=$(echo "$html" | grep -o 'href="/assets/[^"]*\.css"' | head -1 | sed 's/href="//;s/"//')
if [ -n "$css_path" ]; then
    css_status=$(curl -s -o /dev/null -w "%{http_code}" "${FRONTEND_URL}${css_path}")
    if [ "$css_status" = "200" ]; then
        log_result "PASS" "TC-1-UI-003" "CSS bundle loads (${css_path})"
    else
        log_result "FAIL" "TC-1-UI-003" "CSS bundle should load" "Status: $css_status"
    fi
else
    log_result "FAIL" "TC-1-UI-003" "CSS bundle path not found in HTML"
fi

# TC-1-UI-004: JS bundle loads
echo "Testing: JS bundle loads..."
js_path=$(echo "$html" | grep -o 'src="/assets/[^"]*\.js"' | head -1 | sed 's/src="//;s/"//')
if [ -n "$js_path" ]; then
    js_status=$(curl -s -o /dev/null -w "%{http_code}" "${FRONTEND_URL}${js_path}")
    if [ "$js_status" = "200" ]; then
        log_result "PASS" "TC-1-UI-004" "JS bundle loads (${js_path})"
    else
        log_result "FAIL" "TC-1-UI-004" "JS bundle should load" "Status: $js_status"
    fi
else
    log_result "FAIL" "TC-1-UI-004" "JS bundle path not found in HTML"
fi

echo ""
echo "--- Static CSS/Tailwind Analysis ---"
echo ""

# Analyze the source code for UI issues
SRC_DIR="/Users/vyakush/Downloads/cloudtrail-local-nlq/web/src"

# TC-1-VIS-001: Check for minimum font sizes (text smaller than 10px is problematic)
echo "Testing: Font size minimums..."
tiny_fonts=$(grep -r "text-\[[0-9]px\]" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | grep -oP "text-\[\d+px\]" | sort -u)
has_tiny=$(echo "$tiny_fonts" | grep -E "text-\[[0-9]px\]" | head -5)
if [ -n "$has_tiny" ]; then
    log_result "FAIL" "TC-1-VIS-001" "Found very small font sizes" "$has_tiny"
else
    log_result "PASS" "TC-1-VIS-001" "No dangerously small custom font sizes found"
fi

# TC-1-VIS-002: Check for monospace on log/code content
echo "Testing: Monospace usage for technical content..."
mono_usage=$(grep -r "font-mono" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$mono_usage" -ge "3" ]; then
    log_result "PASS" "TC-1-VIS-002" "Monospace font used in $mono_usage places"
else
    log_result "FAIL" "TC-1-VIS-002" "Monospace should be used for technical content" "Only $mono_usage uses"
fi

# TC-1-VIS-003: Check for overflow handling
echo "Testing: Overflow handling..."
overflow_usage=$(grep -r "overflow\|truncate\|text-ellipsis" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$overflow_usage" -ge "5" ]; then
    log_result "PASS" "TC-1-VIS-003" "Overflow handling present ($overflow_usage instances)"
else
    log_result "FAIL" "TC-1-VIS-003" "Insufficient overflow handling" "Only $overflow_usage instances"
fi

# TC-1-VIS-004: Check for dark mode support
echo "Testing: Dark mode support..."
dark_classes=$(grep -r "dark:" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$dark_classes" -ge "20" ]; then
    log_result "PASS" "TC-1-VIS-004" "Dark mode support present ($dark_classes dark: classes)"
else
    log_result "FAIL" "TC-1-VIS-004" "Insufficient dark mode support" "Only $dark_classes dark: classes"
fi

# TC-1-VIS-005: Check for loading states
echo "Testing: Loading state indicators..."
loading_indicators=$(grep -r "loading\|spinner\|Spinner\|Loading\|isLoading" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$loading_indicators" -ge "5" ]; then
    log_result "PASS" "TC-1-VIS-005" "Loading indicators present ($loading_indicators references)"
else
    log_result "FAIL" "TC-1-VIS-005" "Insufficient loading indicators" "Only $loading_indicators"
fi

# TC-1-VIS-006: Check for error state handling
echo "Testing: Error state handling..."
error_handling=$(grep -r "error\|Error\|err\b" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | grep -v "\.test\." | wc -l)
if [ "$error_handling" -ge "20" ]; then
    log_result "PASS" "TC-1-VIS-006" "Error handling present ($error_handling references)"
else
    log_result "FAIL" "TC-1-VIS-006" "Insufficient error handling" "Only $error_handling"
fi

# TC-1-VIS-007: Check for responsive design (flex/grid usage)
echo "Testing: Responsive layout..."
responsive=$(grep -r "flex\|grid\|responsive\|sm:\|md:\|lg:" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$responsive" -ge "50" ]; then
    log_result "PASS" "TC-1-VIS-007" "Responsive layout present ($responsive flex/grid uses)"
else
    log_result "FAIL" "TC-1-VIS-007" "Insufficient responsive design" "Only $responsive"
fi

# TC-1-VIS-008: Check for accessible button sizes (min 44px)
echo "Testing: Button sizing..."
small_buttons=$(grep -r "p-1\b\|px-1\b\|py-0\b\|h-4\b\|w-4\b" "$SRC_DIR" 2>/dev/null | grep -i "button\|btn\|click" | grep -v "node_modules" | wc -l)
if [ "$small_buttons" -le "5" ]; then
    log_result "PASS" "TC-1-VIS-008" "Most buttons appear adequately sized"
else
    log_result "FAIL" "TC-1-VIS-008" "Found $small_buttons potentially small click targets"
fi

# TC-1-VIS-009: Check for color-only indicators (accessibility)
echo "Testing: Non-color indicators..."
icon_usage=$(grep -r "lucide-react\|Icon\|icon" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$icon_usage" -ge "10" ]; then
    log_result "PASS" "TC-1-VIS-009" "Icons used alongside colors ($icon_usage icon references)"
else
    log_result "FAIL" "TC-1-VIS-009" "Insufficient non-color indicators" "Only $icon_usage"
fi

# TC-1-VIS-010: Check for keyboard accessibility
echo "Testing: Keyboard accessibility..."
keyboard=$(grep -r "onKeyDown\|onKeyPress\|tabIndex\|aria-\|role=" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$keyboard" -ge "3" ]; then
    log_result "PASS" "TC-1-VIS-010" "Keyboard/ARIA support present ($keyboard references)"
else
    log_result "FAIL" "TC-1-VIS-010" "Insufficient keyboard accessibility" "Only $keyboard"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
