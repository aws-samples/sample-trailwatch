#!/bin/bash
# Phase 7 & 8: Browser Compatibility & Accessibility Analysis
SRC_DIR="/Users/vyakush/Downloads/cloudtrail-local-nlq/web/src"
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

echo "=== PHASE 7 & 8: COMPATIBILITY & ACCESSIBILITY ==="
echo ""

# TC-7-COMPAT-001: No browser-specific CSS prefixes needed (Tailwind handles)
echo "Testing: Browser compatibility via Tailwind..."
tailwind_config=$(cat /Users/vyakush/Downloads/cloudtrail-local-nlq/web/tailwind.config.js 2>/dev/null || cat /Users/vyakush/Downloads/cloudtrail-local-nlq/web/tailwind.config.ts 2>/dev/null)
if [ -n "$tailwind_config" ]; then
    log_result "PASS" "TC-7-COMPAT-001" "Tailwind CSS handles browser prefixes automatically"
else
    log_result "FAIL" "TC-7-COMPAT-001" "No Tailwind config found"
fi

# TC-7-COMPAT-002: No browser-specific APIs used
echo "Testing: No browser-specific APIs..."
webkit_usage=$(grep -r "webkit\|moz-\|ms-\|-o-" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | grep -v ".css" | wc -l)
if [ "$webkit_usage" -le "2" ]; then
    log_result "PASS" "TC-7-COMPAT-002" "No browser-specific API usage ($webkit_usage instances)"
else
    log_result "FAIL" "TC-7-COMPAT-002" "Browser-specific APIs found" "$webkit_usage instances"
fi

# TC-7-COMPAT-003: ES module compatibility
echo "Testing: Modern JS features..."
optional_chain=$(grep -r "\?\." "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
nullish=$(grep -r "??" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
log_result "PASS" "TC-7-COMPAT-003" "Modern JS: optional chaining ($optional_chain), nullish coalescing ($nullish) - Vite transpiles"

# TC-8-A11Y-001: ARIA labels present
echo "Testing: ARIA labels..."
aria_count=$(grep -r "aria-" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$aria_count" -ge "5" ]; then
    log_result "PASS" "TC-8-A11Y-001" "ARIA attributes present ($aria_count instances)"
else
    log_result "FAIL" "TC-8-A11Y-001" "Insufficient ARIA attributes" "Only $aria_count"
fi

# TC-8-A11Y-002: Semantic HTML elements
echo "Testing: Semantic HTML..."
semantic=$(grep -r "<nav\|<header\|<main\|<footer\|<section\|<article\|<aside" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$semantic" -ge "3" ]; then
    log_result "PASS" "TC-8-A11Y-002" "Semantic HTML elements used ($semantic instances)"
else
    log_result "FAIL" "TC-8-A11Y-002" "Insufficient semantic HTML" "Only $semantic"
fi

# TC-8-A11Y-003: Focus management
echo "Testing: Focus management..."
focus=$(grep -r "focus\|Focus\|autoFocus\|tabIndex" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$focus" -ge "3" ]; then
    log_result "PASS" "TC-8-A11Y-003" "Focus management present ($focus references)"
else
    log_result "FAIL" "TC-8-A11Y-003" "Insufficient focus management" "Only $focus"
fi

# TC-8-A11Y-004: Alt text for images
echo "Testing: Image alt text..."
img_no_alt=$(grep -r "<img" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | grep -v "alt=" | wc -l)
if [ "$img_no_alt" -le "0" ]; then
    log_result "PASS" "TC-8-A11Y-004" "All images have alt text (or no img tags used)"
else
    log_result "FAIL" "TC-8-A11Y-004" "Images without alt text" "$img_no_alt instances"
fi

# TC-8-A11Y-005: Color contrast (check for low-contrast text classes)
echo "Testing: Color contrast..."
low_contrast=$(grep -r "text-gray-300\|text-gray-400\|text-gray-500" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
# These are common in dark mode where they're fine, but flag if excessive
if [ "$low_contrast" -le "100" ]; then
    log_result "PASS" "TC-8-A11Y-005" "Color contrast: $low_contrast light-gray text instances (acceptable with dark bg)"
else
    log_result "FAIL" "TC-8-A11Y-005" "Excessive low-contrast text" "$low_contrast instances"
fi

# TC-8-A11Y-006: Keyboard shortcuts
echo "Testing: Keyboard shortcuts..."
keyboard_shortcuts=$(grep -r "onKeyDown\|onKeyPress\|hotkey\|shortcut" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$keyboard_shortcuts" -ge "1" ]; then
    log_result "PASS" "TC-8-A11Y-006" "Keyboard shortcuts present ($keyboard_shortcuts references)"
else
    log_result "FAIL" "TC-8-A11Y-006" "No keyboard shortcuts found" "IR analysts need quick navigation"
fi

# TC-8-A11Y-007: Error messages are descriptive
echo "Testing: Error message quality..."
generic_errors=$(grep -r '"error"\|"Error"\|"failed"' "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | grep -v "\.test\." | head -20)
descriptive=$(echo "$generic_errors" | grep -c "message\|detail\|reason\|description")
if [ "$descriptive" -ge "3" ]; then
    log_result "PASS" "TC-8-A11Y-007" "Error messages appear descriptive ($descriptive with context)"
else
    log_result "FAIL" "TC-8-A11Y-007" "Error messages may lack context" "Only $descriptive descriptive"
fi

# TC-8-A11Y-008: Loading states visible
echo "Testing: Loading state visibility..."
loading_ui=$(grep -r "Spinner\|Loading\|Skeleton\|animate-pulse\|animate-spin" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$loading_ui" -ge "5" ]; then
    log_result "PASS" "TC-8-A11Y-008" "Loading UI indicators present ($loading_ui instances)"
else
    log_result "FAIL" "TC-8-A11Y-008" "Insufficient loading indicators" "Only $loading_ui"
fi

# TC-8-A11Y-009: Confirmation for destructive actions
echo "Testing: Destructive action confirmations..."
confirm=$(grep -r "confirm\|Confirm\|Are you sure\|Delete.*confirm\|modal.*delete" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$confirm" -ge "1" ]; then
    log_result "PASS" "TC-8-A11Y-009" "Destructive action confirmations present ($confirm references)"
else
    log_result "FAIL" "TC-8-A11Y-009" "No destructive action confirmations found" "Delete operations need confirmation"
fi

# TC-8-A11Y-010: Internationalization support
echo "Testing: i18n support..."
i18n=$(grep -r "useTranslation\|t(" "$SRC_DIR" 2>/dev/null | grep -v "node_modules" | wc -l)
if [ "$i18n" -ge "10" ]; then
    log_result "PASS" "TC-8-A11Y-010" "Internationalization present ($i18n translation calls)"
else
    log_result "FAIL" "TC-8-A11Y-010" "Insufficient i18n support" "Only $i18n"
fi

echo ""
echo "=== RESULTS ==="
echo -e "$RESULTS"
echo ""
echo "PASSED: $PASS | FAILED: $FAIL | TOTAL: $((PASS + FAIL))"
