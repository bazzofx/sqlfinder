#!/bin/bash
# SQL Hunter v1.0
#-- Version Dev 1.1
#------GLOBAL VARIABLES-------

# Source the config file
source config.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

warning="⚠️"
check="✓"

# -------------- DEFAULTS-------------
threads=20
file=""

url=""
HEADER=""
vulnerable=false
verbose=false
header=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

## --- Show Help
show_help() {
  cat << 'EOF'

Help place holder
EOF
}





# ---------------- Parse flags ----------------
while [[ $# -gt 0 ]]; do
    case $1 in
        -H|--header)
            HEADER="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            if [[ -z "$url" ]]; then
                url="$1"
            else
                echo "Error: Unknown argument: $1"
                show_help
            fi
            shift
            ;;
    esac
done


# ---------------- Curl body helper (for JavaScript check) ----------------
#-------------- Helper Functions --------------

curl_body() {
    local CURL_ARGS=()
    
    # Add header if provided
    if [[ -n "$HEADER" ]]; then
        CURL_ARGS+=(-H "$HEADER")
    fi
    
    # Make the request
    curl -s "${CURL_ARGS[@]}" "$1"
}

curl_ResponseCode(){
  curl -s -o /dev/null -w "%{http_code}" "$1"
}

#Validate input ----------------

if [[ -z "$url" ]]; then
  show_help
  exit 1
fi

echo "-------"
echo "Loaded ${#falsePositiveResponse[@]} False Positive patterns"
echo "Loaded ${#payloads[@]} Payload patterns"

# Create grep pattern from falsePositiveResponse array
patterns=$(IFS='|'; echo "${falsePositiveResponse[*]}")

# Fix variable declarations - removed syntax errors
declare -a trueCheckList
declare -a falseCheckList
declare -a falsePositiveList

#---Helper Functions
# ---------------- Function to get base URL without trailing number ----------------
get_base_url() {
  local url="$1"
  # Remove trailing /number pattern
  echo "$url" | sed -E 's|(/[0-9]+)+$||'
}

#----------- LOGIC STARTS HERE ----------

# Track vulnerable base URLs to avoid duplicate checks
declare -A vulnerable_bases=()

# Check if urlList is defined in config.sh, otherwise use single URL
if [[ -z "${urlList[@]}" ]]; then
    urlList=("$url")
fi

for each_url in "${urlList[@]}"; do
  [[ -z "$each_url" ]] && continue
  
  # Get base URL (without trailing /number)
  base_url=$(get_base_url "$each_url")
  
  # Skip if this base URL is already marked as vulnerable
  if [[ -n "${vulnerable_bases[$base_url]}" ]]; then
    if [[ "$verbose" == true ]]; then
      echo -e "${YELLOW}[*] Skipping $each_url (base URL $base_url already marked as vulnerable)${NC}" 1>&2
    fi
    continue
  fi
  
  vulnerable=false
  truePassCheck=false
  falsePassCheck=false
  SQLRiskConfidence=0

  baselineBody=$(curl_body "$each_url")
  
  for payload in "${payloads[@]}"; do
    attackUrl="${each_url}${payload}"
    responseBody=$(curl_body "$attackUrl")
    responseCode=$(curl_ResponseCode "$attackUrl")

    # ----1st Initial check to confirm the url is not a false positive
    if [[ $responseCode -eq 200 ]]; then
        if echo "$responseBody" | grep -Eiq "$patterns"; then
            SQLRiskConfidence=0
            echo "[-] Skipping (false positive): $attackUrl"
            matched=$(echo "$responseBody" | grep -Eio "$patterns" | head -1)
            echo -e "${BLUE}  Reason:${NC} Contains pattern: \"$matched\""
            falsePositiveList+=("$attackUrl")
            break
        fi
    fi
    
    #------2nd Check for Database Errors on the response
    if [[ $responseCode -ne 200 ]]; then
        if echo "$responseBody" | grep -qi "sql.*error\|syntax.*error\|mysql\|postgresql\|oracle"; then
            echo "    [!] SQL error message detected in response"
            falseCheckList+=("$attackUrl")
            falsePassCheck=true
            SQLRiskConfidence=$((SQLRiskConfidence + 25))
            echo -e "${RED}SQL Injection found ${NC} "
            echo -e "${BLUE}  Reason:${NC} Database error found on Response"
        fi
    fi
        
    #------3rd SQL Check Starts here
    if [[ $responseCode -eq 200 ]]; then
        SQLRiskConfidence=$((SQLRiskConfidence + 25))
        trueCheckList+=("$attackUrl")
        truePassCheck=true	
        
        if [[ "$responseBody" == "$baselineBody" ]]; then
            echo "Payload request matches Baseline, SQL Risk Increased"
            SQLRiskConfidence=$((SQLRiskConfidence + 50))
            vulnerable=true
        fi
    elif [[ $responseCode -gt 299 && $responseCode -lt 499 ]]; then
        falseCheckList+=("$attackUrl")
        falsePassCheck=true
        SQLRiskConfidence=$((SQLRiskConfidence + 10))
    else 
        echo "Unexpected response from the server using the below payload"
        echo "$attackUrl"
    fi

    if [[ $SQLRiskConfidence -ge 50 ]]; then
        # Mark this base URL as vulnerable to skip future variations
        vulnerable_bases["$base_url"]=1
    fi

  done

  if [[ $truePassCheck == true && $falsePassCheck == true ]]; then
    echo "SQL Injection point discovered"
    echo "URL: $each_url"
    if [[ ${#trueCheckList[@]} -gt 0 ]]; then
        echo "Payload: ${trueCheckList[0]}"
    fi
    echo "Reason: Boolean Injection detected"
    echo "SQLRisk Confidence = $SQLRiskConfidence"
  fi

done