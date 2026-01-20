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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
#echo "Loaded ${#falsePositiveResponse[@]} False Positive patterns"
#echo "Loaded ${#payloads[@]} Payload patterns"

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

for url in "${urlList[@]}"; do
  [[ -z "$url" ]] && continue
  
  # Get base URL (without trailing /number)
  base_url=$(get_base_url "$url")
  #echo "DEBUG:Vulnerable:$vulnerable"
  #echo "DEBUG:BaseUrl:${vulnerable_bases[$base_url]}"
  #sleep 1
  # Skip if this base URL is already marked as vulnerable
  if [[ -n "${vulnerable_bases[$base_url]}" ]]; then
    if [[ "$verbose" == true ]]; then
      echo -e "${YELLOW}[*] Skipping $url (base URL $base_url already marked as vulnerable)${NC}" 1>&2
    fi
    continue
  fi
  
  vulnerable=false
  truePassCheck=false
  falsePassCheck=false
  SQLRiskConfidence=0

  baselineBody=$(curl_body "$url")
  echo "Starting SQL Injection checks..."
  echo -e "Target:{$GREEN}$url${NC}"
  for payload in "${payloads[@]}"; do
    attackUrl="${url}${payload}"
    attackBody=$(curl_body "$attackUrl")
    responseCode=$(curl_ResponseCode "$attackUrl")
    #echo "Debug:$attackUrl"
    #b=$(echo "$baselineBody" | grep -o '<[^>]*>'| wc -l)
   # echo "Debug:Baseline $b"
   # a=$(echo "$attackBody"   | grep -o '<[^>]*>'| wc -l)

    #If page is not found try the next $url/$payload
    if [[ $responseCode -eq 404 ]]; then
        echo -e "${RED}[$responseCode]${NC}Page not found" 
        continue
    
    elif [[ $responseCode -gt 404 && $responseCode -le 499 ]]; then
        echo -e "${RED}[$responseCode]${NC}Some type of bad request" 
      fi  

    # ----1st Initial check to confirm the url is not a false positive
    if [[ $responseCode -eq 200 ]]; then
        if echo "$attackBody" | grep -Eiq "$patterns"; then
            SQLRiskConfidence=0
            echo "[-] Skipping (false positive): $attackUrl"
            matched=$(echo "$attackBody" | grep -Eio "$patterns" | head -1)
            echo -e "${BLUE}  Reason:${NC} Contains pattern: \"$matched\""
            falsePositiveList+=("$attackUrl")
            continue
        fi
    fi
    
    #------2nd Check for Database Errors on the response
    if [[ $responseCode -ne 200 ]]; then
        if echo "$attackBody" | grep -qi "sql.*error\|syntax.*error\|mysql\|postgresql\|oracle"; then
            echo "    [!] SQL error message detected in response"
            falseCheckList+=("$attackUrl")
            falsePassCheck=true
            SQLRiskConfidence=$((SQLRiskConfidence + 25))
            echo -e "${RED}SQL Injection found ${NC} "
            echo -e "${BLUE}  Reason:${NC} Database error found on Response"
        fi
    fi
        
    #------The actual SQL Check Starts here
    if [[ $responseCode -eq 200 ]]; then
        SQLRiskConfidence=$((SQLRiskConfidence + 25))
        trueCheckList+=("$attackUrl")
        truePassCheck=true  
        
        if [[ "$attackBody" == "$baselineBody" ]]; then
            echo "Payload request matches Baseline, SQL Risk Increased"
            SQLRiskConfidence=$((SQLRiskConfidence + 50))
            vulnerable=true

        else
        if [[ $responseCode -eq 200 ]] && [[ "$attackBody" != "$baselineBody" ]]; then
        
            echo "Checking for element count changes..."
            "$SCRIPT_DIR/diff.sh" -u "$url" #|| true
            # Capture the exit code
            diff_exit_code=$?
            if [[ $diff_exit_code -eq 1 ]]; then
                # Here you can return 1 to your main function
                vulnerable=true
                SQLRiskConfidence=$((SQLRiskConfidence + 25))
                #by adding risk will make the risk confidence raise to 50, and the url base will be added to be skipped 
                break
            fi            

            #-- here
        fi 
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
    echo -e "${RED}[VULNERABLE] ⚠️ SQL INJECTION DETECTED!${NC}"
    echo "URL: $url"
    echo "Payload: $payload"
    if [[ ${#trueCheckList[@]} -gt 0 ]]; then
        echo "Payload: ${trueCheckList[0]}"
    fi
    echo "Reason: Boolean Injection detected"
    echo "SQLRisk Confidence = $SQLRiskConfidence"
  fi

done