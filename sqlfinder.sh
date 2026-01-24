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
parallel_max=1  # Default sequential
original_args=("$@")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

## --- Show Help
show_help() {
  cat << 'EOF'
SQL Hunter - SQL Injection Scanner with Parallel Processing

Usage: ./sqlhunter.sh [OPTIONS] <URL>

Options:
  -H, --header <HEADER>     Add custom HTTP header
  -p, --parallel <NUM>      Maximum parallel requests (default: 1)
  -v, --verbose             Outputs a bigger commmand
  -h, --help                Show this help message

Example:
  ./sqlhunter.sh -p 20 -H "Cookie: session=abc123" https://example.com/page?id=1
EOF
}

# ---------------- Parse flags ----------------
while [[ $# -gt 0 ]]; do
    case $1 in
        -H|--header)
            HEADER="$2"
            shift 2
            ;;
        -p|--parallel)
            parallel_max="$2"
            shift 2
            ;;
        -v|--verbose)
            verbose=true
            shift 1  # Only shift 1 for flags without parameters
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            # This handles the URL argument
            if [[ -z "$url" ]]; then
                url="$1"
            else
                echo "Error: Unknown argument: $1"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# ---------------- Curl body helper ----------------
curl_body() {
    local CURL_ARGS=()
    
    if [[ -n "$HEADER" ]]; then
        CURL_ARGS+=(-H "$HEADER")
    fi
    
    curl -s "${CURL_ARGS[@]}" "$1"
}

curl_ResponseCode() {
    local CURL_ARGS=()
    
    if [[ -n "$HEADER" ]]; then
        CURL_ARGS+=(-H "$HEADER")
    fi
    
    curl -s -o /dev/null -w "%{http_code}" "${CURL_ARGS[@]}" "$1"
}

#- Collect URLs
collect_urls() {
  local url="$1"
  local KATANA_ARGS=()
  KATANA_ARGS=(-u "$url" -jsl -silent)
  [[ -n "$header" ]] && KATANA_ARGS+=(-H "$header")

  katana "${KATANA_ARGS[@]}" 2>/dev/null \
    | uro 2>/dev/null \
    | grep -Ev '\.(js|tsx|php|html|htm|json)(\?|$)' \
    | sed 's/:id//' \
    | sed  's/\\n$//' \
    | sort -u
}

add_number_variations() {
    local exceptions=("cart" "checkout" "logout" "login" "profile" "settings" "account")
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        # Check if URL already ends with a number
        if [[ "$url" =~ /[0-9]+$ ]]; then
            echo "$url"
            continue
        fi
        # Check if URL ends with any exception word
        skip=false
        for exception in "${exceptions[@]}"; do
            if [[ "$url" =~ /${exception}$ ]]; then
                echo "$url"
                skip=true
                break
            fi
        done
        [[ "$skip" == true ]] && continue
        # If not, create variations with numbers 1-3
        echo "$url"
        for i in {1..3}; do
            echo "${url}/${i}"
        done
    done
}

#---Helper Functions
get_base_url() {
  local url="$1"
  echo "$url" | sed -E 's|(/[0-9]+)+$||'
}

run_sql_logic_check() {
        if [[ $responseCode -eq 404 ]]; then
               return 0
            
            elif [[ $responseCode -gt 404 && $responseCode -le 499 ]]; then
                echo -e "${RED}[$responseCode]${NC}Some type of bad request" 
            fi

            # False positive check
            if [[ $responseCode -eq 200 ]]; then
                if echo "$attackBody" | grep -Eiq "$patterns"; then
                    SQLRiskConfidence=0
                    echo "[-] Skipping (false positive): $attackUrl"
                    matched=$(echo "$attackBody" | grep -Eio "$patterns" | head -1)
                    echo -e "${BLUE}  Reason:${NC} Contains pattern: \"$matched\""
                    falsePositiveList+=("$attackUrl")
                    return 0
                fi
            fi
            
            # SQL error check
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
            
            # SQL injection logic
            if [[ $responseCode -eq 200 ]]; then
                SQLRiskConfidence=$((SQLRiskConfidence + 25))
                trueCheckList+=("$attackUrl")
                truePassCheck=true  
                
                if [[ "$attackBody" == "$baselineBody" ]]; then
                    echo -e "$attackUrl"
                    echo "Payload request matches Baseline, SQL Risk Increased"
                    SQLRiskConfidence=$((SQLRiskConfidence + 50))
                    vulnerable=true

                elif [[ "$attackBody" != "$baselineBody" ]]; then
                    echo "Checking for element count changes..."
                    "$SCRIPT_DIR/diff.sh" -u "$url" "${original_args[@]}"
                    diff_exit_code=$?
                    if [[ $diff_exit_code -eq 0 ]]; then
                        vulnerable=true
                        SQLRiskConfidence=$((SQLRiskConfidence + 25))
                        return 99
                    fi
                fi
            elif [[ $responseCode -gt 299 && $responseCode -lt 499 ]]; then
                falseCheckList+=("$attackUrl")
                falsePassCheck=true
                SQLRiskConfidence=$((SQLRiskConfidence + 10))
            fi

            if [[ $SQLRiskConfidence -ge 50 ]]; then
                vulnerable_bases["$base_url"]=1
            fi
    }


#Validate input 
if [[ -z "$url" ]]; then
  show_help
  exit 1
fi


# Read URL list into array
echo -e "[${GREEN}+${NC}] - Collecting URLs from: $url"
IFS=$'\n' read -r -d '' -a urlList <<< "$(collect_urls "$url")"


echo "${urlList[@]}"
echo "-------------------------"


#We will add a random number to these Urls, as that is how some we can detect SQL injection on these
IFS=$'\n' noTrailUrlList=($(printf "%s\n" "${urlList[@]}"| grep -E '\.(js|tsx|php|html|htm|json)(\?|$)'))
# Expand the URLs with number variationsf=
urlsNoTrailExpanded=$(printf "%s\n" "${noTrailUrlList[@]}" | add_number_variations)
# Combine the expanded URLs back into urlList
IFS=$'\n' read -r -d '' -a urlList <<< "$(printf "%s\n" "${urlList[@]}\n${urlsNoTrailExpanded}" | sort -u)"




echo -e "[${GREEN}+${NC}] - Found ${#urlList[@]} urLs to test"
echo -e ${YELLOW}"---SQL Injection Target List---${NC}"
for p in "${urlList[@]}"; do
    echo "$p"
done
echo -e "${YELLOW}---------------------------------------${NC}"



# Create grep pattern from falsePositiveResponse array
patterns=$(IFS='|'; echo "${falsePositiveResponse[*]}")

# Fix variable declarations
declare -a trueCheckList
declare -a falseCheckList
declare -a falsePositiveList
declare -a listVulnUrls
#----------- LOGIC STARTS HERE ----------

declare -A vulnerable_bases=()
#

# Check and attempt exploit login pages..
#echo "---Login Pages found (${#loginPages[@]})---"


#Main SQL Vuln Loop Checker
for url in "${urlList[@]}"; do
  [[ -z "$url" ]] && continue
  
  base_url=$(get_base_url "$url")
  
  if [[ -n "${vulnerable_bases[$base_url]}" ]]; then
    echo -e "${YELLOW}[*] Skipping $url (base URL already marked as vulnerable)${NC}"
    continue
  fi
  
  vulnerable=false
  truePassCheck=false
  falsePassCheck=false
  SQLRiskConfidence=0

#--------------- Running Inside Loop ---------------

# Check and attempt exploit forms on the body of url
 # Fetch Original Body 
  baselineBody=$(curl_body "$url")
  if [[ $verbose == true ]]; then
  echo -e "Target:${GREEN}$url${NC}"
  echo "Starting SQL Injection checks..."
  echo "Searching for Submission forms on Url"
  fi

#Testing login pages
if [[ "$url" =~ (login|admin|dashboard|signin) ]]; then
    "$SCRIPT_DIR/sqlogin.sh" -u "$url" "${original_args[@]}"
fi

  echo "Checking forms on $url"
  if [[ $forms == true ]]; then
  "$SCRIPT_DIR/sqlFormFinder.sh" -u "$url" "${original_args[@]}"
  fi
  



  # PARALLEL PROCESSING
  if [[ $parallel_max -gt 1 ]]; then
    echo "Testing ${#payloads[@]} payloads with $parallel_max parallel workers..."
    
    # Create temp directory
    tempdir=$(mktemp -d)
    
    # Function for parallel execution
    process_payload() {
        local index="$1"
        local payload="$2"
        local url="$3"
        
        local attackUrl="${url}${payload}"
        local CURL_ARGS=()
        [[ -n "$HEADER" ]] && CURL_ARGS+=(-H "$HEADER")
        
        # Get response code
        local responseCode
        responseCode=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_ARGS[@]}" "$attackUrl" 2>/dev/null || echo "000")
        
        # Get response body
        local attackBody=""
        if [[ $responseCode -eq 200 ]] || [[ $responseCode -ne 000 ]]; then
            attackBody=$(curl -s "${CURL_ARGS[@]}" "$attackUrl" 2>/dev/null || echo "")
        fi
        
        # Save to temp files
        echo "$responseCode" > "$tempdir/code_$index"
        echo "$attackBody" > "$tempdir/body_$index"
        echo "$attackUrl" > "$tempdir/url_$index"
        if [[ $verbose == true ]]; then
            echo -e "${RED}Attacking:$attackUrl${NC}"
        fi
    }
    
    export -f process_payload
    export HEADER


    # Run in parallel
    for i in "${!payloads[@]}"; do
        echo "$i" "${payloads[$i]}" "$url"
    done | xargs -I {} -P "$parallel_max" \
        bash -c 'process_payload $1 "$2" "$3"' _ {}
    
    # Read results
    for i in "${!payloads[@]}"; do
        if [[ -f "$tempdir/code_$i" ]]; then
            responseCode=$(cat "$tempdir/code_$i")
            attackBody=$(cat "$tempdir/body_$i")
            attackUrl=$(cat "$tempdir/url_$i")
            payload="${payloads[$i]}"
      #-------------------------------------------------------------------------------------------------------------------------
            # PROCESS EACH PAYLOAD (SAME LOGIC AS SEQUENTIAL)
            run_sql_logic_check
            #Check if already vulnerable
            if [[ $? -eq 99 ]]; then
			    break
			fi
      #--------------------------------------------------------------------------------------------------------------------------      
        fi
    done
    
    # Clean up
    rm -rf "$tempdir"
    
  else
    # SEQUENTIAL PROCESSING (ORIGINAL CODE)
    for payload in "${payloads[@]}"; do
      attackUrl="${url}${payload}"
      if [[ $verbose == true ]]; then
        echo -e "${BLUE}Attacking:$attackUrl${NC}"
      fi
      attackBody=$(curl_body "$attackUrl")
      responseCode=$(curl_ResponseCode "$attackUrl")
      #-------------------------------------------------------------------------------------------------------------------------
            run_sql_logic_check
            #Check if already vulnerable
            if [[ $? -eq 99 ]]; then
			    break
			fi            
      #--------------------------------------------------------------------------------------------------------------------------
      
    done
  fi

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