check_pattern_changes() {
    local baseline="$1"
    local attackBody="$2"
    
    # Common patterns to check
    patterns=("product" "item" "row" "record" "entry" "<div>" "<tr>" "<li>" "<img " "href=" "<pre>")
    
    for pattern in "${patterns[@]}"; do
        b_count=$(echo "$baseline" | grep -c "$pattern")
        a_count=$(echo "$attackBody" | grep -c "$pattern")
        
        if [[ $b_count -ne $a_count ]]; then
            change=$(( a_count - b_count ))
            echo "$pattern: $b_count → $a_count (+$change)"
        fi
    done
}

# Simple check for vulnerability based on pattern changes
check_vulnerable() {
    local baseline="$1"
    local attackBody="$2"
    
    baseline_total=$(echo "$baseline" | grep -o '<[^>]*>' | wc -l)
    attack_total=$(echo "$attackBody" | grep -o '<[^>]*>' | wc -l)
    
    if [[ $baseline_total -gt 0 ]] && [[ $attack_total -gt $baseline_total ]]; then
        increase=$(( (attack_total - baseline_total) * 100 / baseline_total ))
        if [[ $increase -ge 2 ]]; then
            return 0  # Vulnerable
        fi
    fi
    return 1  # Not vulnerable
}

# In your main script:
if [[ $responseCode -eq 200 ]] && [[ "$attackBody" != "$baselineBody" ]]; then
    echo "Checking for element count changes..."
    
    if check_vulnerable "$baselineBody" "$attackBody"; then
        echo -e "${RED}[VULNERABLE] ⚠️ SQL INJECTION DETECTED!${NC}"
        echo "Elements increased: $(echo "$baselineBody" | grep -o '<[^>]*>' | wc -l) → $(echo "$attackBody" | grep -o '<[^>]*>' | wc -l)"
        echo -------------
            echo -e "${RED}[VULNERABLE] ⚠️ POSSIBLE SQL INJECTION VULNERABILITY DETECTED!${NC}"
            echo -e "    URL: ${YELLOW}$url${NC}"
            echo -e "    Payload: ${YELLOW}$payload${NC}"
            echo -e "    Reason: ${BLUE}Elements on page increased$ ${increase_pct}% (${original_count} → ${sql_count})${NC}"
            echo ""
            
            # Try to identify what changed (product count, etc.)
            echo "    Element Count Analysis:"
            echo "       Original: $original_count HTML elements"
            echo "       SQL test: $sql_count HTML elements"





        # Show pattern changes
        check_pattern_changes "$baselineBody" "$attackBody"
        
        SQLRiskConfidence=$((SQLRiskConfidence + 75))
        vulnerable=true
    fi
fi