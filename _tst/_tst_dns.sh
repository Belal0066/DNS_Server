#!/bin/bash
# _tst_dns.sh


GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
RESET='\033[0m' 


DNS_SERVER="127.0.0.66"
DOMAINS=("hahalol.com" "m4mwgoud.com" "google.com" "test123.com")
PARALLEL_QUERIES=10
TOTAL_TESTS=10


get_timestamp() {
    date '+@%H:%M:%S.%N' | cut -b1-27
}


query_dns() {
    local domain=$1
    local query_id=$2
    local start_time=$(date +%s.%N)
    local start_timestamp=$(get_timestamp)
    
    echo -e "${BLUE}[Query $query_id] ${start_timestamp} Starting query for ${domain}${RESET}"
    
    
    result=$(nslookup $domain $DNS_SERVER 2>&1)
    exit_code=$?
    
    local end_time=$(date +%s.%N)
    local end_timestamp=$(get_timestamp)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[Query $query_id] ${end_timestamp} Success: $domain (${duration}s)${RESET}"
    else
        echo -e "${RED}[Query $query_id] ${end_timestamp} Failed: $domain (${duration}s)${RESET}"
    fi
}


echo "=== DNS Server Test ==="
echo "Server: $DNS_SERVER"
echo "Parallel Queries: $PARALLEL_QUERIES"
echo "Total Tests: $TOTAL_TESTS"
echo "===================="


TOTAL_START=$(date +%s)


for ((i=1; i<=$TOTAL_TESTS; i++)); do
    
    RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
    
    
    query_dns $RANDOM_DOMAIN $i &
    
    
    if (( i % PARALLEL_QUERIES == 0 )); then
        wait
        echo "------- Batch complete -------"
    fi
done


wait


TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo "===================="
echo "All tests completed in $TOTAL_DURATION seconds"