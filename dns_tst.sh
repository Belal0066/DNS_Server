#!/bin/bash
# dns_tst.sh

# Colors for better visibility
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test configuration
DNS_SERVER="127.0.0.66"
DOMAINS=("hahalol.com" "m4mwgoud.com" "google.com" "elbolbol.com")
PARALLEL_QUERIES=10
TOTAL_TESTS=10

# Function to get high precision timestamp
get_timestamp() {
    date '+@%H:%M:%S.%N' | cut -b1-27
}

# Function to make a single DNS query with timing
query_dns() {
    local domain=$1
    local query_id=$2
    local start_time=$(date +%s.%N)
    local start_timestamp=$(get_timestamp)
    
    echo -e "${BLUE}[Query $query_id] ${start_timestamp} Starting query for ${domain}${NC}"
    
    # Make the actual DNS query
    result=$(nslookup $domain $DNS_SERVER 2>&1)
    exit_code=$?
    
    local end_time=$(date +%s.%N)
    local end_timestamp=$(get_timestamp)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[Query $query_id] ${end_timestamp} Success: $domain (${duration}s)${NC}"
    else
        echo -e "${RED}[Query $query_id] ${end_timestamp} Failed: $domain (${duration}s)${NC}"
    fi
}

# Print test configuration
echo "=== DNS Server Test ==="
echo "Server: $DNS_SERVER"
echo "Parallel Queries: $PARALLEL_QUERIES"
echo "Total Tests: $TOTAL_TESTS"
echo "===================="

# Start time for overall execution
TOTAL_START=$(date +%s)

# Run queries in parallel
for ((i=1; i<=$TOTAL_TESTS; i++)); do
    # Select a random domain
    RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
    
    # Run query in background
    query_dns $RANDOM_DOMAIN $i &
    
    # If we've started PARALLEL_QUERIES queries, wait for one to finish
    if (( i % PARALLEL_QUERIES == 0 )); then
        wait
        echo "------- Batch complete -------"
    fi
done

# Wait for any remaining queries
wait

# Calculate total execution time
TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo "===================="
echo "All tests completed in $TOTAL_DURATION seconds"

