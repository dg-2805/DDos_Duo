#!/bin/bash

# DNS Load Balancer Performance Test Script
# This script tests the optimized DNS load balancer for high QPS

echo "=== DNS Load Balancer Performance Test ==="
echo "Testing optimized load balancer for 1000-2000 QPS target"
echo

# Configuration
LB_PORT=5353
MOCK_PORT1=5354
MOCK_PORT2=5355
TEST_DURATION=30
TARGET_QPS=1500

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${RED}Port $port is already in use${NC}"
        return 1
    fi
    return 0
}

# Function to cleanup processes
cleanup() {
    echo -e "\n${YELLOW}Cleaning up processes...${NC}"
    pkill -f "mock_dns_server" 2>/dev/null
    pkill -f "dns_load_balancer" 2>/dev/null
    sleep 2
}

# Function to start mock DNS servers
start_mock_servers() {
    echo -e "${YELLOW}Starting mock DNS servers...${NC}"
    
    # Start first mock server
    ./mock_dns_server --port $MOCK_PORT1 --response-delay 1 &
    MOCK_PID1=$!
    
    # Start second mock server  
    ./mock_dns_server --port $MOCK_PORT2 --response-delay 1 &
    MOCK_PID2=$!
    
    sleep 2
    
    # Test mock servers
    if ! dig @127.0.0.1 -p $MOCK_PORT1 google.com A +time=1 >/dev/null 2>&1; then
        echo -e "${RED}Mock server 1 failed to start${NC}"
        return 1
    fi
    
    if ! dig @127.0.0.1 -p $MOCK_PORT2 google.com A +time=1 >/dev/null 2>&1; then
        echo -e "${RED}Mock server 2 failed to start${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Mock servers started successfully${NC}"
    return 0
}

# Function to start load balancer
start_load_balancer() {
    echo -e "${YELLOW}Starting optimized load balancer...${NC}"
    
    # Set environment variables for optimization
    export MOCK_BACKENDS=1
    export LB_CACHE_TTL_MS=5000
    
    # Start load balancer with multiple workers
    sudo ./dns_load_balancer -p $LB_PORT -w 4 -v &
    LB_PID=$!
    
    sleep 3
    
    # Test load balancer
    if ! dig @127.0.0.1 -p $LB_PORT google.com A +time=1 >/dev/null 2>&1; then
        echo -e "${RED}Load balancer failed to start${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Load balancer started successfully${NC}"
    return 0
}

# Function to run performance test
run_performance_test() {
    echo -e "${YELLOW}Running performance test for ${TEST_DURATION} seconds...${NC}"
    echo "Target QPS: $TARGET_QPS"
    echo
    
    # Create test domains file
    cat > test_domains.txt << EOF
google.com
example.com
test.com
domain.com
site.com
EOF
    
    # Run dnsperf for high QPS testing
    if command -v dnsperf >/dev/null 2>&1; then
        echo "Using dnsperf for testing..."
        dnsperf -s 127.0.0.1 -p $LB_PORT -d test_domains.txt -l $TEST_DURATION -Q $TARGET_QPS -c 100
    elif command -v dig >/dev/null 2>&1; then
        echo "Using dig for basic testing..."
        # Simple test with dig
        for i in $(seq 1 100); do
            dig @127.0.0.1 -p $LB_PORT google.com A +time=1 >/dev/null 2>&1 &
        done
        wait
    else
        echo -e "${RED}Neither dnsperf nor dig found. Please install dnsperf for accurate testing.${NC}"
        return 1
    fi
    
    rm -f test_domains.txt
}

# Function to measure QPS
measure_qps() {
    echo -e "${YELLOW}Measuring QPS...${NC}"
    
    local start_time=$(date +%s)
    local queries=0
    
    # Run queries for 10 seconds
    for i in $(seq 1 1000); do
        dig @127.0.0.1 -p $LB_PORT google.com A +time=1 >/dev/null 2>&1 &
        queries=$((queries + 1))
        
        # Check every 100 queries
        if [ $((queries % 100)) -eq 0 ]; then
            local current_time=$(date +%s)
            local elapsed=$((current_time - start_time))
            if [ $elapsed -ge 10 ]; then
                break
            fi
        fi
    done
    
    wait
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    local qps=$((queries / elapsed))
    
    echo "Measured QPS: $qps"
    
    if [ $qps -ge 1000 ]; then
        echo -e "${GREEN}SUCCESS: Achieved $qps QPS (target: 1000+)${NC}"
        return 0
    else
        echo -e "${RED}FAILED: Only achieved $qps QPS (target: 1000+)${NC}"
        return 1
    fi
}

# Main execution
main() {
    echo "Checking prerequisites..."
    
    # Check if running as root (for port 53)
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Note: Running without root privileges. Using port $LB_PORT${NC}"
    fi
    
    # Check if binaries exist
    if [ ! -f "./dns_load_balancer" ]; then
        echo -e "${RED}dns_load_balancer binary not found. Please build first.${NC}"
        exit 1
    fi
    
    if [ ! -f "./mock_dns_server" ]; then
        echo -e "${RED}mock_dns_server binary not found. Please build first.${NC}"
        exit 1
    fi
    
    # Check ports
    if ! check_port $LB_PORT || ! check_port $MOCK_PORT1 || ! check_port $MOCK_PORT2; then
        echo -e "${RED}Required ports are in use. Please free them and try again.${NC}"
        exit 1
    fi
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    echo -e "${GREEN}Starting performance test...${NC}"
    
    # Start services
    if ! start_mock_servers; then
        exit 1
    fi
    
    if ! start_load_balancer; then
        exit 1
    fi
    
    # Run tests
    echo -e "${GREEN}All services started. Running performance tests...${NC}"
    
    # Quick QPS measurement
    if measure_qps; then
        echo -e "${GREEN}Performance test PASSED!${NC}"
        echo -e "${GREEN}The optimized load balancer can handle 1000+ QPS${NC}"
    else
        echo -e "${RED}Performance test FAILED!${NC}"
        echo -e "${YELLOW}Consider further optimizations or hardware upgrades${NC}"
    fi
    
    echo -e "\n${YELLOW}Test completed. Check the output above for results.${NC}"
}

# Run main function
main "$@"
