#!/bin/bash
# DNS Load Balancer Performance Test Script

echo "DNS Load Balancer Performance Test"
echo "==================================="
echo ""

# Check if dnsperf is installed
if ! command -v dnsperf &> /dev/null; then
    echo "ERROR: dnsperf is not installed."
    echo "Install it with: sudo apt-get install dnsperf"
    exit 1
fi

# Configuration
LB_HOST="127.0.0.1"
LB_PORT="5353"
QUERIES_FILE="queries.txt"
DURATION=30
QPS=10000

echo "Load Balancer: ${LB_HOST}:${LB_PORT}"
echo "Queries File: ${QUERIES_FILE}"
echo "Duration: ${DURATION} seconds"
echo "Target QPS: ${QPS}"
echo ""

# Test 1: Low QPS baseline
echo "=== Test 1: Baseline (1000 QPS) ==="
dnsperf -d ${QUERIES_FILE} -s ${LB_HOST} -p ${LB_PORT} -l ${DURATION} -Q 1000

echo ""
echo "=== Test 2: Medium Load (5000 QPS) ==="
dnsperf -d ${QUERIES_FILE} -s ${LB_HOST} -p ${LB_PORT} -l ${DURATION} -Q 5000

echo ""
echo "=== Test 3: High Load (10000 QPS) ==="
dnsperf -d ${QUERIES_FILE} -s ${LB_HOST} -p ${LB_PORT} -l ${DURATION} -Q 10000

echo ""
echo "=== Test 4: Maximum Load (50000 QPS) ==="
dnsperf -d ${QUERIES_FILE} -s ${LB_HOST} -p ${LB_PORT} -l ${DURATION} -Q 50000

echo ""
echo "=== Test Complete ==="
echo "Check metrics at: curl http://localhost:8080"

