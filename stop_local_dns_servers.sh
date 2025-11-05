#!/bin/bash
# Stop all local DNS servers

if [ -f /tmp/dns_servers.pids ]; then
    echo "Stopping DNS servers..."
    while read pid; do
        if kill -0 $pid 2>/dev/null; then
            kill $pid
            echo "Stopped server with PID $pid"
        fi
    done < /tmp/dns_servers.pids
    rm -f /tmp/dns_servers.pids
    echo "All DNS servers stopped."
else
    echo "No DNS server PIDs found. They may already be stopped."
fi

# Also kill any remaining python DNS servers
pkill -f "local_dns_server[123].py" 2>/dev/null && echo "Cleaned up any remaining DNS server processes"

