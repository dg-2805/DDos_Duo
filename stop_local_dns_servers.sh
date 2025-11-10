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

# Stop BIND server if running
if [ -f /tmp/bind_server.pid ]; then
    BIND_PID=$(cat /tmp/bind_server.pid)
    if kill -0 $BIND_PID 2>/dev/null; then
        kill $BIND_PID
        echo "Stopped BIND server with PID $BIND_PID"
    fi
    rm -f /tmp/bind_server.pid
fi

# Also try to stop any named processes
pkill -f "named.*named.conf.bind" 2>/dev/null && echo "Cleaned up any remaining BIND processes"

