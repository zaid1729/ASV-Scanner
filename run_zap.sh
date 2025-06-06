#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Check if ZAP is installed
if [ ! -f "/usr/share/zaproxy/zap.sh" ]; then
    print_error "ZAP not found at /usr/share/zaproxy/zap.sh"
    print_error "Please install OWASP ZAP or update the path in this script."
    exit 1
fi

print_status "Starting ZAP proxy on localhost:8080..."
print_status "Press Ctrl+C to stop the proxy."

# Run ZAP proxy
/usr/share/zaproxy/zap.sh -daemon -host localhost -port 8080
