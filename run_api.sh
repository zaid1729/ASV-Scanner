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

# Find the cve_api directory
if [ -d "cve_api" ]; then
    cd cve_api
elif [ -d "asv-scanner/cve_api" ]; then
    cd asv-scanner/cve_api
else
    print_error "Cannot find cve_api directory."
    print_error "Please run from asv-scanner directory or its parent."
    exit 1
fi

print_status "Starting CVE API..."
print_status "Press Ctrl+C to stop the API."

# Check if api.py exists
if [ ! -f "api.py" ]; then
    print_error "api.py not found in cve_api directory."
    exit 1
fi

# Run the API
python3 api.py
