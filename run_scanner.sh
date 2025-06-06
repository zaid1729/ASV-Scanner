#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if in asv-scanner directory or parent directory
if [ -d "asv-scanner" ]; then
    cd asv-scanner
elif [ ! -f "requirements.txt" ]; then
    print_error "Not in asv-scanner directory. Please run from asv-scanner or its parent directory."
    exit 1
fi

print_status "Setting up Python virtual environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "myenv" ]; then
    python3 -m venv myenv
    print_status "Virtual environment created."
else
    print_warning "Virtual environment already exists."
fi

# Activate virtual environment
source myenv/bin/activate
print_status "Virtual environment activated."

# Install dependencies
print_status "Installing dependencies..."
pip install -r requirements.txt

print_warning "Make sure ZAP proxy and CVE API are running before proceeding!"
echo -n "Press Enter when ready to run the scanner..."
read

# Run the scanner
print_status "Running ASV scanner with active scan and proxy..."
python3 main.py --activescan --proxy

print_status "Scanning completed."
