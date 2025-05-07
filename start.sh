#!/bin/bash

# activate virtual environment
source scanner_venv/bin/activate

echo "[+] Starting CVE API server..."
cd cve_api || { echo "cve_api folder not found"; exit 1; }
python3 api.py &

API_PID=$!
cd ..

sleep 3
echo "[+] CVE API server should now be running at http://127.0.0.1:8000"


sleep 3
echo "[+] Starting ZAP proxy on http://127.0.0.1:8080"
/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080


echo "[+] Launching ASV scanner..."
python3 main.py

# Optional: kill the API server after scanner ends
echo "[+] Shutting down CVE API server..."
kill $API_PID
