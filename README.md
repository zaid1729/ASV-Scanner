# 🔍 ASV PCI DSS Security Scanner

A multi-threaded security scanner that checks for:
- Open ports and known CVEs (via Nmap & CVE API)
- SSL/TLS security (certificates, weak ciphers)
- DNS zone transfers, SMTP open relays, ICMP exposure
- Web application security (external scripts, ZAP scan)
- PCI DSS-compliant reporting (JSON + console summary + PDf format)

---

## 📦 Requirements
Before installing requirements, it is recommended to create a python virtual environment to evade collision between  python dependicies:
- Create environment before starting the project:
```bash
python3 -m venv myenv
```
- Activate your environment:
```bash
source myenv/bin/activate
```
- Deactivate when you are done:
```bash
deactivate
```

##
Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run

First, run ZAP. execute on a new termianl the following command:
```bash
/usr/share/zaproxy/zap.sh -daemon -host localhost -port 8080
```

Then, open another new terminal and go to `asv-scanner` > `cve_api` folder, run:
```bash
python3 api.py
```
The server is listening on `http://127.0.0.1:8000` for the CVE Database.

After, in another terminal, go Inside the `asv-scanner` folder, run:

```bash
python3 main.py --activescan --proxy
```

Then enter your **target or the Scope** when prompted.

Example:
```bash
Enter Target IP or Domain: example.com
```

---

## 📝 Output

- Full PCI DSS scan summary is printed in the console
- A detailed report is saved as:
  ```
  pci_asv_scan_report.json
  ```
- The report on PDF format is generated inside the ``asv-scanner`` folder.  

---

## 📁 Project Structure

```
scanner/
├── main.py                 # Entry point
├── config.py               # Global constants
├── core/                   # Scanning & reporting logic
│   ├── port_scanner.py
│   ├── report.py
│   └── result_manager.py
├── utils/                  # Helper tools
│   ├── tls_scanner.py
│   ├── cve_api.py
│   ├── proxies_checker.py
│   ├── dns_smtp_icmp.py
│   ├── passive_web.py
│   └── zap_scanner.py
├── cve_api/                  # Helper tools
│   ├── api.py
├── data/                  # Helper tools
│   ├── merged_cve.json  # this is where the CVE database is located.
├── requirements.txt
```

---

## ⚠️ Notes

- Requires **Nmap3** installed on your system. 
- Make sure OWASP ZAP is running at `http://127.0.0.1:8080` if using active scan.
- For the purpose of simplicity, in ZAP Proxy go to `Tools > Options > API` and disable API key option.
- Works best on **Linux-based OS** (Ubuntu, Kali, etc.)

---

## 📖 License

MIT — do what you want, just give credit if it helps. 🙂
