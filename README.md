# Subee - Advanced Subdomain Scanner 🔍

**"Chupa-Chups your way through subdomains!"** - by bughunter

## 🚀 Overview

Subee is a powerful asynchronous subdomain scanner designed for security researchers, bug bounty hunters, and penetration testers. This tool combines multiple reconnaissance techniques to discover hidden subdomains and identify live web applications.

## ✨ Features

- **Multi-source enumeration** (VirusTotal, SecurityTrails APIs)
- **Bruteforce scanning** with custom wordlists
- **Live subdomain verification** with status codes
- **Smart error handling** and retry mechanisms
- **CSV export** with organized results
- **Asynchronous I/O** for blazing fast scans
- **Developer-friendly** with clean code structure

## 🛠 Installation

```bash
git clone https://github.com/bughunter-chupachups/subee.git
cd subee
pip install -r requirements.txt
```

📖 Usage
Basic scan:
```
python subee.py -d example.com
```

With custom wordlist:
```
python subee.py -d example.com -w wordlist.txt
```

Specify output file:
```
python subee.py -d example.com -o results.csv
```

⚙️ Configuration
Get API keys:

   - VirusTotal
   - SecurityTrails

Replace in code:
```
# In SubdomainScanner class:
headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}
headers = {"APIKEY": "YOUR_SECURITYTRAILS_API_KEY"}
```

📊 Output Format

Results are saved in CSV format with two sections:
Found Subdomains - All discovered subdomains
Live Subdomains - Verified live domains with status codes
Example output:
```
Found Subdomains

admin.example.com
dev.example.com
test.example.com


Live Subdomains,Final URL,Status Code

www.example.com,www.example.com/login,200
api.example.com,api.example.com/v2,301
```

🧰 Requirements
   - Python 3.7+
   - aiohttp
   - dnspython
  - tqdm

🤝 Contributing

Fork the project
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

📜 License

Distributed under the MIT License. See LICENSE for more information.

📌 Roadmap

Add more API integrations (Censys, Shodan)
Implement recursive subdomain discovery
Add screenshot functionality
Develop Docker container version
