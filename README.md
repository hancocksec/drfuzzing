# 🧪 DrFuzzing - Advanced Web Path Fuzzer

Dr Fuzzing is an advanced web path fuzzing tool designed to discover hidden directories and endpoints in web applications.  
It utilizes multithreading for fast execution and supports both HTTP and HTTPS protocols with full user-configurable options.

---

## ✨ Features

- 🔎 Detect hidden paths using customizable wordlists
- ⚡ High performance with multithreaded scanning
- 🔐 SSL support with optional verification bypass
- 🚫 Optional redirect control
- 📄 Save results to external output files
- 🧠 Response encoding detection using chardet
- ⌛ Full control over timeouts and request delays

---

## 🧰 Requirements

`bash
python >= 3.7

📦 Installation

pip install -r requirements.txt


---

🚀 Usage

python drfuzzing.py -u https://example.com -w word.txt

⚙️ Available Options

Option Description

-u, --url ✅ (Required) Target URL (e.g., https://example.com)
-w, --wordlist ✅ (Required) Path to the wordlist file
-t, --threads Number of threads (default: 10)
-o, --output Save results to a file
--timeout Request timeout in seconds (default: 15)
--no-ssl-verify Disable SSL certificate verification
--no-redirects Disable following redirects
--show-all Show all responses (including 404s)
--delay Delay between requests in seconds (default: 0.1)



---

📁 Examples

# Quick scan with 20 threads
python drfuzzing.py -u https://target.com -w wordlists/dirs.txt -t 20

# Disable SSL verification and redirects
python drfuzzing.py -u https://target.com -w wordlists/dirs.txt --no-ssl-verify --no-redirects

# Save results to a file
python drfuzzing.py -u https://target.com -w wordlists/dirs.txt -o results.txt


---

📂 Project Structure

DrFuzzing/
├── drfuzzing.py
├── README.md
├── requirements.txt
├── wordlists/
│   └── word.txt



---

🧑‍💻 Author

Hancock

GitHub: github.com/hancock



---

📜 License

This project is licensed under the MIT License.


---

🛠️ Future Plans

[ ] Automatic 403 bypass detection

[ ] GUI (Graphical User Interface) support

[ ] Smarter handling of WAF (Web Application Firewall)

[ ] Support for custom user-agents and headers



---

> Contribute via Forks and Pull Requests — become the next Dr of Fuzzing! 💉




---

🏷️ Badges (Optional)

![Python](https://img.shields.io/badge/Python-3.7+-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---
