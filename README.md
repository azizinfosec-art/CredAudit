# 🔐 CredAudit

**CredAudit** is a fast, resilient **secret scanner** for local and shared folders.  
It helps security teams and developers **detect passwords, tokens, API keys, private keys, and other sensitive information** in multiple file formats.  

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)  
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## ✨ Features

- 🚀 **High performance**: Multithreading (file discovery) + multiprocessing (scanning)  
- ⚡ **Resilient scanning**: skips unreadable/locked files without crashing  
- 🛡️ **Rich detection rules**:
  - Password assignments (`password=secret123`, `pwd:`, `token=...`)  
  - Cloud keys (AWS, GCP, Azure, GitHub, Google, Slack)  
  - PEM private keys, JWTs, Slack Webhooks  
  - High-entropy string detection  
- 📂 **Multi-format support**:
  - `.txt`, `.json`, `.env`, `.docx`, `.pdf`, `.xlsx`  
  - Optional archive scanning (`.zip`, `.rar`) with depth control  
- 🧩 **Configurable** via `config.yaml` + CLI overrides  
- 🎯 **CI/CD friendly**:
  - `--fail-on {Low,Medium,High}` returns non-zero exit codes  
- 📊 **Reports**:
  - JSON → structured output  
  - CSV → tabular data  
  - HTML → severity-colored table with secrets redacted  
  - SARIF → integrate with GitHub Security tab

---

## 📦 Installation

### Clone & install
```powershell
git clone https://github.com/azizinfosec-art/CredAudit
cd credaudit
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install .
Requirements
Python 3.9+

Windows, Linux, or macOS

For .rar archive scanning: install unrar or unar

🚀 Usage
Show help
powershell
Copy code
credaudit --help
Validate configuration
powershell
Copy code
credaudit validate
List detection rules
powershell
Copy code
credaudit rules
Run a scan
powershell
Copy code
# Scan a folder and output JSON + HTML reports
credaudit scan -p C:\data --formats json html -o .\out --timestamp

# Verbose mode (shows skipped files with reasons)
credaudit scan -p C:\data --verbose

# Scan inside ZIP/RAR archives, 2 levels deep
credaudit scan -p C:\data --scan-archives --archive-depth 2 --formats sarif html
📂 Example Reports
HTML report (redacted findings with severity coloring):


🛠 Configuration
The default config is in config.yaml:

yaml
Copy code
include_ext: [".txt", ".json", ".env", ".docx", ".pdf", ".xlsx"]
exclude_glob: ["**/.git/**", "**/__pycache__/**", "**/node_modules/**"]
threads: 8
entropy_min_length: 20
entropy_threshold: 4.0
rules:
  enable_password_assignment: true
  enable_jwt: true
  enable_private_keys: true
  enable_cloud_tokens: true
  enable_entropy: true
You can override any of these via CLI flags.

🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request with improvements.
Ideas:

New regex rules for secrets

Performance enhancements

Exporters (Markdown, Excel, etc.)

Integration with cloud APIs

⚖️ License
This project is licensed under the MIT License. See the LICENSE file for details.

⚠️ Disclaimer
CredAudit is a security auditing tool.

Do not use it to scan systems or files without explicit permission.

Always comply with your organization’s security policies.

Authors are not responsible for misuse of this tool.

