# 🚀 InfernoRecon - Reconnaissance Framework

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
![Python](https://img.shields.io/badge/python-3.6+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**🔥 Lightning-Fast Network Recon with Real-Time Exploit Discovery 🔥**

*AI-enhanced reconnaissance with live alerts, parallel scans, and smart exploit matching.*

</div>

---
![Recon Output](./images/POC.svg)
---

## 🎯 Features At a Glance

| Core Features                | Advanced Modules                 |
| ---------------------------- | -------------------------------- |
| ⚡ Parallel Port Scanning     | 🌐 Web Content Scraping          |
| 🔧 Technology Detection      | 🗄️ DB Enumeration (MySQL, etc.) |
| 📋 Real-Time Banner Grabbing | 🔑 Credential Discovery          |
| 💥 Exploit Auto-Search       | 🎯 Vuln Assessment               |
| 🔊 Sound Alerts              | 📊 Professional Reports          |

---

## 📸 Quick Demo (Live Output)

```bash
[✓] Port 80 open (http)
[📋] Banner: Apache 2.4.18
[🔧] Detected: Apache 2.4.18
[💥] Exploits Found: 4
[🚨] Redis (no auth!) on 6379
[🔑] Creds found: password=admin123
```

---

## ⚙️ Quick Start

### 🧩 Installation

```bash
git clone https://github.com/sneckey0day/InfernoRecon.git
cd InfernoRecon
chmod +x setup.sh && ./setup.sh
chmod +x infernorecon.py
```

### 🔍 Basic Usage

```bash
./infernorecon.py 192.168.1.100
./infernorecon.py 192.168.1.100 --no-sound
./infernorecon.py 192.168.1.100 --timeout 600 --database-enum
./infernorecon.py 192.168.1.100 --advanced-creds
```

---

## 🛠️ Advanced Capabilities

<details>
<summary>🔊 Sound Alerts</summary>

| Alert Type     | Sound  |
| -------------- | ------ |
| 🚨 Critical    | High   |
| 💥 Exploits    | Medium |
| 🔑 Credentials | Beep   |

Toggle with `--no-sound`

</details>

<details>
<summary>🗄️ Database Enumeration</summary>

Ports & Services:

* 3306 (MySQL)
* 5432 (PostgreSQL)
* 27017 (MongoDB)
* 6379 (Redis)
* 1433 (MSSQL)
* 1521 (Oracle)

</details>

<details>
<summary>💥 Exploit Discovery Engine</summary>

* 🔍 SearchSploit Integration
* 🧠 Smart term variation
* ⚙️ Real-time matching
* CMS/Web/File server aware

</details>

<details>
<summary>🎨 UI/UX Enhancements</summary>

| Type        | Styling                   |
| ----------- | ------------------------- |
| 🚨 Critical | Red + Blinking + Sound    |
| 💥 Exploit  | Red Background + Sound    |
| 🔑 Creds    | Purple + Underline + Beep |
| ✅ Found     | Bright Green + Bold       |
| 📋 Banners  | Bright Blue + Bold        |

</details>

---

## 📋 Command Line Options

| Option             | Description                   |
| ------------------ | ----------------------------- |
| `target`           | Target IP/host                |
| `--timeout`        | Timeout duration (sec)        |
| `--no-sound`       | Mute alerts                   |
| `--database-enum`  | Enable DB module              |
| `--advanced-creds` | Extended credential discovery |

---

## 📁 Output Structure

```
inferno_output/
├── live_findings.json         
├── nmap_detailed.xml          
├── banner_info.txt            
├── exploits_<tech>.json       
├── technologies.json          
├── tmp/
│   ├── feroxbuster_results.txt
│   └── sensitive_files/
└── summary_report.html         
```

---

## 🔒 Use Cases

| Scenario            | Command Example                    |
| ------------------- | ---------------------------------- |
| 🧪 Pentest Recon    | `--database-enum --advanced-creds` |
| 🎯 Bug Bounty Scan  | `--timeout 300`                    |
| 🧱 Internal Network | `--no-sound --timeout 600`         |
| 🎓 CTF Practice     | `--timeout 300`                    |

---

## 🧰 Dependencies

### 🐍 Python

```bash
pip3 install requests beautifulsoup4 lxml
```

### 🔧 Tools

* `nmap`, `searchsploit`, `feroxbuster`, `enum4linux`, `smbclient`

✅ Auto-installed by `setup.sh`

---

## 🎨 Customization Options

### 🔊 Sound Alerts

```python
def play_sound_alert(self, alert_type="critical"):
    os.system("paplay /your/custom.wav")
```

### 🎨 Terminal Colors

```python
class Colors:
    CRITICAL = '\033[1;91m'
    INFO = '\033[1;96m'
```

---

## 🤝 Contributing

| Type             | Description                       |
| ---------------- | --------------------------------- |
| 🐞 Bugs          | Use GitHub Issues w/ full details |
| ✨ Features       | Describe clearly w/ use case      |
| 🔧 Pull Requests | Fork → Branch → PR                |

---

## 📜 License

**MIT License** – see `LICENSE` file for full text.

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing only.**

* ✅ Use only on systems you own or are authorized to test
* ❌ No illegal use permitted
* 🛡️ Responsibility lies with the user

---

## 📞 Support & Docs

| Type       | Link                                                                |
| ---------- | ------------------------------------------------------------------- |
| 📧 Email   | [sneckey0day@gmail.com](mailto:sneckey0day@gmail.com)           |
| 🐛 Issues  | [GitHub Issues](https://github.com/sneckey0day/InfernoRecon/issues) |
---

<div align="center">

### ⭐️ Star This Repo If You Found It Useful ⭐️

**Built with precision by the Red Team Community**

[![GitHub stars](https://img.shields.io/github/stars/sneckey0day/InfernoRecon.svg?style=social)](https://github.com/sneckey0day/InfernoRecon)

</div>

---
