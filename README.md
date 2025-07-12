# 🚀 Advanced Parallel Reconnaissance Framework

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
![Python](https://img.shields.io/badge/python-3.6+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**🔥 Lightning-Fast Parallel Network Reconnaissance with Real-Time Exploit Discovery 🔥**

*The most comprehensive reconnaissance framework with AI-powered analysis, sound alerts, and instant exploit discovery*

</div>

---

## 🎯 **Features Overview**

<table>
<tr>

### 🚀 **Core Features**
- ⚡ **Ultra-Fast Parallel Scanning**
- 🔊 **Sound Alerts System**
- 🎨 **Enhanced UI with Emojis**
- 📋 **Real-Time Banner Grabbing**
- 🔧 **Technology Detection**
- 💥 **Automatic Exploit Discovery**

</td>

### 🛡️ **Advanced Modules**
- 🌐 **Web Content Scraping**
- 🗄️ **Database Enumeration**
- 🔑 **Credential Discovery**
- 📁 **FTP/SMB Testing**
- 🎯 **Vulnerability Assessment**
- 📊 **Professional Reporting**

</td>
</tr>
</table>

---

## 📸 **Screenshots**

### 🎬 **Real-Time Scanning in Action**
```bash
[19:16:47] ✅ [FOUND] Port 80/tcp open (http)
[19:16:48] 📋 [BANNER] BANNER grabbed from port 8080: Server: HFS 2.3...
[19:16:48] 🔧 [TECH] TECHNOLOGY detected: HFS 2.3
[19:16:49] 💥 [EXPLOIT] EXPLOITS FOUND for HFS 2.3: 14 exploits
[19:16:50] 💥 [EXPLOIT]   -> Rejetto HTTP File Server (HFS) - Remote Command Execution
[19:16:51] 🚨 [CRITICAL] Redis service active on port 6379 - NO AUTH!
[19:16:52] 🔑 [CREDS] CREDENTIAL: password = admin123
```

### 📊 **Professional Summary Report**
```bash
FINAL SUMMARY:
  🌐 Open Ports: 12
  🔗 Web Services: 3  
  📄 URLs Found: 47
  🔧 Technologies: 5
  🗄️ Databases: 2
  📋 Banners: 8
  🔑 Credentials: 3

🔧 TECHNOLOGIES: 5 detected with exploit search!
🗄️ DATABASES: 2 database services found!
🔑 CRITICAL: 3 credentials found!
```

---

## 🚀 **Quick Start**

### 📦 **Installation**

```bash
# Clone the repository
git clone https://github.com/sneckey0day/InfernoRecon.git
cd InfernoRecon

# Run the setup script (installs all dependencies)
chmod +x setup.sh
./setup.sh

# Make the tool executable
chmod +x infernorecon.py
```

### ⚡ **Basic Usage**

```bash
# Basic reconnaissance scan
./infernorecon.py 192.168.1.100

# Silent mode (no sound alerts)
./infernorecon.py 192.168.1.100 --no-sound

# Extended scan with database enumeration
./infernorecon.py 192.168.1.100 --timeout 600 --database-enum

# Advanced credential testing
./infernorecon.py 192.168.1.100 --advanced-creds
```

---

## 🛠️ **Advanced Features**

### 🔊 **Sound Alert System**
<details>
<summary>Click to expand</summary>

- **🚨 Critical Findings**: High-pitched alert for vulnerabilities
- **💥 Exploit Discovery**: Medium-pitched alert for available exploits  
- **🔑 Credentials Found**: Quick beep for discovered credentials
- **🔇 Toggle Option**: Use `--no-sound` to disable alerts

```bash
# Enable sound alerts (default)
./infernorecon.py target.com

# Disable sound alerts
./infernorecon.py target.com --no-sound
```

</details>

### 🗄️ **Database Enumeration**
<details>
<summary>Click to expand</summary>

Automatically detects and tests:
- **MySQL** (Port 3306)
- **PostgreSQL** (Port 5432)
- **MongoDB** (Port 27017)
- **Redis** (Port 6379)
- **MSSQL** (Port 1433)
- **Oracle** (Port 1521)

```bash
# Enable database enumeration
./infernorecon.py target.com --database-enum
```

</details>

### 💥 **Exploit Discovery Engine**
<details>
<summary>Click to expand</summary>

- **SearchSploit Integration**: Automatic exploit searching
- **Smart Variations**: Multiple search terms per technology
- **Real-Time Results**: Instant exploit discovery
- **Special Cases**: Enhanced searches for common technologies

**Supported Technologies:**
- Web Servers (Apache, Nginx, IIS)
- CMS Systems (WordPress, Drupal, Joomla)
- File Servers (HFS, Rejetto)
- Programming Languages (PHP, ASP.NET)
- And many more...

</details>

### 🎨 **Enhanced User Interface**
<details>
<summary>Click to expand</summary>

- **🚨 Critical**: Red background + blinking + sound
- **💥 Exploits**: Red background + sound alert
- **🔑 Credentials**: Purple + underline + sound
- **✅ Found**: Bright green + bold
- **🔧 Technology**: Bright cyan + bold
- **📋 Banner**: Bright blue + bold

</details>

---

## 📋 **Command Line Options**

| Option | Description | Example |
|--------|-------------|---------|
| `target` | Target IP or hostname | `192.168.1.100` |
| `--timeout` | Scan timeout in seconds | `--timeout 600` |
| `--no-sound` | Disable sound alerts | `--no-sound` |
| `--database-enum` | Enable database enumeration | `--database-enum` |
| `--advanced-creds` | Enable advanced credential testing | `--advanced-creds` |

---

## 🎯 **Use Cases**

### 🔒 **Penetration Testing**
```bash
# Comprehensive pentest reconnaissance
./infernorecon.py target.company.com --timeout 900 --database-enum --advanced-creds
```

### 🐛 **Bug Bounty Hunting**
```bash
# Quick vulnerability discovery
./infernorecon.py bounty-target.com --timeout 300
```

### 🏢 **Internal Network Assessment**
```bash
# Internal network scan
./infernorecon.py 10.10.10.100 --no-sound --timeout 600
```

### 🎓 **CTF & Learning**
```bash
# TryHackMe/HackTheBox scanning
./infernorecon.py 10.10.211.42 --timeout 300
```

---

## 📁 **Output Structure**

```
advanced_recon_target_timestamp/
├── 📄 live_findings.json          # Real-time results
├── 🌐 nmap_detailed.xml           # Nmap scan results
├── 📋 banner_info.txt             # Collected banners
├── 💥 exploits_Apache_2.4.18.json # Exploit details
├── 🔧 technologies.json           # Detected technologies
├── tmp/                           # Temporary files (auto-cleaned)
│   ├── feroxbuster_results.txt
│   ├── sensitive_files/
│   └── downloaded_content/
└── 📊 summary_report.html         # Final report
```

---

## 🔧 **Dependencies**

### 🐍 **Python Packages**
```bash
pip3 install requests beautifulsoup4 lxml
```

### 🛠️ **External Tools**
- **nmap** - Network scanning
- **searchsploit** - Exploit database
- **feroxbuster** - Directory enumeration
- **smbclient** - SMB enumeration
- **enum4linux** - Linux enumeration

*All dependencies are automatically installed by the setup script!*

---

## 🎨 **Customization**

### 🔊 **Custom Sound Alerts**
```python
# Edit infernorecon.py to customize sound files
def play_sound_alert(self, alert_type="default"):
    if alert_type == "critical":
        os.system("paplay /path/to/your/critical-sound.wav")
```

### 🎨 **Custom Colors**
```python
# Modify the Colors class for custom themes
class Colors:
    CUSTOM_CRITICAL = '\033[1;91m'  # Your custom color
```

---

## 🤝 **Contributing**

We welcome contributions! Here's how you can help:

### 🐛 **Bug Reports**
- Use the issue tracker
- Include system information
- Provide reproduction steps

### ✨ **Feature Requests**
- Describe the feature
- Explain the use case
- Provide implementation ideas

### 🔧 **Pull Requests**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ **Disclaimer**

**🚨 IMPORTANT: This tool is for authorized security testing only!**

- ✅ Only use on systems you own or have explicit permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Use responsibly and ethically
- ❌ Do not use for malicious purposes
- ❌ Do not test systems without permission

The authors are not responsible for any misuse or damage caused by this tool.

---

## 🙏 **Acknowledgments**

- **SearchSploit** - Exploit database integration
- **Nmap** - Network scanning capabilities
- **Feroxbuster** - Directory enumeration
- **BeautifulSoup** - Web content parsing
- **Community** - Bug reports and feature suggestions

---

## 📞 **Support**

### 💬 **Get Help**
- 📧 **Email**: support@yourproject.com
- 💬 **Discord**: [Join our server](https://discord.gg/yourserver)
- 🐛 **Issues**: [GitHub Issues](https://github.com/sneckey0day/InfernoRecon/issues)

### 📚 **Documentation**
- 📖 **Wiki**: [Project Wiki](https://github.com/yourusername/advanced-recon-framework/wiki)
- 🎥 **Tutorials**: [YouTube Channel](https://youtube.com/yourchannel)
- 📝 **Blog**: [Project Blog](https://yourblog.com)

---

<div align="center">

### 🌟 **Star this repository if you found it helpful!** 🌟

**Made with ❤️ by the Security Research Community**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/advanced-recon-framework.svg?style=social&label=Star)](https://github.com/sneckey0day/InfernoRecon)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/advanced-recon-framework.svg?style=social&label=Fork)](https://github.com/sneckey0day/InfernoRecon/fork)

</div>
