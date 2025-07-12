#!/bin/bash

# Complete Recon Framework Setup Script
# This script installs all required tools for the reconnaissance framework on Debian-based systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                RECON FRAMEWORK SETUP SCRIPT                 ║"
echo "║              Installing Required Tools...                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] This script should not be run as root${NC}"
   echo -e "${YELLOW}[*] Please run as a regular user with sudo privileges${NC}"
   exit 1
fi

# Check if running on Debian-based system
if ! command -v apt &> /dev/null; then
    echo -e "${RED}[!] This script is designed for Debian-based systems (Ubuntu, Kali, etc.)${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Updating package lists...${NC}"

echo -e "${BLUE}[*] Installing basic dependencies...${NC}"
sudo apt install -y curl wget git build-essential python3 python3-pip

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install requests urllib3 beautifulsoup4 lxml google-generativeai ldap3

# Install Nmap
echo -e "${BLUE}[*] Installing Nmap...${NC}"
sudo apt install -y nmap

# Install RustScan
echo -e "${BLUE}[*] Installing RustScan...${NC}"
if ! command -v rustscan &> /dev/null; then
    echo -e "${YELLOW}[*] Downloading RustScan...${NC}"
    wget -q https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    sudo dpkg -i rustscan_2.0.1_amd64.deb
    rm rustscan_2.0.1_amd64.deb
    echo -e "${GREEN}[+] RustScan installed successfully${NC}"
else
    echo -e "${GREEN}[+] RustScan already installed${NC}"
fi

# Install Feroxbuster
echo -e "${BLUE}[*] Installing Feroxbuster...${NC}"
if ! command -v feroxbuster &> /dev/null; then
    echo -e "${YELLOW}[*] Downloading Feroxbuster...${NC}"
    wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-linux-x86_64.tar.gz
    tar -xzf feroxbuster-linux-x86_64.tar.gz
    sudo mv feroxbuster /usr/local/bin/
    sudo chmod +x /usr/local/bin/feroxbuster
    rm feroxbuster-linux-x86_64.tar.gz
    echo -e "${GREEN}[+] Feroxbuster installed successfully${NC}"
else
    echo -e "${GREEN}[+] Feroxbuster already installed${NC}"
fi

# Install dirb (fallback for feroxbuster)
echo -e "${BLUE}[*] Installing dirb...${NC}"
sudo apt install -y dirb

# Install SMB tools
echo -e "${BLUE}[*] Installing SMB enumeration tools...${NC}"
sudo apt install -y smbclient enum4linux

# Install FTP client
echo -e "${BLUE}[*] Installing FTP client...${NC}"
sudo apt install -y ftp

# Install wordlists
echo -e "${BLUE}[*] Installing wordlists...${NC}"
sudo apt install -y wordlists

# Create wordlists directory if it doesn't exist
if [ ! -d "/usr/share/wordlists" ]; then
    sudo mkdir -p /usr/share/wordlists
fi

# Download SecLists if not present
if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    echo -e "${YELLOW}[*] Downloading SecLists...${NC}"
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    echo -e "${GREEN}[+] SecLists downloaded${NC}"
fi

# Install additional useful tools
echo -e "${BLUE}[*] Installing additional tools...${NC}"
sudo apt install -y nikto gobuster dirbuster hydra john masscan

# Install impacket for AD enumeration
echo -e "${BLUE}[*] Installing Impacket for AD enumeration...${NC}"
pip3 install impacket

# Install ldap tools
echo -e "${BLUE}[*] Installing LDAP tools...${NC}"
sudo apt install -y ldap-utils

# Install DNS tools
echo -e "${BLUE}[*] Installing DNS enumeration tools...${NC}"
sudo apt install -y dnsutils dnsrecon dnsenum

# Make the main script executable
chmod +x recon_tool.py

# Create a symbolic link for easy access
echo -e "${BLUE}[*] Creating symbolic link...${NC}"
sudo ln -sf $(pwd)/recon_tool.py /usr/local/bin/recon-framework

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETED!                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}[*] All tools have been installed successfully!${NC}"
echo -e "${YELLOW}[*] You can now run the framework with:${NC}"
echo -e "${GREEN}    ./recon_tool.py <target_ip>${NC}"
echo -e "${GREEN}    or${NC}"
echo -e "${GREEN}    recon-framework <target_ip>${NC}"
echo ""
echo -e "${BLUE}[*] Installed tools:${NC}"
echo -e "    • RustScan - Fast port scanner"
echo -e "    • Nmap - Network mapper"
echo -e "    • Feroxbuster - Web directory brute forcer"
echo -e "    • dirb - Web directory scanner (fallback)"
echo -e "    • enum4linux - SMB enumeration"
echo -e "    • smbclient - SMB client"
echo -e "    • Impacket - AD enumeration tools"
echo -e "    • SecLists - Comprehensive wordlists"
echo -e "    • And many more..."
echo ""
echo -e "${PURPLE}[*] Example usage:${NC}"
echo -e "${CYAN}    ./recon_tool.py 192.168.1.100${NC}"
echo -e "${CYAN}    ./recon_tool.py example.com --skip-web${NC}"
echo -e "${CYAN}    ./recon_tool.py 10.10.10.10 --skip-rustscan --threads 100${NC}"
