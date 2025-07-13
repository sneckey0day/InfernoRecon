#!/usr/bin/env python3
"""
Fast Parallel Reconnaissance Framework
Real-time results with immediate enumeration
"""

import threading
import subprocess
import queue
import time
import json
import os
import re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Enhanced Colors and Theme
class Colors:
    # Basic Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Bright Colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_PURPLE = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'
    BRIGHT_WHITE = '\033[1;97m'
    
    # Background Colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    
    # Text Styles
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    
    # Reset
    END = '\033[0m'

class FastRecon:
    def __init__(self, target, sound_alerts=True):
        self.target = target
        self.sound_alerts = sound_alerts
        self.output_dir = f"advanced_recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results_queue = queue.Queue()
        self.open_ports = set()
        self.web_ports = set()
        self.ftp_ports = set()
        self.smb_ports = set()
        self.found_urls = set()
        self.credentials = []
        self.active_tasks = 0
        
        # New additions for exploit discovery
        self.discovered_technologies = set()
        self.banner_info = []
        self.exploit_results = []
        self.tested_exploits = set()
        
        # Enhanced features
        self.database_ports = set()
        self.advanced_creds = []
        self.screenshots = []
        self.ad_ports = set()  # Active Directory ports
        self.domain_info = {}  # Domain information
        self.ad_users = []
        self.ad_computers = []
        
        # Create output directory and tmp directory
        Path(self.output_dir).mkdir(exist_ok=True)
        self.tmp_dir = os.path.join(self.output_dir, "tmp")
        Path(self.tmp_dir).mkdir(exist_ok=True)
        
        # Start result printer
        self.printer_thread = threading.Thread(target=self.result_printer, daemon=True)
        self.printer_thread.start()
        
        self.log_result(f"Advanced reconnaissance started on {target}", "INFO")

    def play_sound_alert(self, alert_type="default"):
        """Play sound alerts for critical findings"""
        if not self.sound_alerts:
            return
            
        try:
            import os
            import platform
            
            # Different sounds for different alert types
            if platform.system() == "Linux":
                if alert_type == "critical":
                    os.system("paplay /usr/share/sounds/alsa/Front_Left.wav 2>/dev/null >/dev/null || beep -f 1000 -l 200 2>/dev/null >/dev/null || printf '\a' >/dev/null")
                elif alert_type == "exploit":
                    os.system("paplay /usr/share/sounds/alsa/Front_Right.wav 2>/dev/null >/dev/null || beep -f 1500 -l 300 2>/dev/null >/dev/null || printf '\a' >/dev/null")
                elif alert_type == "creds":
                    os.system("paplay /usr/share/sounds/alsa/Rear_Left.wav 2>/dev/null >/dev/null || beep -f 2000 -l 100 2>/dev/null >/dev/null || printf '\a' >/dev/null")
                else:
                    os.system("printf '\a' >/dev/null")  # Simple beep
            else:
                # Fallback for other systems - use sys.stdout.write instead of print
                import sys
                sys.stdout.write('\a')
                sys.stdout.flush()
                
        except Exception:
            pass

    def log_result(self, message, result_type="INFO", data=None):
        """Log results immediately"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_queue.put({
            'timestamp': timestamp,
            'type': result_type,
            'message': message,
            'data': data
        })

    def result_printer(self):
        """Print results in real-time"""
        while True:
            try:
                result = self.results_queue.get(timeout=1)
                
                # Color coding
                if result['type'] == 'CRITICAL':
                    color = Colors.RED + Colors.BOLD
                elif result['type'] == 'FOUND':
                    color = Colors.GREEN
                elif result['type'] == 'WARNING':
                    color = Colors.YELLOW
                else:
                    color = Colors.CYAN
                
                # Enhanced UI with emojis and sound alerts
                if result['type'] == 'CRITICAL':
                    print(f"[{result['timestamp']}] {color}🚨 [{result['type']}]{Colors.END} {result['message']}")
                    self.play_sound_alert("critical")
                elif result['type'] == 'EXPLOIT':
                    print(f"[{result['timestamp']}] {color}💥 [{result['type']}]{Colors.END} {result['message']}")
                    self.play_sound_alert("exploit")
                elif result['type'] == 'CREDS':
                    print(f"[{result['timestamp']}] {color}🔑 [{result['type']}]{Colors.END} {result['message']}")
                    self.play_sound_alert("creds")
                elif result['type'] == 'FOUND':
                    print(f"[{result['timestamp']}] {color}✅ [{result['type']}]{Colors.END} {result['message']}")
                elif result['type'] == 'TECH':
                    print(f"[{result['timestamp']}] {color}🔧 [{result['type']}]{Colors.END} {result['message']}")
                elif result['type'] == 'BANNER':
                    print(f"[{result['timestamp']}] {color}📋 [{result['type']}]{Colors.END} {result['message']}")
                else:
                    print(f"[{result['timestamp']}] {color}[{result['type']}]{Colors.END} {result['message']}")
                
                # Save critical findings immediately
                if result['type'] in ['CRITICAL', 'FOUND', 'CREDS', 'EXPLOIT', 'TECH', 'BANNER'] and result['data']:
                    self.save_finding(result)
                    
            except queue.Empty:
                continue

    def save_finding(self, result):
        """Save important findings immediately"""
        findings_file = os.path.join(self.output_dir, "live_findings.json")
        
        try:
            if os.path.exists(findings_file):
                with open(findings_file, 'r') as f:
                    findings = json.load(f)
            else:
                findings = []
            
            findings.append(result)
            
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=2)
        except:
            pass

    def run_command(self, cmd, timeout=30):
        """Run command with timeout"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result
        except:
            return None

    def port_scanner(self):
        """Fast port scanning"""
        self.active_tasks += 1
        self.log_result("Starting port discovery...", "INFO")
        
        # Quick scan of top ports
        cmd = ["nmap", "-T4", "--top-ports", "1000", "--open", self.target]
        result = self.run_command(cmd, 120)
        
        if result and result.returncode == 0:
            for line in result.stdout.split('\n'):
                if "/tcp" in line and "open" in line:
                    try:
                        port = int(line.split('/')[0])
                        service = line.split()[2] if len(line.split()) > 2 else "unknown"
                        
                        self.open_ports.add(port)
                        self.log_result(f"Port {port}/tcp open ({service})", "FOUND", 
                                      {'port': port, 'service': service})
                        
                        # Immediately start service enumeration and banner grabbing
                        self.start_service_enum(port, service)
                        self.banner_grab_async(port, service)
                        
                    except:
                        continue
        
        self.active_tasks -= 1

    def banner_grab_async(self, port, service):
        """Grab banners from services and detect technologies"""
        def banner_worker():
            try:
                banner_info = None
                
                # For HTTP services
                if "http" in service.lower() or port in [80, 443, 8080, 8443]:
                    banner_info = self.grab_http_banner(port)
                
                # For other services, try socket connection
                elif port not in [80, 443, 8080, 8443]:
                    banner_info = self.grab_generic_banner(port)
                
                if banner_info:
                    self.log_result(f"BANNER grabbed from port {port}: {banner_info[:80]}...", "BANNER",
                                  {'port': port, 'service': service, 'banner': banner_info})
                    
                    self.banner_info.append({
                        'port': port,
                        'service': service,
                        'banner': banner_info
                    })
                    
                    # Analyze banner for technology/version info
                    self.analyze_banner_for_tech(banner_info, port)
                    
            except Exception as e:
                pass
        
        threading.Thread(target=banner_worker, daemon=True).start()

    def grab_http_banner(self, port):
        """Grab HTTP banner and headers"""
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            
            banner_info = []
            
            # Server header
            if 'Server' in response.headers:
                banner_info.append(f"Server: {response.headers['Server']}")
            
            # X-Powered-By header
            if 'X-Powered-By' in response.headers:
                banner_info.append(f"X-Powered-By: {response.headers['X-Powered-By']}")
            
            # Other interesting headers
            interesting_headers = ['X-AspNet-Version', 'X-Generator', 'X-Drupal-Cache']
            for header in interesting_headers:
                if header in response.headers:
                    banner_info.append(f"{header}: {response.headers[header]}")
            
            return "; ".join(banner_info) if banner_info else None
            
        except:
            return None

    def grab_generic_banner(self, port):
        """Grab banner using socket"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # Send basic request based on service
            if port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            else:
                # Try HTTP request
                sock.send(b"GET / HTTP/1.0\\r\\n\\r\\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            return banner.strip() if banner else None
            
        except:
            return None

    def analyze_banner_for_tech(self, banner, port):
        """Analyze banner for technology and version information"""
        if not banner:
            return
            
        # Technology patterns with version extraction
        tech_patterns = {
            'Apache': r'Apache[/\\s]+([0-9.]+)',
            'Nginx': r'nginx[/\\s]+([0-9.]+)',
            'IIS': r'Microsoft-IIS[/\\s]+([0-9.]+)',
            'PHP': r'PHP[/\\s]+([0-9.]+)',
            'vsftpd': r'vsftpd[/\\s]+([0-9.]+)',
            'OpenSSH': r'OpenSSH[_/\\s]+([0-9.]+)',
            'HFS': r'HFS[/\\s]+([0-9.]+)',
            'Rejetto': r'Rejetto[/\\s]+([0-9.]+)',
            'ProFTPD': r'ProFTPD[/\\s]+([0-9.]+)',
            'FileZilla': r'FileZilla[/\\s]+([0-9.]+)',
            'Lighttpd': r'lighttpd[/\\s]+([0-9.]+)',
            'Tomcat': r'Tomcat[/\\s]+([0-9.]+)',
        }
        
        for tech_name, pattern in tech_patterns.items():
            try:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    
                    if version:
                        tech_version = f"{tech_name} {version}"
                        self.log_result(f"TECHNOLOGY detected: {tech_version}", "TECH",
                                      {'technology': tech_name, 'version': version, 'port': port})
                        
                        # Add to discovered technologies for exploit searching
                        self.discovered_technologies.add((tech_name, version))
                        
                        # Immediately search for exploits
                        threading.Thread(target=self.search_exploits_for_tech, 
                                       args=(tech_name, version), daemon=True).start()
                    else:
                        self.log_result(f"TECHNOLOGY detected: {tech_name} (version unknown)", "TECH",
                                      {'technology': tech_name, 'version': 'unknown', 'port': port})
                        
                        self.discovered_technologies.add((tech_name, 'unknown'))
                        threading.Thread(target=self.search_exploits_for_tech, 
                                       args=(tech_name, None), daemon=True).start()
                        
            except Exception as e:
                continue

    def start_service_enum(self, port, service):
        """Start service-specific enumeration immediately"""
        if "http" in service.lower() or port in [80, 443, 8080, 8443, 8000, 8888]:
            self.web_ports.add(port)
            threading.Thread(target=self.web_enum, args=(port,), daemon=True).start()
            
        elif "ftp" in service.lower() or port == 21:
            self.ftp_ports.add(port)
            threading.Thread(target=self.ftp_enum, args=(port,), daemon=True).start()
            
        elif "smb" in service.lower() or port in [139, 445]:
            self.smb_ports.add(port)
            threading.Thread(target=self.smb_enum, args=(port,), daemon=True).start()
        
        elif port in [1433, 3306, 5432, 1521, 27017, 6379, 5984]:  # Database ports
            self.database_ports.add(port)
            threading.Thread(target=self.database_enum, args=(port, service), daemon=True).start()
            
        elif port in [88, 389, 636, 3268, 3269, 53] or "ldap" in service.lower() or "kerberos" in service.lower():  # Active Directory ports
            self.ad_ports.add(port)
            threading.Thread(target=self.ad_enum, args=(port, service), daemon=True).start()

    def web_enum(self, port):
        """Immediate web enumeration"""
        self.active_tasks += 1
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{self.target}:{port}"
        
        self.log_result(f"Starting web enum on {base_url}", "INFO")
        
        # Test connectivity
        try:
            import requests
            response = requests.get(base_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                self.log_result(f"Web service active: {base_url}", "FOUND")
                
                # Start multiple parallel web tasks
                tasks = [
                    threading.Thread(target=self.quick_dir_scan, args=(base_url,), daemon=True),
                    threading.Thread(target=self.check_sensitive_files, args=(base_url,), daemon=True),
                    threading.Thread(target=self.analyze_page, args=(base_url, response.text), daemon=True),
                    threading.Thread(target=self.extract_links, args=(base_url, response.text), daemon=True)
                ]
                
                for task in tasks:
                    task.start()
                    
        except Exception as e:
            self.log_result(f"Web service unreachable: {base_url}", "WARNING")
        
        self.active_tasks -= 1

    def quick_dir_scan(self, base_url):
        """Quick directory enumeration"""
        self.active_tasks += 1
        common_dirs = [
            'admin', 'login', 'dashboard', 'api', 'config', 'backup',
            'uploads', 'files', 'data', 'test', 'dev', 'staging',
            'phpmyadmin', 'wp-admin', 'administrator', 'panel'
        ]
        
        for directory in common_dirs:
            try:
                import requests
                url = f"{base_url}/{directory}"
                response = requests.get(url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    self.log_result(f"Directory found: {url}", "FOUND", {'url': url})
                    self.found_urls.add(url)
                    
                    # Immediately analyze this directory
                    threading.Thread(target=self.analyze_page, 
                                   args=(url, response.text), daemon=True).start()
                    
            except:
                continue
        
        self.active_tasks -= 1

    def check_sensitive_files(self, base_url):
        """Check for sensitive files"""
        self.active_tasks += 1
        sensitive_files = [
            'robots.txt', '.env', 'config.php', 'wp-config.php',
            'backup.zip', 'database.sql', '.git/config', 'admin.php',
            'login.php', 'phpinfo.php', 'test.php', '.htaccess',
            'web.config', 'app.config', 'settings.py', 'config.json'
        ]
        
        for filename in sensitive_files:
            try:
                import requests
                url = f"{base_url}/{filename}"
                response = requests.get(url, timeout=3, verify=False)
                
                if response.status_code == 200 and len(response.text) > 10:
                    self.log_result(f"SENSITIVE FILE: {url}", "CRITICAL", 
                                  {'url': url, 'type': 'sensitive_file'})
                    
                    # Save file immediately
                    self.save_content(url, response.text, 'sensitive')
                    
                    # Analyze for credentials
                    self.find_credentials(response.text, url)
                    
            except:
                continue
        
        self.active_tasks -= 1

    def analyze_page(self, url, content):
        """Analyze page content for interesting info"""
        if not content or len(content) < 50:
            return
            
        self.active_tasks += 1
        
        # Find forms and inputs
        self.find_forms(url, content)
        
        # Find credentials
        self.find_credentials(content, url)
        
        # Find interesting patterns
        patterns = {
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'internal_ips': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
            'api_endpoints': r'["\']([^"\']*(?:api|rest)[^"\']*)["\']',
            'js_files': r'src=["\']([^"\']*\.js[^"\']*)["\']'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches[:3]:  # Limit results
                self.log_result(f"{pattern_name.upper()}: {match}", "FOUND", 
                              {'type': pattern_name, 'value': match, 'source': url})
        
        self.active_tasks -= 1

    def find_forms(self, url, content):
        """Find forms and input fields"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET')
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                input_types = [inp.get('type', 'text') for inp in inputs]
                
                if 'password' in input_types:
                    self.log_result(f"LOGIN FORM: {url} -> {action}", "CRITICAL",
                                  {'type': 'login_form', 'url': url, 'action': action})
                elif inputs:
                    self.log_result(f"Form found: {url} ({len(inputs)} inputs)", "FOUND",
                                  {'type': 'form', 'url': url, 'inputs': len(inputs)})
        except:
            pass

    def find_credentials(self, content, source):
        """Find credentials in content"""
        patterns = {
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s\n]{4,})["\']?',
            'username': r'(?i)(user|username|login)\s*[:=]\s*["\']?([^"\'\s\n]{3,})["\']?',
            'api_key': r'(?i)(api[_-]?key|token)\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
            'hash': r'\b[a-fA-F0-9]{32,128}\b',
            'private_key': r'-----BEGIN [A-Z ]+PRIVATE KEY-----'
        }
        
        for cred_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            for match in matches[:2]:  # Limit results
                if isinstance(match, tuple):
                    value = match[1] if len(match) > 1 else match[0]
                else:
                    value = match
                
                if len(value) > 3:  # Filter out short matches
                    self.log_result(f"CREDENTIAL: {cred_type} = {value[:30]}...", "CRITICAL",
                                  {'type': 'credential', 'cred_type': cred_type, 'value': value})
                    
                    self.credentials.append({
                        'type': cred_type,
                        'value': value,
                        'source': source
                    })

    def extract_links(self, base_url, content):
        """Extract and test internal links"""
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse
            
            soup = BeautifulSoup(content, 'html.parser')
            base_domain = urlparse(base_url).netloc
            
            links = soup.find_all(['a', 'script', 'link'])
            
            for link in links[:15]:  # Limit to prevent overload
                href = None
                if link.name == 'a' and link.get('href'):
                    href = link.get('href')
                elif link.name == 'script' and link.get('src'):
                    href = link.get('src')
                elif link.name == 'link' and link.get('href'):
                    href = link.get('href')
                
                if href and not href.startswith(('http://', 'https://', 'mailto:', 'tel:')):
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    
                    if parsed.netloc == base_domain and full_url not in self.found_urls:
                        self.found_urls.add(full_url)
                        
                        # Test URL immediately
                        threading.Thread(target=self.test_url, args=(full_url,), daemon=True).start()
        except:
            pass

    def test_url(self, url):
        """Test discovered URL"""
        try:
            import requests
            response = requests.get(url, timeout=5, verify=False)
            
            if response.status_code == 200 and len(response.text) > 500:
                # Check if it's not an error page
                error_indicators = ['not found', 'error', 'forbidden', 'access denied']
                if not any(indicator in response.text.lower() for indicator in error_indicators):
                    
                    self.log_result(f"Interesting URL: {url}", "FOUND", {'url': url})
                    
                    # Check for interesting file types
                    if any(ext in url.lower() for ext in ['.txt', '.log', '.bak', '.old', '.sql', '.config']):
                        self.log_result(f"INTERESTING FILE: {url}", "CRITICAL", {'type': 'file', 'url': url})
                        self.save_content(url, response.text, 'interesting_file')
                    
                    # Analyze content
                    self.find_credentials(response.text, url)
                    
                    # Enhanced technology detection from web content
                    self.enhanced_technology_detection(url, response.text)
        except:
            pass

    def search_exploits_for_tech(self, tech_name, version):
        """Search for exploits using searchsploit"""
        try:
            # Create different search variations
            search_terms = []
            
            if version:
                # With version
                search_terms.extend([
                    f"{tech_name} {version}",
                    f"{tech_name} v{version}",
                    f"{tech_name}{version}",
                    f"{tech_name} {version.split('.')[0]}",  # Major version only
                ])
            
            # Without version
            search_terms.extend([
                tech_name,
                tech_name.lower(),
            ])
            
            # Special cases for common technologies
            if tech_name.lower() == 'hfs':
                search_terms.extend(['rejetto', 'http file server', 'hfs 2', 'hfsv2'])
            elif tech_name.lower() == 'apache':
                search_terms.extend(['httpd', 'apache httpd'])
            elif tech_name.lower() == 'openssh':
                search_terms.extend(['ssh', 'openssh'])
            
            all_exploits = []
            
            for search_term in search_terms[:6]:  # Limit searches
                exploit_key = f"{tech_name}:{search_term}"
                if exploit_key not in self.tested_exploits:
                    self.tested_exploits.add(exploit_key)
                    
                    exploits = self.run_searchsploit(search_term)
                    if exploits:
                        all_exploits.extend(exploits)
            
            if all_exploits:
                # Remove duplicates
                unique_exploits = []
                seen_titles = set()
                for exploit in all_exploits:
                    if exploit['title'] not in seen_titles:
                        unique_exploits.append(exploit)
                        seen_titles.add(exploit['title'])
                
                self.log_result(f"EXPLOITS FOUND for {tech_name} {version or ''}: {len(unique_exploits)} exploits", "EXPLOIT",
                              {'technology': tech_name, 'version': version, 'exploits': unique_exploits[:5]})
                
                # Show top exploits
                for exploit in unique_exploits[:3]:
                    self.log_result(f"  -> {exploit['title']}", "EXPLOIT",
                                  {'exploit_title': exploit['title'], 'exploit_type': exploit.get('type', 'exploit')})
            
        except Exception as e:
            pass

    def run_searchsploit(self, search_term):
        """Run searchsploit command"""
        try:
            cmd = ["searchsploit", "-j", search_term]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result and result.returncode == 0:
                try:
                    # Parse JSON output
                    data = json.loads(result.stdout)
                    exploits = []
                    
                    if 'RESULTS_EXPLOIT' in data:
                        for exploit in data['RESULTS_EXPLOIT'][:10]:  # Limit results
                            exploits.append({
                                'title': exploit.get('Title', ''),
                                'path': exploit.get('Path', ''),
                                'type': exploit.get('Type', 'exploit')
                            })
                    
                    return exploits
                    
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    return self.parse_searchsploit_text(result.stdout)
            
            return []
            
        except Exception as e:
            return []

    def parse_searchsploit_text(self, output):
        """Parse searchsploit text output as fallback"""
        try:
            exploits = []
            lines = output.split('\n')
            
            for line in lines:
                if '|' in line and not line.startswith('-') and 'Exploit Title' not in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        title = parts[0].strip()
                        path = parts[1].strip() if len(parts) > 1 else ''
                        
                        if title and len(title) > 5:
                            exploits.append({
                                'title': title,
                                'path': path,
                                'type': 'exploit'
                            })
            
            return exploits[:10]
            
        except:
            return []

    def enhanced_technology_detection(self, url, content):
        """Enhanced technology detection from web content"""
        if not content:
            return
            
        # More comprehensive technology patterns (excluding JS libraries)
        tech_patterns = {
            # CMS Detection
            'WordPress': [
                r'wp-content',
                r'WordPress ([0-9.]+)',
                r'generator.*WordPress ([0-9.]+)'
            ],
            'Drupal': [
                r'Drupal\.settings',
                r'sites/default',
                r'Drupal ([0-9.]+)',
                r'generator.*Drupal ([0-9.]+)'
            ],
            'Joomla': [
                r'Joomla!',
                r'administrator/index\.php',
                r'Joomla! ([0-9.]+)',
                r'generator.*Joomla! ([0-9.]+)'
            ],
            
            # Web Servers (from HTML comments/headers)
            'Apache': [
                r'Apache/([0-9.]+)',
                r'Server: Apache/([0-9.]+)'
            ],
            'Nginx': [
                r'nginx/([0-9.]+)',
                r'Server: nginx/([0-9.]+)'
            ],
            'IIS': [
                r'Microsoft-IIS/([0-9.]+)',
                r'Server: Microsoft-IIS/([0-9.]+)'
            ],
            
            # Programming Languages
            'PHP': [
                r'PHP/([0-9.]+)',
                r'X-Powered-By: PHP/([0-9.]+)',
                r'PHPSESSID'
            ],
            'ASP.NET': [
                r'ASP\.NET Version:([0-9.]+)',
                r'X-AspNet-Version: ([0-9.]+)',
                r'__VIEWSTATE'
            ],
            
            # File Servers
            'HFS': [
                r'HttpFileServer ([0-9.]+)',
                r'HFS ([0-9.]+)',
                r'Rejetto.*([0-9.]+)',
                r'Http File Server'
            ],
            
            # Other Applications
            'phpMyAdmin': [
                r'phpMyAdmin ([0-9.]+)',
                r'pma_username'
            ],
            'Tomcat': [
                r'Apache Tomcat/([0-9.]+)',
                r'Tomcat/([0-9.]+)'
            ]
        }
        
        for tech_name, patterns in tech_patterns.items():
            for pattern in patterns:
                try:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = None
                        if match.groups():
                            version = match.group(1)
                        
                        tech_key = f"{tech_name}:{version or 'unknown'}"
                        if tech_key not in [f"{t[0]}:{t[1]}" for t in self.discovered_technologies]:
                            
                            if version:
                                self.log_result(f"TECHNOLOGY detected in content: {tech_name} {version}", "TECH",
                                              {'technology': tech_name, 'version': version, 'source': url})
                            else:
                                self.log_result(f"TECHNOLOGY detected in content: {tech_name}", "TECH",
                                              {'technology': tech_name, 'version': 'unknown', 'source': url})
                            
                            self.discovered_technologies.add((tech_name, version or 'unknown'))
                            threading.Thread(target=self.search_exploits_for_tech, 
                                           args=(tech_name, version), daemon=True).start()
                            
                            break  # Found this tech, move to next
                        
                except Exception as e:
                    continue

    def ftp_enum(self, port):
        """Enhanced FTP enumeration with comprehensive data download"""
        self.active_tasks += 1
        self.log_result(f"Testing FTP on port {port}", "INFO")
        
        # Create FTP directory structure
        ftp_dir = os.path.join(self.output_dir, f"ftp_{port}")
        Path(ftp_dir).mkdir(exist_ok=True)
        
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.target, port, timeout=10)
            ftp.login('anonymous', 'anonymous@domain.com')
            
            self.log_result(f"FTP ANONYMOUS ACCESS: port {port}", "CRITICAL",
                          {'type': 'ftp_anonymous', 'port': port})
            
            # Get detailed directory listing
            files_and_dirs = []
            try:
                # Try to get detailed listing
                ftp.retrlines('LIST', files_and_dirs.append)
            except:
                # Fallback to simple listing
                try:
                    simple_files = ftp.nlst()
                    files_and_dirs = [f"- {f}" for f in simple_files]
                except:
                    files_and_dirs = []
            
            if files_and_dirs:
                self.log_result(f"FTP directory listing: {len(files_and_dirs)} items found", "FOUND", 
                              {'items': files_and_dirs[:10]})
                
                # Parse and download files
                downloaded_count = self.download_ftp_contents(ftp, "/", ftp_dir, depth=0)
                
                if downloaded_count > 0:
                    self.log_result(f"Downloaded {downloaded_count} files from FTP", "CRITICAL",
                                  {'port': port, 'downloaded': downloaded_count})
                    
                    # Analyze downloaded files
                    threading.Thread(target=self.analyze_ftp_files, args=(ftp_dir,), daemon=True).start()
            
            ftp.quit()
            
        except Exception as e:
            # Try common credential combinations
            self.try_ftp_credentials(port, ftp_dir)
        
        self.active_tasks -= 1

    def download_ftp_contents(self, ftp, remote_path, local_dir, depth=0, max_depth=3):
        """Recursively download FTP contents"""
        if depth > max_depth:
            return 0
            
        downloaded_count = 0
        
        try:
            # Change to remote directory
            if remote_path != "/":
                ftp.cwd(remote_path)
            
            # Get directory listing
            items = []
            try:
                ftp.retrlines('LIST', items.append)
            except:
                return 0
            
            for item in items[:20]:  # Limit items per directory
                try:
                    # Parse LIST output
                    parts = item.split()
                    if len(parts) < 9:
                        continue
                        
                    permissions = parts[0]
                    filename = ' '.join(parts[8:])  # Handle filenames with spaces
                    
                    if filename in ['.', '..']:
                        continue
                    
                    # Create safe local filename
                    safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.')).rstrip()
                    if not safe_filename:
                        safe_filename = f"unknown_file_{downloaded_count}"
                    
                    if permissions.startswith('d'):  # Directory
                        # Create local directory and recurse
                        subdir_path = os.path.join(local_dir, safe_filename)
                        Path(subdir_path).mkdir(exist_ok=True)
                        
                        # Save current directory
                        current_dir = ftp.pwd()
                        
                        try:
                            # Recursively download subdirectory
                            sub_downloaded = self.download_ftp_contents(ftp, filename, subdir_path, depth + 1, max_depth)
                            downloaded_count += sub_downloaded
                            
                            # Return to parent directory
                            ftp.cwd(current_dir)
                            
                        except Exception as e:
                            # Return to parent directory on error
                            try:
                                ftp.cwd(current_dir)
                            except:
                                pass
                    
                    else:  # Regular file
                        local_path = os.path.join(local_dir, safe_filename)
                        
                        try:
                            with open(local_path, 'wb') as f:
                                ftp.retrbinary(f'RETR {filename}', f.write)
                            
                            if os.path.exists(local_path):
                                file_size = os.path.getsize(local_path)
                                self.log_result(f"Downloaded FTP file: {filename} ({file_size} bytes)", "FOUND",
                                              {'file': filename, 'size': file_size, 'path': remote_path})
                                downloaded_count += 1
                                
                                # Skip very large files for analysis
                                if file_size > 10 * 1024 * 1024:  # 10MB limit
                                    continue
                        
                        except Exception as e:
                            # Clean up failed download
                            if os.path.exists(local_path):
                                os.remove(local_path)
                
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return downloaded_count

    def try_ftp_credentials(self, port, ftp_dir):
        """Try common FTP credentials"""
        common_creds = [
            ('ftp', 'ftp'),
            ('admin', 'admin'),
            ('admin', ''),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('ftpuser', 'ftpuser')
        ]
        
        for username, password in common_creds:
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(self.target, port, timeout=5)
                ftp.login(username, password)
                
                self.log_result(f"FTP VALID CREDENTIALS: {username}:{password}", "CRITICAL",
                              {'type': 'ftp_creds', 'username': username, 'password': password, 'port': port})
                
                # Download files with valid credentials
                downloaded_count = self.download_ftp_contents(ftp, "/", ftp_dir, depth=0)
                if downloaded_count > 0:
                    threading.Thread(target=self.analyze_ftp_files, args=(ftp_dir,), daemon=True).start()
                
                ftp.quit()
                return
                
            except Exception as e:
                continue

    def analyze_ftp_files(self, ftp_dir):
        """Analyze downloaded FTP files for interesting content"""
        self.active_tasks += 1
        
        try:
            for root, dirs, files in os.walk(ftp_dir):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip large files to prevent memory issues
                    if os.path.getsize(filepath) > 1024 * 1024:  # Skip files > 1MB
                        continue
                    
                    try:
                        # Try to read as text
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(10000)  # Read first 10KB
                        
                        # Look for credentials and sensitive information
                        self.find_credentials(content, f"ftp://{os.path.basename(filepath)}")
                        
                        # Look for interesting file types
                        if any(ext in filename.lower() for ext in ['.txt', '.log', '.conf', '.config', '.ini', '.xml', '.sql', '.bak']):
                            self.log_result(f"Interesting FTP file: {filename}", "FOUND",
                                          {'type': 'interesting_ftp_file', 'file': filename})
                        
                        # Look for specific patterns
                        if any(keyword in content.lower() for keyword in ['password', 'secret', 'key', 'token', 'credential']):
                            self.log_result(f"FTP file contains sensitive keywords: {filename}", "CRITICAL",
                                          {'type': 'sensitive_ftp_file', 'file': filename})
                        
                        # Look for database dumps
                        if any(keyword in content.lower() for keyword in ['insert into', 'create table', 'drop table']):
                            self.log_result(f"FTP file appears to be database dump: {filename}", "CRITICAL",
                                          {'type': 'database_dump', 'file': filename})
                    
                    except Exception as e:
                        # Try binary analysis for specific file types
                        if filename.lower().endswith(('.doc', '.docx', '.pdf', '.xls', '.xlsx', '.zip', '.rar')):
                            self.log_result(f"Found document/archive file: {filename}", "FOUND",
                                          {'type': 'document_archive', 'file': filename})
        
        except Exception as e:
            pass
        
        self.active_tasks -= 1

    def smb_enum(self, port):
        """SMB enumeration with data download"""
        self.active_tasks += 1
        self.log_result(f"Testing SMB on port {port}", "INFO")
        
        # Create SMB directory structure
        smb_dir = os.path.join(self.output_dir, f"smb_{port}")
        Path(smb_dir).mkdir(exist_ok=True)
        
        # Test null session
        cmd = ["smbclient", "-L", self.target, "-N", "-p", str(port)]
        result = self.run_command(cmd, 30)
        
        if result and result.returncode == 0 and "Sharename" in result.stdout:
            self.log_result(f"SMB NULL SESSION: port {port}", "CRITICAL",
                          {'type': 'smb_null', 'port': port})
            
            # Parse shares
            shares = []
            for line in result.stdout.split('\n'):
                if "Disk" in line or "IPC" in line:
                    try:
                        share_name = line.split()[0]
                        shares.append(share_name)
                        self.log_result(f"SMB share: {share_name}", "FOUND", {'share': share_name})
                    except:
                        continue
            
            # Download data from accessible shares
            for share in shares:
                if share and share not in ['IPC$', 'ADMIN$']:  # Skip administrative shares
                    threading.Thread(target=self.download_smb_share, 
                                   args=(share, port, smb_dir), daemon=True).start()
        else:
            self.log_result(f"SMB null session failed on port {port}", "INFO")
        
        self.active_tasks -= 1

    def download_smb_share(self, share_name, port, smb_dir):
        """Download files from SMB share"""
        self.active_tasks += 1
        self.log_result(f"Attempting to download from SMB share: {share_name}", "INFO")
        
        # Create directory for this share
        share_dir = os.path.join(smb_dir, share_name.replace('$', '_dollar'))
        Path(share_dir).mkdir(exist_ok=True)
        
        try:
            # First, try to list files in the share
            cmd = ["smbclient", f"//{self.target}/{share_name}", "-N", "-p", str(port), "-c", "ls"]
            result = self.run_command(cmd, 30)
            
            if result and result.returncode == 0:
                self.log_result(f"SMB share {share_name} is accessible", "FOUND", 
                              {'share': share_name, 'accessible': True})
                
                # Parse file listing
                files_to_download = []
                directories = []
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('.') and not line.startswith('\\'):
                        # Parse smbclient ls output
                        parts = line.split()
                        if len(parts) >= 1:
                            filename = parts[0]
                            if filename and filename not in ['.', '..']:
                                # Check if it's a directory (contains 'D' attribute)
                                if 'D' in line:
                                    directories.append(filename)
                                else:
                                    files_to_download.append(filename)
                
                self.log_result(f"Found {len(files_to_download)} files and {len(directories)} directories in {share_name}", 
                              "FOUND", {'share': share_name, 'files': len(files_to_download), 'dirs': len(directories)})
                
                # Download files (limit to prevent overwhelming)
                downloaded_count = 0
                for filename in files_to_download[:20]:  # Limit to 20 files per share
                    if self.download_smb_file(share_name, filename, port, share_dir):
                        downloaded_count += 1
                
                # Explore directories (limited depth)
                for dirname in directories[:5]:  # Limit to 5 directories
                    self.explore_smb_directory(share_name, dirname, port, share_dir, depth=1)
                
                if downloaded_count > 0:
                    self.log_result(f"Downloaded {downloaded_count} files from SMB share {share_name}", 
                                  "CRITICAL", {'share': share_name, 'downloaded': downloaded_count})
                    
                    # Analyze downloaded files for credentials
                    threading.Thread(target=self.analyze_smb_files, args=(share_dir,), daemon=True).start()
                
            else:
                self.log_result(f"SMB share {share_name} not accessible or empty", "INFO")
                
        except Exception as e:
            self.log_result(f"Error accessing SMB share {share_name}: {str(e)}", "WARNING")
        
        self.active_tasks -= 1

    def download_smb_file(self, share_name, filename, port, share_dir):
        """Download a single file from SMB share"""
        try:
            # Sanitize filename for local storage
            safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.')).rstrip()
            if not safe_filename:
                safe_filename = "unknown_file"
            
            local_path = os.path.join(share_dir, safe_filename)
            
            # Use smbclient to download the file
            cmd = ["smbclient", f"//{self.target}/{share_name}", "-N", "-p", str(port), 
                   "-c", f"get \"{filename}\" \"{local_path}\""]
            
            result = self.run_command(cmd, 60)  # Longer timeout for file downloads
            
            if result and result.returncode == 0 and os.path.exists(local_path):
                file_size = os.path.getsize(local_path)
                self.log_result(f"Downloaded SMB file: {filename} ({file_size} bytes)", "FOUND",
                              {'share': share_name, 'file': filename, 'size': file_size})
                return True
            else:
                # Clean up failed download
                if os.path.exists(local_path):
                    os.remove(local_path)
                return False
                
        except Exception as e:
            return False

    def explore_smb_directory(self, share_name, dirname, port, share_dir, depth=1, max_depth=2):
        """Explore SMB directory recursively (limited depth)"""
        if depth > max_depth:
            return
            
        try:
            # Create local directory
            local_dir = os.path.join(share_dir, dirname.replace('/', '_').replace('\\', '_'))
            Path(local_dir).mkdir(exist_ok=True)
            
            # List files in directory
            cmd = ["smbclient", f"//{self.target}/{share_name}", "-N", "-p", str(port), 
                   "-c", f"cd \"{dirname}\"; ls"]
            
            result = self.run_command(cmd, 30)
            
            if result and result.returncode == 0:
                files_in_dir = []
                subdirs = []
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('.') and not line.startswith('\\'):
                        parts = line.split()
                        if len(parts) >= 1:
                            item_name = parts[0]
                            if item_name and item_name not in ['.', '..']:
                                if 'D' in line:
                                    subdirs.append(item_name)
                                else:
                                    files_in_dir.append(item_name)
                
                # Download files from this directory (limited)
                for filename in files_in_dir[:10]:  # Limit files per directory
                    remote_path = f"{dirname}/{filename}"
                    self.download_smb_file_with_path(share_name, remote_path, port, local_dir, filename)
                
                # Recursively explore subdirectories (limited)
                for subdir in subdirs[:3]:  # Limit subdirectories
                    subdir_path = f"{dirname}/{subdir}"
                    self.explore_smb_directory(share_name, subdir_path, port, share_dir, depth + 1, max_depth)
                    
        except Exception as e:
            pass

    def download_smb_file_with_path(self, share_name, remote_path, port, local_dir, filename):
        """Download file with full remote path"""
        try:
            safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.')).rstrip()
            if not safe_filename:
                safe_filename = "unknown_file"
                
            local_path = os.path.join(local_dir, safe_filename)
            
            cmd = ["smbclient", f"//{self.target}/{share_name}", "-N", "-p", str(port), 
                   "-c", f"get \"{remote_path}\" \"{local_path}\""]
            
            result = self.run_command(cmd, 60)
            
            if result and result.returncode == 0 and os.path.exists(local_path):
                file_size = os.path.getsize(local_path)
                self.log_result(f"Downloaded: {remote_path} ({file_size} bytes)", "FOUND",
                              {'share': share_name, 'file': remote_path, 'size': file_size})
                return True
            else:
                if os.path.exists(local_path):
                    os.remove(local_path)
                return False
                
        except Exception as e:
            return False

    def analyze_smb_files(self, share_dir):
        """Analyze downloaded SMB files for interesting content"""
        self.active_tasks += 1
        
        try:
            for root, dirs, files in os.walk(share_dir):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip large files to prevent memory issues
                    if os.path.getsize(filepath) > 1024 * 1024:  # Skip files > 1MB
                        continue
                    
                    try:
                        # Try to read as text
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(10000)  # Read first 10KB
                        
                        # Look for credentials and sensitive information
                        self.find_credentials(content, f"smb://{os.path.basename(filepath)}")
                        
                        # Look for interesting file types
                        if any(ext in filename.lower() for ext in ['.txt', '.log', '.conf', '.config', '.ini', '.xml']):
                            self.log_result(f"Interesting SMB file: {filename}", "FOUND",
                                          {'type': 'interesting_smb_file', 'file': filename})
                        
                        # Look for specific patterns
                        if any(keyword in content.lower() for keyword in ['password', 'secret', 'key', 'token', 'credential']):
                            self.log_result(f"SMB file contains sensitive keywords: {filename}", "CRITICAL",
                                          {'type': 'sensitive_smb_file', 'file': filename})
                    
                    except Exception as e:
                        # Try binary analysis for specific file types
                        if filename.lower().endswith(('.doc', '.docx', '.pdf', '.xls', '.xlsx')):
                            self.log_result(f"Found document file: {filename}", "FOUND",
                                          {'type': 'document', 'file': filename})
        
        except Exception as e:
            pass
        
        self.active_tasks -= 1

    def analyze_file(self, filepath):
        """Analyze downloaded files"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(5000)  # Read first 5KB
            
            self.find_credentials(content, f"file://{os.path.basename(filepath)}")
            
        except:
            pass

    def save_content(self, url, content, content_type):
        """Save content immediately"""
        try:
            import hashlib
            filename = f"{content_type}_{hashlib.md5(url.encode()).hexdigest()[:8]}.html"
            filepath = os.path.join(self.tmp_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"<!-- Source: {url} -->\n")
                f.write(content)
            
        except:
            pass

    def test_credentials(self):
        """Test found credentials"""
        if not self.credentials:
            return
            
        self.log_result(f"Testing {len(self.credentials)} credentials", "INFO")
        
        usernames = [c['value'] for c in self.credentials if c['type'] == 'username']
        passwords = [c['value'] for c in self.credentials if c['type'] == 'password']
        
        if usernames and passwords:
            # Test FTP
            for ftp_port in list(self.ftp_ports)[:2]:
                threading.Thread(target=self.test_ftp_creds, 
                               args=(usernames[:3], passwords[:3], ftp_port), daemon=True).start()

    def test_ftp_creds(self, usernames, passwords, port):
        """Test credentials against FTP"""
        for username in usernames:
            for password in passwords:
                try:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(self.target, port, timeout=5)
                    ftp.login(username, password)
                    
                    self.log_result(f"VALID FTP CREDS: {username}:{password}", "CRITICAL",
                                  {'service': 'FTP', 'username': username, 'password': password})
                    
                    ftp.quit()
                    return
                except:
                    continue

    def run(self, timeout=300):
        """Run fast reconnaissance"""
        start_time = time.time()
        
        # Start port scanning
        threading.Thread(target=self.port_scanner, daemon=True).start()
        
        # Monitor and test credentials periodically
        last_cred_test = 0
        
        while time.time() - start_time < timeout:
            time.sleep(2)
            
            # Test credentials every 30 seconds if we have some
            if time.time() - last_cred_test > 30 and self.credentials:
                threading.Thread(target=self.test_credentials, daemon=True).start()
                last_cred_test = time.time()
        
        # Wait for remaining tasks
        while self.active_tasks > 0:
            time.sleep(1)
            if time.time() - start_time > timeout + 30:  # Extra 30 seconds
                break
        
        self.log_result("Reconnaissance completed", "INFO")
        
        # Clean up temporary files
        self.cleanup_tmp_files()
        return {
            'open_ports': len(self.open_ports),
            'web_services': len(self.web_ports),
            'urls_found': len(self.found_urls),
            'credentials': len(self.credentials),
            'technologies': len(self.discovered_technologies),
            'banners': len(self.banner_info),
            'exploits': len(self.exploit_results),
            'databases': len(self.database_ports)
        }

    def database_enum(self, port, service):
        """Database enumeration"""
        self.active_tasks += 1
        self.log_result(f"Testing database on port {port}", "INFO")
        
        db_type = self.identify_database_type(port, service)
        
        if db_type == "MySQL":
            self.test_mysql(port)
        elif db_type == "PostgreSQL":
            self.test_postgresql(port)
        elif db_type == "Redis":
            self.test_redis(port)
        elif db_type == "MongoDB":
            self.test_mongodb(port)
        else:
            self.test_generic_database(port, db_type)
        
        self.active_tasks -= 1

    def identify_database_type(self, port, service):
        """Identify database type"""
        db_map = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}
        return db_map.get(port, "Unknown")

    def test_redis(self, port):
        """Test Redis database"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            sock.send(b"*1\\r\\n$4\\r\\nPING\\r\\n")
            response = sock.recv(1024)
            
            if b"PONG" in response:
                self.log_result(f"Redis service active on port {port} - NO AUTH!", "CRITICAL",
                              {'port': port, 'service': 'Redis'})
                self.play_sound_alert("critical")
            
            sock.close()
        except:
            pass

    def test_mysql(self, port):
        """Test MySQL database"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            data = sock.recv(1024)
            if data:
                self.log_result(f"MySQL service detected on port {port}", "FOUND", 
                              {'port': port, 'service': 'MySQL'})
            sock.close()
        except:
            pass

    def test_postgresql(self, port):
        """Test PostgreSQL database"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            self.log_result(f"PostgreSQL service detected on port {port}", "FOUND",
                          {'port': port, 'service': 'PostgreSQL'})
            sock.close()
        except:
            pass

    def test_mongodb(self, port):
        """Test MongoDB database"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            self.log_result(f"MongoDB service detected on port {port}", "FOUND",
                          {'port': port, 'service': 'MongoDB'})
            sock.close()
        except:
            pass

    def test_generic_database(self, port, db_type):
        """Test generic database"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            self.log_result(f"{db_type} database detected on port {port}", "FOUND",
                          {'port': port, 'service': db_type})
            sock.close()
        except:
            pass

    def ad_enum(self, port, service):
        """Active Directory enumeration"""
        self.active_tasks += 1
        self.log_result(f"Testing Active Directory on port {port}", "INFO")
        
        # Create AD directory structure
        ad_dir = os.path.join(self.output_dir, f"ad_{port}")
        Path(ad_dir).mkdir(exist_ok=True)
        
        # Identify AD service type
        if port == 88 or "kerberos" in service.lower():
            self.kerberos_enum(port, ad_dir)
        elif port in [389, 636] or "ldap" in service.lower():
            self.ldap_enum(port, ad_dir)
        elif port == 53:
            self.dns_enum_for_ad(port, ad_dir)
        elif port in [3268, 3269]:
            self.global_catalog_enum(port, ad_dir)
        
        self.active_tasks -= 1

    def ldap_enum(self, port, ad_dir):
        """LDAP enumeration for Active Directory"""
        self.log_result(f"Starting LDAP enumeration on port {port}", "INFO")
        
        try:
            # Test anonymous LDAP bind
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{self.target}:{port}", "-s", "base", "namingcontexts"]
            result = self.run_command(cmd, 30)
            
            if result and result.returncode == 0:
                self.log_result(f"LDAP ANONYMOUS BIND successful on port {port}", "CRITICAL",
                              {'type': 'ldap_anonymous', 'port': port})
                
                # Extract domain information
                domain_info = self.extract_domain_info(result.stdout)
                if domain_info:
                    self.domain_info.update(domain_info)
                    self.log_result(f"Domain discovered: {domain_info.get('domain', 'Unknown')}", "CRITICAL",
                                  {'type': 'domain_info', 'domain': domain_info})
                
                # Save LDAP output
                ldap_file = os.path.join(ad_dir, "ldap_base_info.txt")
                with open(ldap_file, 'w') as f:
                    f.write(result.stdout)
                
                # Enumerate users and computers
                threading.Thread(target=self.enumerate_ad_users, args=(port, ad_dir), daemon=True).start()
                threading.Thread(target=self.enumerate_ad_computers, args=(port, ad_dir), daemon=True).start()
                
            else:
                self.log_result(f"LDAP anonymous bind failed on port {port}", "INFO")
                
        except Exception as e:
            self.log_result(f"LDAP enumeration error: {str(e)}", "WARNING")

    def kerberos_enum(self, port, ad_dir):
        """Kerberos enumeration"""
        self.log_result(f"Starting Kerberos enumeration on port {port}", "INFO")
        
        try:
            # Test if Kerberos is responding
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                self.log_result(f"Kerberos service active on port {port}", "FOUND",
                              {'type': 'kerberos_active', 'port': port})
                
                # Try to get realm information using nmap
                cmd = ["nmap", "-p", str(port), "--script", "krb5-enum-users", self.target]
                result = self.run_command(cmd, 60)
                
                if result and result.returncode == 0:
                    kerberos_file = os.path.join(ad_dir, "kerberos_info.txt")
                    with open(kerberos_file, 'w') as f:
                        f.write(result.stdout)
                    
                    # Extract realm information
                    if "Kerberos" in result.stdout:
                        self.log_result("Kerberos realm information discovered", "FOUND",
                                      {'type': 'kerberos_realm'})
            
        except Exception as e:
            self.log_result(f"Kerberos enumeration error: {str(e)}", "WARNING")

    def dns_enum_for_ad(self, port, ad_dir):
        """DNS enumeration for Active Directory discovery"""
        self.log_result(f"Starting DNS enumeration for AD on port {port}", "INFO")
        
        try:
            # Try to discover domain controllers via DNS
            dns_queries = [
                "_ldap._tcp.dc._msdcs",
                "_kerberos._tcp.dc._msdcs", 
                "_gc._tcp",
                "_ldap._tcp"
            ]
            
            for query in dns_queries:
                cmd = ["nslookup", "-type=SRV", f"{query}.{self.target}", self.target]
                result = self.run_command(cmd, 15)
                
                if result and result.returncode == 0 and "service" in result.stdout.lower():
                    self.log_result(f"AD DNS record found: {query}", "CRITICAL",
                                  {'type': 'ad_dns_record', 'query': query})
                    
                    # Save DNS results
                    dns_file = os.path.join(ad_dir, f"dns_{query.replace('.', '_')}.txt")
                    with open(dns_file, 'w') as f:
                        f.write(result.stdout)
            
        except Exception as e:
            self.log_result(f"DNS AD enumeration error: {str(e)}", "WARNING")

    def enumerate_ad_users(self, port, ad_dir):
        """Enumerate Active Directory users"""
        self.active_tasks += 1
        
        try:
            # Get domain base DN
            base_dn = self.domain_info.get('base_dn', '')
            if not base_dn:
                base_dn = f"DC={self.target.replace('.', ',DC=')}"
            
            # Search for users
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{self.target}:{port}", 
                   "-b", base_dn, "(objectClass=user)", "sAMAccountName", "cn", "mail"]
            result = self.run_command(cmd, 60)
            
            if result and result.returncode == 0:
                users = self.parse_ldap_users(result.stdout)
                if users:
                    self.ad_users.extend(users)
                    self.log_result(f"Found {len(users)} AD users", "CRITICAL",
                                  {'type': 'ad_users', 'count': len(users), 'users': users[:10]})
                    
                    # Save users to file
                    users_file = os.path.join(ad_dir, "ad_users.txt")
                    with open(users_file, 'w') as f:
                        for user in users:
                            f.write(f"{user}\n")
                    
                    # Save detailed LDAP output
                    users_detail_file = os.path.join(ad_dir, "ad_users_detailed.txt")
                    with open(users_detail_file, 'w') as f:
                        f.write(result.stdout)
            
        except Exception as e:
            self.log_result(f"AD user enumeration error: {str(e)}", "WARNING")
        
        self.active_tasks -= 1

    def enumerate_ad_computers(self, port, ad_dir):
        """Enumerate Active Directory computers"""
        self.active_tasks += 1
        
        try:
            # Get domain base DN
            base_dn = self.domain_info.get('base_dn', '')
            if not base_dn:
                base_dn = f"DC={self.target.replace('.', ',DC=')}"
            
            # Search for computers
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{self.target}:{port}", 
                   "-b", base_dn, "(objectClass=computer)", "cn", "dNSHostName", "operatingSystem"]
            result = self.run_command(cmd, 60)
            
            if result and result.returncode == 0:
                computers = self.parse_ldap_computers(result.stdout)
                if computers:
                    self.ad_computers.extend(computers)
                    self.log_result(f"Found {len(computers)} AD computers", "FOUND",
                                  {'type': 'ad_computers', 'count': len(computers), 'computers': computers[:10]})
                    
                    # Save computers to file
                    computers_file = os.path.join(ad_dir, "ad_computers.txt")
                    with open(computers_file, 'w') as f:
                        for computer in computers:
                            f.write(f"{computer}\n")
                    
                    # Save detailed LDAP output
                    computers_detail_file = os.path.join(ad_dir, "ad_computers_detailed.txt")
                    with open(computers_detail_file, 'w') as f:
                        f.write(result.stdout)
            
        except Exception as e:
            self.log_result(f"AD computer enumeration error: {str(e)}", "WARNING")
        
        self.active_tasks -= 1

    def extract_domain_info(self, ldap_output):
        """Extract domain information from LDAP output"""
        domain_info = {}
        
        try:
            lines = ldap_output.split('\n')
            for line in lines:
                if 'namingcontexts:' in line.lower():
                    dn = line.split(':', 1)[1].strip()
                    if dn.startswith('DC='):
                        domain_parts = []
                        for part in dn.split(','):
                            if part.strip().startswith('DC='):
                                domain_parts.append(part.strip()[3:])
                        
                        if domain_parts:
                            domain_info['domain'] = '.'.join(domain_parts)
                            domain_info['base_dn'] = dn
                            break
            
        except Exception as e:
            pass
        
        return domain_info

    def parse_ldap_users(self, ldap_output):
        """Parse LDAP output to extract usernames"""
        users = []
        
        try:
            lines = ldap_output.split('\n')
            current_user = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('sAMAccountName:'):
                    username = line.split(':', 1)[1].strip()
                    if username and username not in ['$', 'krbtgt']:
                        users.append(username)
                        
        except Exception as e:
            pass
        
        return list(set(users))  # Remove duplicates

    def parse_ldap_computers(self, ldap_output):
        """Parse LDAP output to extract computer names"""
        computers = []
        
        try:
            lines = ldap_output.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('cn:'):
                    computer = line.split(':', 1)[1].strip()
                    if computer and not computer.endswith('$'):
                        computers.append(computer)
                elif line.startswith('dNSHostName:'):
                    hostname = line.split(':', 1)[1].strip()
                    if hostname:
                        computers.append(hostname)
                        
        except Exception as e:
            pass
        
        return list(set(computers))  # Remove duplicates

    def global_catalog_enum(self, port, ad_dir):
        """Global Catalog enumeration"""
        self.log_result(f"Starting Global Catalog enumeration on port {port}", "INFO")
        
        try:
            # Test Global Catalog connection
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{self.target}:{port}", "-s", "base", "supportedCapabilities"]
            result = self.run_command(cmd, 30)
            
            if result and result.returncode == 0:
                self.log_result(f"Global Catalog accessible on port {port}", "FOUND",
                              {'type': 'global_catalog', 'port': port})
                
                # Save GC info
                gc_file = os.path.join(ad_dir, "global_catalog_info.txt")
                with open(gc_file, 'w') as f:
                    f.write(result.stdout)
            
        except Exception as e:
            self.log_result(f"Global Catalog enumeration error: {str(e)}", "WARNING")

    def cleanup_tmp_files(self):
        """Clean up temporary files"""
        try:
            import shutil
            if os.path.exists(self.tmp_dir):
                # Move important files to main output directory before cleanup
                for filename in os.listdir(self.tmp_dir):
                    if filename.endswith(('.txt', '.json', '.html')):
                        src = os.path.join(self.tmp_dir, filename)
                        dst = os.path.join(self.output_dir, filename)
                        shutil.move(src, dst)
                
                # Remove empty tmp directory
                shutil.rmtree(self.tmp_dir, ignore_errors=True)
                self.log_result("Temporary files cleaned up", "INFO")
        except Exception as e:
            pass

def main():
    import argparse
    
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                FAST PARALLEL RECON v2.0                     ║
║              Real-time Results & Enumeration                ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}[*] Lightning fast reconnaissance with immediate results{Colors.END}
""")
    
    parser = argparse.ArgumentParser(description="Advanced Parallel Reconnaissance Framework")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--timeout", type=int, default=300, help="Scan timeout in seconds (default: 300)")
    parser.add_argument("--no-sound", action="store_true", help="Disable sound alerts")
    parser.add_argument("--database-enum", action="store_true", help="Enable database enumeration")
    parser.add_argument("--advanced-creds", action="store_true", help="Enable advanced credential testing")
    
    args = parser.parse_args()
    
    print(f"{Colors.GREEN}[+] Target: {args.target}{Colors.END}")
    print(f"{Colors.GREEN}[+] Timeout: {args.timeout} seconds{Colors.END}")
    print(f"{Colors.YELLOW}[*] Results appear in real-time below...{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    
    try:
        # Initialize with sound alerts option
        sound_enabled = not args.no_sound
        recon = FastRecon(args.target, sound_alerts=sound_enabled)
        
        if sound_enabled:
            print(f"{Colors.GREEN}🔊 Sound alerts enabled{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🔇 Sound alerts disabled{Colors.END}")
            
        results = recon.run(args.timeout)
        
        print(f"\n{Colors.BOLD}FINAL SUMMARY:{Colors.END}")
        print(f"  Open Ports: {results['open_ports']}")
        print(f"  Web Services: {results['web_services']}")
        print(f"  URLs Found: {results['urls_found']}")
        print(f"  Credentials: {results['credentials']}")
        print(f"\n{Colors.CYAN}Results saved in: {recon.output_dir}{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted{Colors.END}")

if __name__ == "__main__":
    main()