#!/usr/bin/env python3
"""
MRD10X ETHICAL HACKING TOOLS SUITE - 30 TOOLS COMPLETE
Created by: mrd10x
For authorized penetration testing only
"""

import requests
import threading
import socket
import dns.resolver
import ssl
import time
import subprocess
import os
import hashlib
import random
import string
import re
import json
import base64
from datetime import datetime
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

class MrD10XEthicalTools:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "mrd10x"
        self.show_banner()
        
    def show_banner(self):
        print(Fore.CYAN + """
                  ____________________        
_______ ________________  /_<  /_  __ \___  __
__  __ `__ \_  ___/  __  /__  /_  / / /_  |/_/
_  / / / / /  /__ / /_/ / _  / / /_/ /__>  <  
/_/ /_/ /_//_/_(_)\__,_/  /_/  \____/ /_/|_|  
        """)
        
        print(Fore.YELLOW + "🔐 " + Fore.MAGENTA + "30+ ETHICAL HACKING TOOLS SUITE")
        print(Fore.YELLOW + "⚡ " + Fore.GREEN + "Version: " + Fore.WHITE + self.version)
        print(Fore.YELLOW + "👤 " + Fore.GREEN + "Author: " + Fore.RED + self.author)
        print(Fore.YELLOW + "⚠️  " + Fore.RED + "FOR AUTHORIZED TESTING ONLY!")
        print(Fore.CYAN + "=" * 60)

    def show_menu(self):
        """Display 30 tools menu lengkap"""
        print(Fore.MAGENTA + "\n📋 " + Fore.YELLOW + "30 ETHICAL HACKING TOOLS:" + Style.RESET_ALL)
        
        print(Fore.CYAN + "\n🔍 1-5: RECONNAISSANCE")
        print(Fore.WHITE + "1. Port Scanner")
        print(Fore.WHITE + "2. DNS Lookup") 
        print(Fore.WHITE + "3. WHOIS Checker")
        print(Fore.WHITE + "4. Subdomain Finder")
        print(Fore.WHITE + "5. HTTP Header Analyzer")

        print(Fore.RED + "\n🔧 6-10: VULNERABILITY SCANNING")
        print(Fore.WHITE + "6. SQL Injection Tester")
        print(Fore.WHITE + "7. XSS Detector")
        print(Fore.WHITE + "8. Directory Bruteforcer") 
        print(Fore.WHITE + "9. File Upload Tester")
        print(Fore.WHITE + "10. SSL/TLS Checker")

        print(Fore.YELLOW + "\n⚡ 11-15: PERFORMANCE TESTING")
        print(Fore.WHITE + "11. Load Tester")
        print(Fore.WHITE + "12. Stress Tester")
        print(Fore.WHITE + "13. API Fuzzer")
        print(Fore.WHITE + "14. Website Speed Test") 
        print(Fore.WHITE + "15. Uptime Monitor")

        print(Fore.BLUE + "\n🌐 16-20: NETWORK TOOLS")
        print(Fore.WHITE + "16. Ping Sweeper")
        print(Fore.WHITE + "17. Traceroute")
        print(Fore.WHITE + "18. IP Geolocation")
        print(Fore.WHITE + "19. MAC Address Lookup")
        print(Fore.WHITE + "20. Network Interface Info")

        print(Fore.MAGENTA + "\n📊 21-25: ANALYSIS TOOLS")
        print(Fore.WHITE + "21. Log Analyzer")
        print(Fore.WHITE + "22. Backup File Finder")
        print(Fore.WHITE + "23. Config File Scanner")
        print(Fore.WHITE + "24. Email Harvester")
        print(Fore.WHITE + "25. CMS Detector")

        print(Fore.RED + "\n🛡️ 26-30: SECURITY TOOLS")
        print(Fore.WHITE + "26. Password Strength Checker")
        print(Fore.WHITE + "27. Hash Cracker (Basic)")
        print(Fore.WHITE + "28. Encryption/Decryption Tool")
        print(Fore.WHITE + "29. Firewall Tester")
        print(Fore.WHITE + "30. Security Headers Check")

        print(Fore.RED + "\n0. " + Fore.YELLOW + "Exit")

    # ==================== TOOL 1: PORT SCANNER ====================
    def port_scanner(self):
        target = input(Fore.CYAN + "Enter target IP/hostname: " + Fore.WHITE)
        print(Fore.CYAN + f"\n🎯 Scanning common ports on {target}...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = "unknown"
                    print(Fore.GREEN + f"✅ Port {port}/TCP - OPEN ({service})")
                sock.close()
            except: pass

        threads = []
        for port in common_ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

    # ==================== TOOL 2: DNS LOOKUP ====================
    def dns_lookup(self):
        domain = input(Fore.CYAN + "Enter domain: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🌐 DNS records for {domain}...")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    print(Fore.GREEN + f"📡 {record_type}: {rdata}")
            except: 
                print(Fore.RED + f"❌ No {record_type} records found")

    # ==================== TOOL 3: WHOIS LOOKUP ====================
    def whois_lookup(self):
        domain = input(Fore.CYAN + "Enter domain: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🔍 WHOIS lookup for {domain}...")
        
        try:
            import whois
            w = whois.whois(domain)
            print(Fore.GREEN + f"📅 Creation Date: {w.creation_date}")
            print(Fore.GREEN + f"📅 Expiration Date: {w.expiration_date}")
            print(Fore.GREEN + f"🏢 Registrar: {w.registrar}")
            print(Fore.GREEN + f"🌍 Name Servers: {w.name_servers}")
        except ImportError:
            print(Fore.RED + "❌ Install: pip install python-whois")

    # ==================== TOOL 4: SUBDOMAIN FINDER ====================
    def subdomain_finder(self):
        domain = input(Fore.CYAN + "Enter domain: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🔎 Finding subdomains for {domain}...")
        
        subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
                     'admin', 'blog', 'shop', 'forum', 'api', 'test', 'dev', 'staging', 'mobile']
        
        found = []
        for sub in subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
                print(Fore.GREEN + f"✅ Found: {subdomain}")
            except:
                print(Fore.RED + f"❌ Not found: {subdomain}")
        
        print(Fore.YELLOW + f"\n📊 Found {len(found)} subdomains")

    # ==================== TOOL 5: HTTP HEADER ANALYZER ====================
    def http_header_analyzer(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🔧 Analyzing HTTP headers for {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 
                              'Strict-Transport-Security', 'Content-Security-Policy']
            
            print(Fore.GREEN + f"📊 Status Code: {response.status_code}")
            print(Fore.GREEN + f"🕒 Response Time: {response.elapsed.total_seconds():.2f}s")
            
            for header, value in response.headers.items():
                color = Fore.YELLOW if header in security_headers else Fore.WHITE
                print(color + f"📋 {header}: {value}")
                
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 6: SQL INJECTION TESTER ====================
    def sql_injection_tester(self):
        url = input(Fore.CYAN + "Enter URL with parameter: " + Fore.WHITE)
        print(Fore.RED + f"\n💉 Testing SQL Injection on {url}...")
        
        payloads = ["'", "';", "' OR '1'='1", "' UNION SELECT 1,2,3--"]
        
        for payload in payloads:
            test_url = url + payload
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    print(Fore.RED + f"⚠️  Possible SQLi: {payload}")
                else:
                    print(Fore.GREEN + f"✅ Safe: {payload}")
            except: pass

    # ==================== TOOL 7: XSS DETECTOR ====================
    def xss_detector(self):
        url = input(Fore.CYAN + "Enter URL with parameter: " + Fore.WHITE)
        print(Fore.RED + f"\n🎯 Testing XSS on {url}...")
        
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        
        for payload in payloads:
            test_url = url + payload
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if payload in response.text:
                    print(Fore.RED + f"⚠️  Possible XSS: {payload}")
                else:
                    print(Fore.GREEN + f"✅ Safe: {payload}")
            except: pass

    # ==================== TOOL 8: DIRECTORY BRUTEFORCER ====================
    def directory_bruteforcer(self):
        url = input(Fore.CYAN + "Enter base URL: " + Fore.WHITE)
        print(Fore.RED + f"\n🔍 Bruteforcing directories on {url}...")
        
        directories = ['admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin', 'test', 'backup']
        
        found = []
        for directory in directories:
            test_url = urljoin(url, directory)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    found.append(test_url)
                    print(Fore.GREEN + f"✅ Found: {test_url}")
            except: pass
        
        print(Fore.YELLOW + f"\n📊 Found {len(found)} directories")

    # ==================== TOOL 9: FILE UPLOAD TESTER ====================
    def file_upload_tester(self):
        url = input(Fore.CYAN + "Enter upload form URL: " + Fore.WHITE)
        print(Fore.RED + f"\n📤 Testing file upload on {url}...")
        
        # Basic file upload test
        files = {'file': ('test.php', '<?php phpinfo(); ?>', 'application/x-php')}
        try:
            response = requests.post(url, files=files, timeout=5, verify=False)
            if response.status_code == 200:
                print(Fore.YELLOW + "⚠️  Upload mungkin berhasil - manual verification needed")
            else:
                print(Fore.RED + "❌ Upload ditolak")
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 10: SSL/TLS CHECKER ====================
    def ssl_tls_checker(self):
        domain = input(Fore.CYAN + "Enter domain: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🔒 Checking SSL/TLS for {domain}...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    print(Fore.GREEN + f"✅ SSL Certificate Valid")
                    print(Fore.GREEN + f"🔐 Protocol: {ssock.version()}")
        except Exception as e:
            print(Fore.RED + f"❌ SSL Error: {e}")

    # ==================== TOOL 11: LOAD TESTER ====================
    def load_tester(self):
        url = input(Fore.CYAN + "Enter URL to test: " + Fore.WHITE)
        threads = int(input(Fore.CYAN + "Number of threads: " + Fore.WHITE))
        duration = int(input(Fore.CYAN + "Duration (seconds): " + Fore.WHITE))
        
        print(Fore.YELLOW + f"\n⚡ Load testing {url}...")
        
        success = failed = 0
        start_time = time.time()
        
        def worker():
            nonlocal success, failed
            while time.time() - start_time < duration:
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code == 200: success += 1
                    else: failed += 1
                except: failed += 1
        
        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for w in workers: w.start()
        for w in workers: w.join()
        
        total = success + failed
        print(Fore.GREEN + f"📊 Requests: {total} | Success: {success} | Failed: {failed}")

    # ==================== TOOL 12: STRESS TESTER ====================
    def stress_tester(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        print(Fore.RED + f"\n💥 Stress testing {url}...")
        
        # Similar to load tester but with more aggressive settings
        self.load_tester()

    # ==================== TOOL 13: API FUZZER ====================
    def api_fuzzer(self):
        url = input(Fore.CYAN + "Enter API endpoint: " + Fore.WHITE)
        print(Fore.YELLOW + f"\n🔍 Fuzzing API {url}...")
        
        fuzz_params = ['id', 'user', 'admin', 'debug', 'test', 'password']
        for param in fuzz_params:
            test_url = f"{url}?{param}=test"
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                print(Fore.WHITE + f"🔧 {param}: {response.status_code}")
            except: pass

    # ==================== TOOL 14: WEBSITE SPEED TEST ====================
    def website_speed_test(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        print(Fore.BLUE + f"\n⏱️  Testing speed for {url}...")
        
        try:
            start = time.time()
            response = requests.get(url, timeout=10, verify=False)
            load_time = time.time() - start
            
            print(Fore.GREEN + f"📊 Load Time: {load_time:.2f} seconds")
            print(Fore.GREEN + f"📦 Content Size: {len(response.content)} bytes")
            print(Fore.GREEN + f"🎯 Status Code: {response.status_code}")
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 15: UPTIME MONITOR ====================
    def uptime_monitor(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "Monitor duration (minutes): " + Fore.WHITE))
        
        print(Fore.GREEN + f"\n📊 Monitoring {url} for {duration} minutes...")
        
        end_time = time.time() + (duration * 60)
        checks = successes = 0
        
        while time.time() < end_time:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    successes += 1
                    print(Fore.GREEN + f"✅ UP - {response.status_code}")
                else:
                    print(Fore.RED + f"❌ DOWN - {response.status_code}")
            except:
                print(Fore.RED + "💥 CONNECTION ERROR")
            
            checks += 1
            time.sleep(30)  # Check every 30 seconds
        
        uptime_percent = (successes / checks) * 100
        print(Fore.YELLOW + f"\n📈 Uptime: {uptime_percent:.1f}% ({successes}/{checks} checks)")

    # ==================== TOOL 16: PING SWEEPER ====================
    def ping_sweeper(self):
        network = input(Fore.CYAN + "Enter network (e.g., 192.168.1.): " + Fore.WHITE)
        print(Fore.BLUE + f"\n🌐 Pinging network {network}1-254...")
        
        def ping_host(ip):
            try:
                subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], stderr=subprocess.DEVNULL)
                print(Fore.GREEN + f"✅ {ip} is UP")
            except:
                print(Fore.RED + f"❌ {ip} is DOWN")
        
        threads = []
        for i in range(1, 255):
            ip = network + str(i)
            thread = threading.Thread(target=ping_host, args=(ip,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 50:
                for t in threads: t.join()
                threads = []
        
        for t in threads: t.join()

    # ==================== TOOL 17: TRACEROUTE ====================
    def traceroute(self):
        target = input(Fore.CYAN + "Enter target: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🛣️  Traceroute to {target}...")
        
        try:
            result = subprocess.check_output(['traceroute', target], stderr=subprocess.DEVNULL)
            print(Fore.GREEN + result.decode())
        except:
            print(Fore.RED + "❌ Traceroute failed or not available")

    # ==================== TOOL 18: IP GEOLOCATION ====================
    def ip_geolocation(self):
        ip = input(Fore.CYAN + "Enter IP address: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🌍 Geolocating IP {ip}...")
        
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            
            if data['status'] == 'success':
                print(Fore.GREEN + f"📍 Country: {data.get('country', 'N/A')}")
                print(Fore.GREEN + f"🏙️  City: {data.get('city', 'N/A')}")
                print(Fore.GREEN + f"🌐 ISP: {data.get('isp', 'N/A')}")
            else:
                print(Fore.RED + "❌ Geolocation failed")
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 19: MAC ADDRESS LOOKUP ====================
    def mac_address_lookup(self):
        mac = input(Fore.CYAN + "Enter MAC address: " + Fore.WHITE)
        print(Fore.BLUE + f"\n🔍 Looking up MAC {mac}...")
        
        # Basic MAC vendor lookup
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:16:3E': 'Xensource',
        }
        
        prefix = mac[:8].upper()
        vendor = vendors.get(prefix, "Unknown vendor")
        print(Fore.GREEN + f"🏢 Vendor: {vendor}")

    # ==================== TOOL 20: NETWORK INTERFACE INFO ====================
    def network_interface_info(self):
        print(Fore.BLUE + f"\n📡 Network Interface Information...")
        
        try:
            result = subprocess.check_output(['ip', 'addr'], stderr=subprocess.DEVNULL)
            print(Fore.GREEN + result.decode())
        except:
            try:
                result = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL)
                print(Fore.GREEN + result.decode())
            except:
                print(Fore.RED + "❌ Network commands not available")

    # ==================== TOOL 21: LOG ANALYZER ====================
    def log_analyzer(self):
        log_file = input(Fore.CYAN + "Enter log file path: " + Fore.WHITE)
        print(Fore.MAGENTA + f"\n📊 Analyzing log file {log_file}...")
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                print(Fore.GREEN + f"📄 Total lines: {len(lines)}")
                
                # Count IP addresses
                ip_pattern = r'\d+\.\d+\.\d+\.\d+'
                ips = re.findall(ip_pattern, ' '.join(lines))
                print(Fore.GREEN + f"🌐 Unique IPs: {len(set(ips))}")
                
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 22: BACKUP FILE FINDER ====================
    def backup_file_finder(self):
        url = input(Fore.CYAN + "Enter website URL: " + Fore.WHITE)
        print(Fore.MAGENTA + f"\n💾 Searching for backup files on {url}...")
        
        backup_files = ['backup.zip', 'database.sql', 'backup.sql', 'wp-config.php.bak', 
                       'config.bak', 'backup.tar.gz', 'www.zip', 'site.bak']
        
        for file in backup_files:
            test_url = urljoin(url, file)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(Fore.GREEN + f"✅ Found: {test_url}")
                else:
                    print(Fore.RED + f"❌ Not found: {file}")
            except: pass

    # ==================== TOOL 23: CONFIG FILE SCANNER ====================
    def config_file_scanner(self):
        url = input(Fore.CYAN + "Enter website URL: " + Fore.WHITE)
        print(Fore.MAGENTA + f"\n🔧 Scanning for config files on {url}...")
        
        config_files = ['.env', 'config.php', 'wp-config.php', 'configuration.php', 
                       'settings.py', 'config.json', 'app.config']
        
        for file in config_files:
            test_url = urljoin(url, file)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(Fore.RED + f"⚠️  Config file exposed: {test_url}")
                else:
                    print(Fore.GREEN + f"✅ Secured: {file}")
            except: pass

    # ==================== TOOL 24: EMAIL HARVESTER ====================
    def email_harvester(self):
        url = input(Fore.CYAN + "Enter website URL: " + Fore.WHITE)
        print(Fore.MAGENTA + f"\n📧 Harvesting emails from {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response.text)
            
            if emails:
                for email in set(emails):
                    print(Fore.GREEN + f"📨 {email}")
            else:
                print(Fore.RED + "❌ No emails found")
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 25: CMS DETECTOR ====================
    def cms_detector(self):
        url = input(Fore.CYAN + "Enter website URL: " + Fore.WHITE)
        print(Fore.MAGENTA + f"\n🔍 Detecting CMS on {url}...")
        
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'media/jui', 'components/com_'],
            'Drupal': ['drupal', 'sites/all', 'core/assets'],
            'Magento': ['magento', 'skin/frontend', 'media/catalog']
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            detected = []
            
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in response.text:
                        detected.append(cms)
                        break
            
            if detected:
                print(Fore.GREEN + f"✅ Detected: {', '.join(set(detected))}")
            else:
                print(Fore.RED + "❌ CMS not detected or custom")
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== TOOL 26: PASSWORD STRENGTH CHECKER ====================
    def password_strength_checker(self):
        password = input(Fore.CYAN + "Enter password to check: " + Fore.WHITE)
        print(Fore.RED + f"\n🔐 Analyzing password strength...")
        
        score = 0
        if len(password) >= 8: score += 1
        if any(c.islower() for c in password) and any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(not c.isalnum() for c in password): score += 1
        
        if score == 4: print(Fore.GREEN + "💪 Password: STRONG")
        elif score == 3: print(Fore.YELLOW + "⚠️  Password: MEDIUM")
        else: print(Fore.RED + "💥 Password: WEAK")

    # ==================== TOOL 27: HASH CRACKER ====================
    def hash_cracker(self):
        hash_input = input(Fore.CYAN + "Enter hash to crack: " + Fore.WHITE)
        print(Fore.RED + f"\n🔓 Attempting to crack hash...")
        
        common_passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']
        
        for pwd in common_passwords:
            if hashlib.md5(pwd.encode()).hexdigest() == hash_input:
                print(Fore.GREEN + f"✅ Cracked! MD5: {pwd}")
                return
            if hashlib.sha1(pwd.encode()).hexdigest() == hash_input:
                print(Fore.GREEN + f"✅ Cracked! SHA1: {pwd}")
                return
        
        print(Fore.RED + "❌ Hash not cracked with common passwords")

    # ==================== TOOL 28: ENCRYPTION/DECRYPTION TOOL ====================
    def encryption_tool(self):
        print(Fore.RED + f"\n🔐 Encryption/Decryption Tool")
        text = input(Fore.CYAN + "Enter text: " + Fore.WHITE)
        
        # Simple Base64 encoding/decoding
        encoded = base64.b64encode(text.encode()).decode()
        print(Fore.GREEN + f"🔒 Encoded (Base64): {encoded}")
        
        decoded = base64.b64decode(encoded).decode()
        print(Fore.GREEN + f"🔓 Decoded: {decoded}")

    # ==================== TOOL 29: FIREWALL TESTER ====================
    def firewall_tester(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        print(Fore.RED + f"\n🔥 Testing firewall on {url}...")
        
        # Test common ports that might be blocked
        ports = [80, 443, 22, 21, 25]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((urlparse(url).hostname, port))
                if result == 0:
                    print(Fore.GREEN + f"✅ Port {port}: OPEN")
                else:
                    print(Fore.RED + f"❌ Port {port}: BLOCKED/CLOSED")
                sock.close()
            except: pass

    # ==================== TOOL 30: SECURITY HEADERS CHECK ====================
    def security_headers_check(self):
        url = input(Fore.CYAN + "Enter URL: " + Fore.WHITE)
        print(Fore.RED + f"\n🛡️  Checking security headers for {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Content security policy'
            }
            
            for header, description in security_headers.items():
                if header in response.headers:
                    print(Fore.GREEN + f"✅ {header}: {response.headers[header]}")
                else:
                    print(Fore.RED + f"❌ {header}: MISSING - {description}")
                    
        except Exception as e:
            print(Fore.RED + f"💥 Error: {e}")

    # ==================== MAIN MENU ====================
    def main(self):
        while True:
            self.show_menu()
            choice = input(Fore.YELLOW + "\n🎯 Select tool (0-30): " + Fore.WHITE)
            
            tools = {
                '1': self.port_scanner, '2': self.dns_lookup, '3': self.whois_lookup,
                '4': self.subdomain_finder, '5': self.http_header_analyzer,
                '6': self.sql_injection_tester, '7': self.xss_detector,
                '8': self.directory_bruteforcer, '9': self.file_upload_tester,
                '10': self.ssl_tls_checker, '11': self.load_tester,
                '12': self.stress_tester, '13': self.api_fuzzer,
                '14': self.website_speed_test, '15': self.uptime_monitor,
                '16': self.ping_sweeper, '17': self.traceroute,
                '18': self.ip_geolocation, '19': self.mac_address_lookup,
                '20': self.network_interface_info, '21': self.log_analyzer,
                '22': self.backup_file_finder, '23': self.config_file_scanner,
                '24': self.email_harvester, '25': self.cms_detector,
                '26': self.password_strength_checker, '27': self.hash_cracker,
                '28': self.encryption_tool, '29': self.firewall_tester,
                '30': self.security_headers_check
            }
            
            if choice == "0":
                print(Fore.GREEN + "👋 Stay ethical! Goodbye mrd10x!")
                break
            elif choice in tools:
                try:
                    tools[choice]()
                except KeyboardInterrupt:
                    print(Fore.RED + "\n⏹️  Operation cancelled")
                except Exception as e:
                    print(Fore.RED + f"💥 Error: {e}")
                input(Fore.YELLOW + "\nPress Enter to continue...")
            else:
                print(Fore.RED + "❌ Invalid choice!")

if __name__ == "__main__":
    try:
        suite = MrD10XEthicalTools()
        suite.main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n👋 Tool terminated. Stay ethical!")