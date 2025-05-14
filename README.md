# CroX - Offensive Multi Tool

A comprehensive Python-based tool for penetration testing and offensive security operations.

![Banner](https://i.imgur.com/ieTRSTK.png)

## Features

- **Reconnaissance & Information Gathering**
  - DNS lookups (A, MX, NS, TXT, etc.)
  - WHOIS information gathering
  - Network scanning capabilities

- **Scanning & Enumeration**
  - TCP port scanning (connect and SYN modes)
  - Nmap integration
  - Multi-threaded scanning

- **Web Application Testing**
  - Directory and file brute-forcing
  - Custom wordlist support

- **Exploitation Tools**
  - Reverse shell generation (Python, Bash, PHP, Perl)
  - Basic C2 server functionality

- **Password Attacks**
  - Hash cracking (MD5, SHA1, SHA256, SHA512, NTLM)
  - Wordlist-based attacks

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/NerdBlud/crox-multitool.git
   cd crox-multitool

    Install dependencies:

```bash
pip install -r requirements.txt
```

##  Run the tool:
```py
    python3 offensive_tool.py
```

## Usage

usage: offensive_tool.py [-h] {recon,scan,web,exploit,password,c2} ...

Offensive Security Multi-Tool

```text

positional arguments:
  {recon,scan,web,exploit,password,c2}
    recon               Reconnaissance and information gathering
    scan                Port scanning and enumeration
    web                 Web application scanning
    exploit             Exploitation tools
    password            Password attacks
    c2                  Command and Control

optional arguments:
  -h, --help            show this help message and exit

```

## Examples

Perform DNS reconnaissance:

```bash
python3 offensive_tool.py recon dns example.com --record-type MX
```

Run a port scan:
```bash
python3 offensive_tool.py scan 192.168.1.1 -p 1-1000 -t 20 --scan-type syn
```

Brute-force web directories:
```bash
python3 offensive_tool.py web dir http://example.com -w common.txt -e php,html
```

Generate a reverse shell payload:
```bash
python3 offensive_tool.py exploit shell generate 10.0.0.1 4444 --type bash
```

Crack a password hash:
```bash
python3 offensive_tool.py password hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 -w fpne.txt
```

## Requirements

    Python 3.6+

    See requirements.txt for dependencies

## Warning

⚠️ This tool is for authorized penetration testing and educational purposes only.
⚠️ Always obtain proper authorization before testing systems you don't own.
⚠️ Use at your own risk.


### Additional Notes:

1. The `requirements.txt` includes both core and optional dependencies. The optional ones are commented out since they're not required for basic functionality.

2. For a complete installation with all features, you may want to create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

    Some features like Nmap scanning require Nmap to be installed on the system (not just the Python package).

    The tool is designed to work with Python 3.6+. Older Python versions are not supported.

    For the best experience, use the tool in a Linux environment as some features (like raw socket operations) may require root privileges or may not work properly on Windows.