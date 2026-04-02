---
name: reconnaissance
description: Passive and active reconnaissance methodology for target profiling
---

# Reconnaissance Methodology

## Phase 1: Passive Reconnaissance

Gather information without directly touching the target.

### WHOIS & Domain Intelligence

```bash
whois <target-domain>
# Extract: registrant, nameservers, creation/expiry dates, registrar
```

### DNS Enumeration

```bash
dig <target-domain> ANY +noall +answer
dig <target-domain> MX +short
dig <target-domain> TXT +short
dig <target-domain> NS +short
dig <target-domain> AXFR @<nameserver>   # Zone transfer attempt
host -t CNAME <target-domain>
```

### Certificate Transparency Logs

```bash
# Query crt.sh for subdomains via CT logs
curl -s "https://crt.sh/?q=%25.<target-domain>&output=json" | jq -r '.[].name_value' | sort -u
```

### Shodan / Censys

```bash
shodan host <target-ip>
shodan search "hostname:<target-domain>"
# Look for: open ports, services, banners, known vulns, SSL cert info
```

### Google Dorks

```
site:<target-domain> filetype:pdf
site:<target-domain> inurl:admin
site:<target-domain> intitle:"index of"
site:<target-domain> ext:sql | ext:bak | ext:log
site:<target-domain> inurl:api
"<target-domain>" password | secret | token | key
```

## Phase 2: Active Reconnaissance

Directly probe the target to discover services and versions.

### Port Scanning (nmap)

```bash
# Fast TCP scan — top 1000 ports
nmap -sV -sC -T4 -oN nmap_initial.txt <target-ip>

# Full TCP port scan
nmap -p- -T4 -oN nmap_full_tcp.txt <target-ip>

# UDP top 100
nmap -sU --top-ports 100 -T4 -oN nmap_udp.txt <target-ip>

# Aggressive scan on discovered ports
nmap -A -p <ports> -oN nmap_aggressive.txt <target-ip>
```

### Service Fingerprinting & Banner Grabbing

```bash
nmap -sV --version-intensity 5 -p <ports> <target-ip>
nc -nv <target-ip> <port>            # Manual banner grab
openssl s_client -connect <target-ip>:443   # TLS banner
```

## Phase 3: Web Reconnaissance

### Technology Detection

```bash
whatweb <target-url>
# Also check: Wappalyzer browser extension, HTTP response headers
curl -sI <target-url> | grep -i "x-powered-by\|server\|x-aspnet"
```

### Sitemap & Robots

```bash
curl -s <target-url>/robots.txt
curl -s <target-url>/sitemap.xml
curl -s <target-url>/.well-known/security.txt
```

### Directory Bruteforce

```bash
# gobuster
gobuster dir -u <target-url> -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobuster.txt

# ffuf — faster, supports recursion
ffuf -u <target-url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -o ffuf_results.json
```

## Decision Tree

```
1. Is the target a domain?
   YES -> WHOIS, DNS, CT logs, Google dorks, then nmap
   NO  -> Skip to nmap directly

2. Are web ports open (80/443)?
   YES -> Run web recon (whatweb, robots, directory brute)
   NO  -> Focus on service-specific enumeration

3. Did CT logs reveal subdomains?
   YES -> Feed into subdomain enumeration (see enumeration.md)
   NO  -> Proceed with known scope only

4. Are there known services (SSH, FTP, SMTP)?
   YES -> Check default creds, version-specific CVEs
   NO  -> Expand port scan to full range
```

## Output Checklist

- [ ] IP addresses and ranges mapped
- [ ] All open ports and services documented
- [ ] Software versions identified
- [ ] Subdomains discovered
- [ ] Web technologies fingerprinted
- [ ] Sensitive files/directories found
- [ ] Potential attack surface ranked by likelihood
