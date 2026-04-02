---
name: enumeration
description: Systematic endpoint, service, and parameter enumeration techniques
---

# Endpoint & Service Enumeration

## Phase 1: Subdomain Enumeration

Discover all subdomains to expand the attack surface.

### Passive Subdomain Discovery

```bash
# crt.sh — Certificate Transparency
curl -s "https://crt.sh/?q=%25.<target-domain>&output=json" | jq -r '.[].name_value' | sort -u

# subfinder — aggregates multiple passive sources
subfinder -d <target-domain> -o subdomains_passive.txt

# amass passive mode
amass enum -passive -d <target-domain> -o amass_passive.txt
```

### Active Subdomain Brute-Force

```bash
# amass active mode with brute-force
amass enum -brute -d <target-domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o amass_active.txt

# gobuster DNS mode
gobuster dns -d <target-domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50

# Resolve discovered subdomains to live hosts
cat all_subdomains.txt | httpx -silent -status-code -title -o live_hosts.txt
```

### Subdomain Takeover Check

```bash
# Check for dangling CNAME records
dig CNAME <subdomain> +short
# If CNAME points to unclaimed service (S3, Heroku, GitHub Pages) -> takeover candidate
# Tools: subjack, nuclei with takeover templates
subjack -w subdomains.txt -t 50 -o takeover_results.txt
```

## Phase 2: Directory & File Enumeration

### Standard Directory Brute-Force

```bash
# gobuster with multiple wordlists
gobuster dir -u <target-url> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -x php,asp,aspx,jsp,html,js -o dirs.txt

# dirsearch — recursive by default
dirsearch -u <target-url> -e php,asp,html -t 50 --format=json -o dirsearch.json

# ffuf with status code filtering
ffuf -u <target-url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -recursion -recursion-depth 2
```

### Sensitive File Discovery

```bash
# Backup and config files
ffuf -u <target-url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .bak,.old,.conf,.env,.sql,.zip,.tar.gz,.git

# Git exposure check
curl -s <target-url>/.git/HEAD
curl -s <target-url>/.git/config
# If accessible -> use git-dumper to extract full repo

# Common sensitive paths
curl -sI <target-url>/.env
curl -sI <target-url>/wp-config.php.bak
curl -sI <target-url>/server-status
curl -sI <target-url>/phpinfo.php
```

## Phase 3: Parameter Discovery

### Automated Parameter Mining

```bash
# Arjun — finds hidden GET/POST parameters
arjun -u <target-url>/endpoint -m GET -o arjun_get.json
arjun -u <target-url>/endpoint -m POST -o arjun_post.json
arjun -u <target-url>/endpoint -m JSON -o arjun_json.json

# ParamMiner patterns to test manually
# Append common params: ?debug=1, ?test=1, ?admin=true, ?id=1, ?page=1
# Headers to probe: X-Forwarded-For, X-Original-URL, X-Rewrite-URL
```

### Crawl-Based Discovery

```bash
# katana — fast crawler for endpoint/param extraction
katana -u <target-url> -d 3 -jc -o crawled_endpoints.txt

# Extract unique parameters from crawled URLs
cat crawled_endpoints.txt | grep "?" | cut -d'?' -f2 | tr '&' '\n' | cut -d'=' -f1 | sort -u
```

## Phase 4: API Endpoint Discovery

### Common API Path Patterns

```bash
# REST API brute-force
ffuf -u <target-url>/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403

# Version enumeration
for v in v1 v2 v3; do curl -sI "<target-url>/api/$v/users"; done

# Swagger/OpenAPI spec discovery
curl -s <target-url>/swagger.json
curl -s <target-url>/openapi.json
curl -s <target-url>/api-docs
curl -s <target-url>/v2/api-docs
```

### GraphQL Detection

```bash
# Common GraphQL endpoints
for path in graphql graphiql graphql/console; do
  curl -s -o /dev/null -w "%{http_code}" "<target-url>/$path"
done

# Introspection query
curl -s -X POST <target-url>/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'
```

## Enumeration Decision Tree

```
1. Subdomains found?
   YES -> Resolve all, check for takeover, enumerate each live host
   NO  -> Focus on primary domain paths and APIs

2. Web app detected?
   YES -> Directory brute, param discovery, crawl
   NO  -> Focus on service-level enumeration (SMB shares, SNMP, etc.)

3. API endpoints found?
   YES -> Check for Swagger docs, test auth, enumerate CRUD operations
   NO  -> Try common API prefixes (/api, /rest, /v1)

4. 403 responses on paths?
   YES -> Note for WAF bypass attempts (see waf_bypass.md)
   NO  -> Continue expanding scope
```

## Output Checklist

- [ ] All live subdomains resolved and documented
- [ ] Directory structure mapped per host
- [ ] Hidden parameters identified per endpoint
- [ ] API schema reconstructed (if no docs found)
- [ ] Sensitive files/backups flagged
- [ ] 403/401 endpoints noted for bypass testing
