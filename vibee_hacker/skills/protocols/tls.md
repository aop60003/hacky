---
name: tls
description: TLS/SSL configuration security assessment techniques
---

# TLS/SSL Security

## Attack Surface

- Deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, anonymous)
- Expired, self-signed, or mismatched certificates
- Missing certificate chain (intermediate CA not sent)
- Vulnerable to known attacks: BEAST, POODLE, CRIME, Heartbleed, ROBOT
- Weak key sizes (RSA < 2048-bit, ECC < 256-bit)
- Missing OCSP stapling or certificate transparency
- TLS renegotiation vulnerabilities

## Detection Techniques

- Enumerate supported protocols and ciphers with `nmap --script ssl-enum-ciphers`
- Test with `testssl.sh` for comprehensive TLS analysis
- Check certificate validity, chain, and SANs with `openssl s_client`
- Test for specific vulnerabilities: Heartbleed, ROBOT, DROWN
- Verify HSTS header and preload status
- Check for mixed content (HTTP resources on HTTPS pages)
- Test certificate pinning bypass on mobile applications

## Common Payloads

### OpenSSL Probing
```bash
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1
openssl s_client -connect target.com:443 -ssl3
openssl s_client -connect target.com:443 -showcerts
openssl s_client -connect target.com:443 -cipher 'NULL:eNULL:aNULL'
```

### Nmap TLS Audit
```bash
nmap --script ssl-enum-ciphers -p 443 target.com
nmap --script ssl-heartbleed -p 443 target.com
nmap --script ssl-poodle -p 443 target.com
nmap --script ssl-cert -p 443 target.com
```

### testssl.sh
```bash
testssl.sh --severity HIGH target.com:443
testssl.sh --vulnerable target.com:443
testssl.sh --protocols --ciphers target.com:443
```

### Weak Cipher Indicators
```
TLS_RSA_WITH_RC4_128_SHA           (RC4 - broken)
TLS_RSA_WITH_3DES_EDE_CBC_SHA     (3DES - Sweet32)
TLS_RSA_WITH_NULL_SHA              (no encryption)
TLS_RSA_EXPORT_WITH_RC4_40_MD5    (export-grade)
```

## Remediation

- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; support only TLS 1.2 and 1.3
- Use strong cipher suites only; prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- Enforce forward secrecy (ECDHE key exchange)
- Use RSA 2048-bit+ or ECC 256-bit+ keys
- Enable HSTS with long max-age, includeSubDomains, and preload
- Configure OCSP stapling for faster revocation checks
- Install complete certificate chain (leaf + intermediates)
- Automate certificate renewal (Let's Encrypt / ACME)
- Recommended TLS 1.2 cipher order:
  ```
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

## References

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
