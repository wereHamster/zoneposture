# hsts-include-subdomains

The HSTS header of the zone apex must have the `includeSubDomains` directive.

- Severity: WARN
- Fixed in: the web server, CDN, or application that sets the response headers of the apex

## Why it matters

Without `includeSubDomains`, the HSTS policy covers the apex only.
A visitor who reaches a subdomain over HTTP is not protected, and cookies of the apex domain that are shared with subdomains can be read or set by an attacker in that connection.

The check applies to the apex only.
Subdomains that send their own HSTS header are graded by `hsts-policy`.

## Fix

Add the directive to the header of the apex.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Every subdomain of the zone must serve HTTPS first, including internal tools and forgotten hosts.
A subdomain that only serves HTTP becomes unreachable for visitors whose browsers have stored the policy.

## Verify

```sh
curl -sI https://example.com/ | grep -i strict-transport-security
```
