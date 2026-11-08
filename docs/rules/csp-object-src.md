# csp-object-src

The Content Security Policy must restrict `<object>` and `<embed>` elements.

- Severity: WARN when the policy has neither `object-src` nor `default-src`
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

`object-src` controls plugin content such as `<object>`, `<embed>`, and `<applet>`.
When neither `object-src` nor `default-src` exists, such elements may load from anywhere, which gives an attacker a way around the script restrictions.

## Fix

Add `object-src 'none'`, or set a `default-src`.
Modern sites need no plugin content.

```http
Content-Security-Policy: object-src 'none'; script-src 'self'
```

## Verify

```sh
curl -sI https://www.example.com/ | grep -i content-security-policy
```
