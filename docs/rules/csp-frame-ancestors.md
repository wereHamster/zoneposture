# csp-frame-ancestors

The Content Security Policy must have a `frame-ancestors` directive that limits which sites may embed the page.

- Severity: PASS for a restrictive value, WARN when the value is `*`, `https:`, or `http:`, or when only `X-Frame-Options` restricts framing, FAIL when nothing restricts framing
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

If any site can embed the page in a frame, an attacker can overlay it with invisible or misleading elements and trick visitors into clicking (clickjacking).

`X-Frame-Options` is the legacy mechanism.
It cannot express a list of allowed sites, and browsers prefer `frame-ancestors` when both exist.
`frame-ancestors` has no effect in a `<meta>` element or in a `Content-Security-Policy-Report-Only` header, so it must be an enforced HTTP header.

## Fix

Add `frame-ancestors` to the enforced policy.

```http
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
```

Use `'none'` if no site should embed the page, `'self'` if only the same origin should, or a list of origins, e.g. `'self' https://partner.example`.
A site that already sends `X-Frame-Options` can keep it next to the new directive for old browsers.

## Verify

```sh
curl -sI https://www.example.com/ | grep -i -E 'content-security-policy|x-frame-options'
```
