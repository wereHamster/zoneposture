# csp-enforced

`https://<host>/` must send an enforced `Content-Security-Policy` header when it serves HTML.

- Severity: FAIL when there is no policy, WARN when only `Content-Security-Policy-Report-Only` is sent, PASS when the response is not HTML
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

A Content Security Policy limits what a page may load and run.
It is the main defense that remains when an attacker manages to inject markup into a page (XSS).
A report-only policy only reports violations, and the browser enforces nothing.

The checks `csp-script-src`, `csp-object-src`, and `csp-frame-ancestors` grade the contents of the policy.
They only apply to HTML responses.
A response without a `Content-Type` counts as HTML, because browsers sniff the type.
A response of another type, such as JSON, gets a PASS here and is not graded further.

## Fix

Send a policy that fits the resources the site uses.

```http
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
```

For an existing site, start with `Content-Security-Policy-Report-Only` to find what a policy would block, fix those sources, then switch to the enforced header.
Use a nonce or a hash for inline scripts instead of `'unsafe-inline'`.

Where the header is set depends on what serves the host: the web server configuration, the CDN or proxy in front of it, or the application framework.

## Verify

```sh
curl -sI https://www.example.com/ | grep -i content-security-policy
```
