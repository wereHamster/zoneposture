# csp-script-src

The Content Security Policy must restrict where scripts come from, without sources that defeat the restriction.

- Severity: PASS for the effective `script-src` (or `default-src`), WARN when scripts are not restricted or a weak source is allowed
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

`script-src` decides which scripts the browser runs, and `default-src` applies when `script-src` is missing.
If neither exists, the policy does not restrict scripts at all.

These sources weaken the restriction:

- `'unsafe-inline'`: inline scripts run, which defeats XSS protection.
- `'unsafe-eval'`: `eval()` and similar functions are allowed.
- `*`: scripts load from any host.
- `https:` and `http:`: scripts load from any URL with that scheme.
- `data:`: scripts load from `data:` URLs.

zoneposture accounts for how browsers evaluate them.
`'unsafe-inline'` is ignored when the policy has a nonce or hash, and host and scheme sources are ignored when it has `'strict-dynamic'`, so those combinations are not reported.
With several policies, a script must pass all of them, so a source is reported only if every policy has it.

## Fix

Remove the weak sources and name what the site needs.
Use a nonce or hash for inline scripts, and list specific hosts for external scripts.

```http
Content-Security-Policy: script-src 'self' 'nonce-r4nd0m' https://cdn.example.net
```

The nonce must be new for every response.
Add `'strict-dynamic'` to let nonce-approved scripts load their own dependencies without a host list.

## Verify

```sh
curl -sI https://www.example.com/ | grep -i content-security-policy
zoneposture audit --zone example.com.zone
```
