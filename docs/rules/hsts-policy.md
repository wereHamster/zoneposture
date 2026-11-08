# hsts-policy

`https://<host>/` must send a `Strict-Transport-Security` header with a `max-age` of at least one year.

- Severity: PASS for `max-age` of 31536000 or more, WARN for a shorter value, FAIL when the header is missing, has no valid `max-age`, or sets `max-age=0`
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

HSTS tells browsers to use HTTPS for the host and to refuse plain HTTP, for the duration of `max-age`.
Without it, the first request of a visitor can go over HTTP, where an attacker on the network can intercept it and downgrade the connection.
`max-age=0` removes the policy from browsers.

Browsers only process the first `Strict-Transport-Security` header of a response, and they ignore it on plain HTTP.

## Fix

Send the header on every HTTPS response of the host.

```http
Strict-Transport-Security: max-age=31536000
```

Where the header is set depends on what serves the host: the web server configuration, the CDN or proxy in front of it, or the application framework.
If a proxy sits in front, set it there or make sure that the proxy passes the header through.

HSTS commits browsers to HTTPS for the whole `max-age`.
Roll it out with a short `max-age`, e.g. 300, confirm that the site works, then raise it to 31536000 or more.

## Verify

```sh
curl -sI https://www.example.com/ | grep -i strict-transport-security
```
