# x-content-type-options

`https://<host>/` must send an `X-Content-Type-Options: nosniff` header.

- Severity: PASS for `nosniff`, FAIL when the header is missing or has another value
- Fixed in: the web server, CDN, or application that sets the response headers of the host

## Why it matters

Without the header, browsers may ignore the `Content-Type` of a response and guess the type from its content (MIME sniffing).
A file that the site serves as text or as an image, such as a user upload, can then run as a script or render as HTML, which allows cross-site scripting.

With `nosniff`, browsers refuse to run a script or apply a stylesheet whose `Content-Type` does not match, and they render responses with the declared type.

Browsers only recognize the value `nosniff`.
When a response has several `X-Content-Type-Options` headers, only the first value counts.

## Fix

Send the header on every response of the host, not only on HTML pages.

```http
X-Content-Type-Options: nosniff
```

Where the header is set depends on what serves the host: the web server configuration, the CDN or proxy in front of it, or the application framework.
If a proxy sits in front, set it there or make sure that the proxy passes the header through.

Make sure that every response declares the correct `Content-Type`, in particular scripts (`text/javascript`) and stylesheets (`text/css`), because browsers block them when the type does not match.

## Verify

```sh
curl -sI https://www.example.com/ | grep -i x-content-type-options
```
