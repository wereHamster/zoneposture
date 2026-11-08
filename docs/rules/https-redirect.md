# https-redirect

`http://<host>/` must redirect to HTTPS, or not be served at all.

- Severity: PASS when it redirects to HTTPS or the port is closed, WARN when it returns an error, FAIL when it serves content, redirects without a valid target, or never reaches HTTPS
- Fixed in: the web server, CDN, or application that serves the host

## Why it matters

A visitor who types the name without a scheme, or follows an old `http://` link, starts on plain HTTP.
If the server answers with content, the visitor never reaches HTTPS, and anyone on the network can read or change the traffic.
A redirect on port 80 moves the visitor to HTTPS, where `hsts-policy` then keeps them.

zoneposture follows redirects that stay on HTTP, up to 10, and grades the first response that does not.
The message shows the final URL when the redirect went through several hops.

## Fix

Answer plain HTTP requests with a permanent redirect to the same path on HTTPS.

```http
HTTP/1.1 301 Moved Permanently
Location: https://www.example.com/
```

Fix the case from the message:

- Content served over HTTP: add the redirect, or close port 80.
- An HTTP error: serve the redirect for every path instead of an error page.
- A missing or invalid `Location` header: set it to an absolute `https://` URL or a relative URL.
- A target that is not `https:`, e.g. `ftp:`: redirect to HTTPS.
- A loop or a chain longer than 10 hops: redirect directly to the HTTPS URL.

## Verify

```sh
curl -sI http://www.example.com/
```

The response is `301` or `308` with a `Location` that starts with `https://`.
