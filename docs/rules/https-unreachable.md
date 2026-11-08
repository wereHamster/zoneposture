# https-unreachable

`https://<host>/` must answer a request.

- Severity: FAIL
- Fixed in: the DNS zone, or the server behind the host

## Why it matters

The host is in the zone, but a request to its HTTPS root fails.
The message shows the reason, e.g. a refused or timed-out connection, a TLS error, a redirect to a non-HTTPS URL, or more than 10 redirects.
The header and security.txt checks are skipped for the host, because there is no response to grade.

A record that points to a server that no longer answers is also a security risk.
If it is a CNAME to a service where the target can be claimed by someone else, an attacker may take over the subdomain (subdomain takeover).

## Fix

Decide whether the host should serve the web.

- If it should, fix the server named in the message.
  Check that the server listens on port 443, has a certificate for the name (see `tls-connection` and the `certificate-*` rules), and that redirects stay on HTTPS and end.
- If it should not, delete its A, AAAA, and CNAME records from the zone.

## Verify

```sh
curl -sSI https://www.example.com/
zoneposture audit --zone example.com.zone
```
