# certificate-hostname

The certificate of a host must be valid for the host's name.

- Severity: FAIL
- Fixed in: the certificate setup of the host

## Why it matters

A certificate is only valid for the names in its subject alternative names (SAN).
When the name is missing, browsers show a security error, and clients that verify names refuse the connection.

The message lists the names that the certificate covers.
Typical causes:

- The server presents a default certificate because it has none for this name.
- The certificate was issued for a different host, e.g. the apex but not `www`.
- A wildcard certificate does not match.
  `*.example.com` covers `www.example.com`, but neither `example.com` itself nor `a.b.example.com`.

## Fix

Issue a certificate whose SAN list contains the name, and configure the server to present it for this name.
For several names on one server, check that the server selects the certificate by the requested name (SNI).

## Verify

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
```
