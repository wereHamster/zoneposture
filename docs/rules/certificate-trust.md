# certificate-trust

The certificate of a host must chain to a trusted root.

- Severity: FAIL
- Fixed in: the certificate setup of the host

## Why it matters

Clients trust a certificate only if it leads through intermediate certificates to a root in their trust store.
When the chain does not, browsers and API clients refuse the connection.

The usual cause is that the server sends only its own certificate and not the intermediates.
Some browsers fetch missing intermediates and hide the problem, but many other clients, such as `curl`, mobile apps, and server-side HTTP libraries, fail.
zoneposture verifies against the Mozilla root store and does not fetch intermediates, so it reports the problem.

The `invalid:` variant of the message carries another validation error from the verifier, e.g. a self-signed certificate or a certificate that is not allowed for server authentication.

## Fix

- For missing intermediates, configure the server with the full chain: the certificate followed by the intermediates, e.g. `fullchain.pem` instead of `cert.pem` for Let's Encrypt.
- For a self-signed certificate or a private CA, replace it with a certificate from a public CA, since the host is on the public internet.
- For another error, read the message and re-issue the certificate accordingly.

## Verify

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com -showcerts </dev/null
```

The output lists every certificate that the server sends, and ends with `Verify return code: 0 (ok)` when the chain is complete.
