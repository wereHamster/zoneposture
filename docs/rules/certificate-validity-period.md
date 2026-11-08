# certificate-validity-period

The certificate of a host must be inside its validity period, with at least 30 days left.

- Severity: PASS with 30 or more days left, WARN with 14 to 29 days, FAIL with fewer than 14 days, when expired, or when not valid yet
- Fixed in: the certificate setup of the host

## Why it matters

Browsers show a full-page error for an expired certificate, and API clients refuse to connect.
Certificates from public CAs are short-lived, and an expiry nearly always means that automatic renewal stopped working.

A certificate that is not valid yet means that the wrong certificate is deployed, or that a clock is wrong.

## Fix

Renew the certificate and deploy it, and make the renewal automatic so that this does not repeat.
ACME clients such as certbot, or the managed certificates of a hosting platform or CDN, renew without manual steps.
If the host already uses one, find out why renewal fails.
A CAA policy that excludes the CA is a common cause (see `certificate-caa`).

For a certificate that is not valid yet, check that the server presents the intended certificate and that its clock is correct.

## Verify

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates
```
