# certificate-caa

The CA that issued the certificate of a host is compared with the CAA records that apply to the host.

- Severity: PASS when the CA is allowed, FAIL when it is not, WARN when the comparison is not conclusive
- Fixed in: the DNS zone, or the certificate setup of the host

## Why it matters

CAs check the CAA records at issuance time.
A certificate that was issued earlier stays valid, but when the CAA records exclude its CA, the next renewal is refused.
The site then goes down with an expired certificate, usually weeks after the CAA change.

For a wildcard certificate, `issuewild` applies if it exists, and `issue` otherwise.

## Fix

The message names the issuer and the owner name whose CAA records were used.
Make the policy and the certificate agree in one of two ways.

- Add the issuer's CAA domain to the `issue` tags at that owner name, and to `issuewild` if the certificate is a wildcard certificate.
- Move the host to a certificate from a CA that the records allow.

Do not remove the CA from the records before the certificate setup has changed.

For the WARN cases:

- If the issuer cannot be mapped to a CAA domain, look up its CAA domain in its documentation and compare it with the records at the owner name manually.
- If the host is a CNAME, CAA records at the alias target take precedence when they exist.
  Check them at the target.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
