# caa-issue

The `issue` tags of a CAA record set decide which CAs may issue certificates.

- Severity: PASS when the tags are valid, WARN when a value is not a CA domain name, FAIL when there is no `issue` tag
- Fixed in: the DNS zone

## Why it matters

Without an `issue` tag, any CA may issue certificates for the name, even if other CAA tags exist.
A value that is not a valid CA domain name, such as a misspelling or a value with extra quotes, does not authorize the CA that the owner intended.
That CA then refuses to issue, and renewals fail.

## Fix

Add one `issue` record for each CA that may issue certificates, using the CA's CAA domain.
Use `";"` to forbid issuance by all CAs.

```text
example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issue "pki.goog"
```

A value is a domain name, optionally followed by `;` and parameters, e.g. `"pki.goog; cansignhttpexchanges=yes"`.
For a WARN, compare the value with the CA's documentation and correct the spelling.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
