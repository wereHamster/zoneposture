# caa-issuewild

The `issuewild` tags of a CAA record set decide which CAs may issue wildcard certificates.

- Severity: PASS when the tags are valid, WARN when there is no `issuewild` tag or a value is not a CA domain name
- Fixed in: the DNS zone

## Why it matters

Without an `issuewild` tag, the CAs in the `issue` tags may also issue wildcard certificates.
A wildcard certificate is valid for every subdomain, so a compromise or mis-issuance has a larger impact than for a single name.

If an `issuewild` tag exists, it replaces `issue` for wildcard certificates.

## Fix

Forbid wildcard issuance if the zone needs no wildcard certificates.

```text
example.com.  3600  IN  CAA  0 issuewild ";"
```

Otherwise name the CA that issues them.

```text
example.com.  3600  IN  CAA  0 issuewild "letsencrypt.org"
```

For a value that is not a valid CA domain name, compare it with the CA's documentation and correct the spelling.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
