# caa-missing

The zone apex has no CAA record set.

- Severity: FAIL
- Fixed in: the DNS zone

## Why it matters

A certification authority (CA) that finds no CAA records may issue certificates for the domain and all of its subdomains.
A CAA record set limits issuance to the CAs that the domain owner chose, which reduces the risk of a mis-issued certificate.

CAs search for CAA records from the requested name up towards the root and use the first record set they find.
A record set at the apex therefore covers every name in the zone that has no record set of its own.

## Fix

Add CAA records at the zone apex.
Name the CA that issues the certificates of the zone by its CAA domain, e.g. `letsencrypt.org` for Let's Encrypt.
The CA's documentation lists its CAA domain.

```text
example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issuewild ";"
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"
```

Use `issuewild ";"` only if the zone needs no wildcard certificates.
Otherwise name the CA that issues them.

Find the CA of every current certificate before publishing.
A record set that excludes the current CA makes the next renewal fail, which `certificate-caa` reports.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
