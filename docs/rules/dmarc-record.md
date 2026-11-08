# dmarc-record

A mail domain must have exactly one DMARC record, as a TXT record at `_dmarc.<domain>`.

- Severity: FAIL when there is no record or more than one, WARN when `_dmarc.<domain>` is a CNAME
- Fixed in: the DNS zone

## Why it matters

DMARC tells receivers what to do with mail that claims to be from the domain but fails SPF and DKIM alignment.
Without it, anyone can spoof the domain and receivers decide on their own.
Receivers ignore all records if there are several.

A subdomain without a record of its own inherits the policy of the apex record.
zoneposture treats the zone apex as the organizational domain.
The finding for a subdomain says so when no record exists at the subdomain or the apex.

zoneposture does not follow a CNAME at `_dmarc`, so the record behind it is not graded.
A CNAME to a hosted DMARC service is valid; check the policy at the target manually or replace the CNAME with a TXT record.

## Fix

Publish one TXT record at `_dmarc.<domain>` that starts with `v=DMARC1`.

```text
_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"
```

`p=none` only monitors, and `dmarc-policy` reports it as FAIL.
Use it temporarily while reading the aggregate reports, then move to `quarantine` or `reject`.

For a duplicate, merge the tags into one record and delete the other.
TXT records at `_dmarc` that do not start with `v=DMARC1` are ignored by receivers.

## Verify

```sh
dig +short TXT _dmarc.example.com
zoneposture audit --zone example.com.zone
```
