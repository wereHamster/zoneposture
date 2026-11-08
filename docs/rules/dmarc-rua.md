# dmarc-rua

A DMARC record must have a `rua=` tag that names where aggregate reports are sent.

- Severity: WARN
- Fixed in: the DNS zone

## Why it matters

Receivers send daily aggregate reports to the `rua=` address.
The reports show which hosts send mail as the domain and whether it passes SPF and DKIM.
Without them, a policy of `quarantine` or `reject` can block legitimate senders without anyone noticing, and spoofing attempts stay invisible.

## Fix

Add `rua=` with a mailbox that someone reads, or a DMARC reporting service.

```text
_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"
```

If the address is in another domain, that domain must authorize the reports with a TXT record at `example.com._report._dmarc.<reporting-domain>` whose value is `v=DMARC1`.
Reporting services give the exact record.

## Verify

```sh
dig +short TXT _dmarc.example.com
zoneposture audit --zone example.com.zone
```
