# spf-record

A mail domain must publish exactly one SPF record.

- Severity: FAIL when there is no SPF record or more than one
- Fixed in: the DNS zone

## Why it matters

SPF lists the hosts that may send mail for a domain.
Without a record, receivers cannot tell forged mail from real mail, and DMARC has less to evaluate.
Two or more records are a permanent error (RFC 7208, section 4.5), so receivers treat the domain as if it had no usable policy.

The mail domains of a zone are the apex and every name with MX or SPF records, a `_dmarc` record, or DKIM keys.

## Fix

Publish one TXT record at the domain that starts with `v=spf1`.

For a domain that sends no mail, publish a record that authorizes no host.

```text
example.com.  3600  IN  TXT  "v=spf1 -all"
```

For a domain that sends mail, list every service that sends on its behalf, then end with `-all`.
The mail provider's documentation gives the `include:` value.

```text
example.com.  3600  IN  TXT  "v=spf1 include:_spf.example.net -all"
```

For two or more records, merge their mechanisms into one record and delete the others.

## Verify

```sh
dig +short TXT example.com
zoneposture audit --zone example.com.zone
```
