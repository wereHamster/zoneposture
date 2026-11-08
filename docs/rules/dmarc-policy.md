# dmarc-policy

The DMARC policy of a mail domain must be `quarantine` or `reject`.

- Severity: PASS for `quarantine` and `reject`, FAIL for `none`, an invalid value, or a missing `p=` tag, WARN when `sp=` is weaker than `p=`
- Fixed in: the DNS zone

## Why it matters

The `p=` tag is the action that receivers take for mail that fails DMARC.
`p=none` only collects reports, and spoofed mail is still delivered.
A record without a valid `p=` tag is not a usable policy.

The `sp=` tag sets the policy for subdomains and overrides `p=` there.
A weaker `sp=` leaves every subdomain open to spoofing, even when the apex is protected.
A subdomain without a record inherits `sp=` from the apex if it exists, and `p=` otherwise.

## Fix

Set `p=` to `quarantine` or `reject`.
Move to it after the aggregate reports (see `dmarc-rua`) show that all legitimate mail passes SPF or DKIM with alignment.

```text
_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"
```

For a weak `sp=`, remove it so that subdomains follow `p=`, or set it to the same value or a stricter one.

## Verify

```sh
dig +short TXT _dmarc.example.com
zoneposture audit --zone example.com.zone
```
