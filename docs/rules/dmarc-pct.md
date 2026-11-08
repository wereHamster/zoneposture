# dmarc-pct

The `pct=` tag of a DMARC record must not be below 100.

- Severity: WARN
- Fixed in: the DNS zone

## Why it matters

`pct=` is the percentage of failing mail to which the policy applies.
With `pct=50`, half of the mail that fails DMARC is delivered as if the policy were weaker.
The tag is meant for a gradual rollout, and it is easy to forget it after the rollout.

## Fix

Remove the `pct=` tag, or set it to `100`.
The default is 100.

```text
_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"
```

## Verify

```sh
dig +short TXT _dmarc.example.com
zoneposture audit --zone example.com.zone
```
