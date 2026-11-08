# spf-all

The SPF record of a mail domain must end in `-all`.

- Severity: PASS for `-all`, WARN for `~all` or a `redirect=` modifier, FAIL for `?all`, `+all`, `all`, or no `all` mechanism
- Fixed in: the DNS zone

## Why it matters

The last mechanism decides what happens to mail from hosts that the record does not list.

- `-all` tells receivers to reject it.
- `~all` (softfail) tells receivers to accept it but treat it as suspicious.
- `?all` and a missing `all` mean neutral: the record gives no verdict on other hosts.
- `+all` and a bare `all` authorize every host in the world.

A `redirect=` modifier delegates the decision to the record of another domain.
zoneposture does not evaluate that record, so it cannot grade it.
Terms after `all` are never evaluated, and `redirect=` is ignored when `all` is present.

## Fix

End the record with `-all` once all legitimate senders are listed.

```text
example.com.  3600  IN  TXT  "v=spf1 include:_spf.example.net -all"
```

`~all` is acceptable while rolling out SPF, but it should not stay.

For a `redirect=` record, check that the record at the target ends in `-all`.
To make the grade conclusive, replace the redirect with the target's mechanisms and an `-all`.

## Verify

```sh
dig +short TXT example.com
zoneposture audit --zone example.com.zone
```
