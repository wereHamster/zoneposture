# caa-iodef

The `iodef` tag of a CAA record set names where CAs report requests that violate the policy.

- Severity: WARN when there is no `iodef` tag, FAIL when its value is not a `mailto:`, `http:`, or `https:` URL
- Fixed in: the DNS zone

## Why it matters

When a CA refuses a request because of the CAA policy, it may report the attempt to the `iodef` address.
Such a report is often the first sign that someone requested a certificate for the domain without permission.
CAs are not required to send reports, but they cannot send any without this tag.

## Fix

Add an `iodef` record with a monitored mailbox or a reporting endpoint.

```text
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"
```

The value must be a URL.
`"security@example.com"` without `mailto:` is invalid.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
