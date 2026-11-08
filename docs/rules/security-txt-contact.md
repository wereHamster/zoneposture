# security-txt-contact

The `security.txt` file must have at least one `Contact` field with a URI, and `http:` is not allowed.

- Severity: PASS when the contacts are valid, FAIL when there is no `Contact` field, a value is not a URI, or a value uses `http:`
- Fixed in: the `security.txt` file of the host

## Why it matters

`Contact` is the one field that tells researchers where to send a report, so a file without a valid one has no use.
RFC 9116 requires the value to be a URI, such as `mailto:`, `tel:`, or `https:`, and web URIs must use HTTPS so that the address cannot be tampered with.
A bare address like `security@example.com` is not a URI.

## Fix

Add a `Contact` field for each way to reach the team.

```text
Contact: mailto:security@example.com
Contact: https://example.com/security/report
```

RFC 9116 treats the first `Contact` field as the most preferred one.

## Verify

```sh
curl -s https://www.example.com/.well-known/security.txt
zoneposture audit --zone example.com.zone
```
