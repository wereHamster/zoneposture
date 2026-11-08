# security-txt-expires

The `security.txt` file must have exactly one `Expires` field that is in the future, but less than a year ahead.

- Severity: PASS when it expires in 30 to 366 days, WARN when it expires within 30 days or more than a year ahead, FAIL when it is missing, repeated, not an RFC 3339 date-time, or in the past
- Fixed in: the `security.txt` file of the host

## Why it matters

`Expires` tells readers when the contact information stops being reliable.
After that date, a researcher must assume that the file is stale and that nobody reads the address.
RFC 9116 recommends less than a year, so that the file is reviewed regularly.

## Fix

Set one `Expires` field with an RFC 3339 date-time in UTC, less than a year ahead.

```text
Expires: 2027-06-30T23:59:59Z
```

An expired file needs a new date.
To keep the file from expiring unnoticed, renew the date in the release process or on a schedule, e.g. every six months.

## Verify

```sh
curl -s https://www.example.com/.well-known/security.txt | grep -i '^expires'
zoneposture audit --zone example.com.zone
```
