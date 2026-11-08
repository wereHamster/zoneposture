# security-txt-missing

A host must serve a `security.txt` file at `/.well-known/security.txt`.

- Severity: FAIL
- Fixed in: the web server or application that serves the host, or the website's static files

## Why it matters

`security.txt` (RFC 9116) tells security researchers how to report a vulnerability.
Without it, a researcher who finds a problem has no reliable contact, and the report may go unsent or to the wrong place.

Only a response with status 200 and the media type `text/plain` counts as a file.
Many servers answer unknown paths with status 200 and an HTML page, which does not count.
The message shows what the host returned instead.
zoneposture follows redirects that stay on HTTPS, up to 10.

The check runs for every web host in the zone separately.
A file on the apex does not cover the subdomains, unless they redirect to it.

## Fix

Serve a plain-text file at `https://<host>/.well-known/security.txt` with the required fields.

```text
Contact: mailto:security@example.com
Expires: 2027-06-30T23:59:59Z
Preferred-Languages: en
Canonical: https://www.example.com/.well-known/security.txt
```

Serve it with `Content-Type: text/plain; charset=utf-8`.
The fields are graded by `security-txt-contact`, `security-txt-expires`, and `security-txt-canonical`, and the file by `security-txt-format`.
Set `Expires` less than a year ahead.

## Verify

```sh
curl -sI https://www.example.com/.well-known/security.txt
```

The response is `200` with `content-type: text/plain; charset=utf-8`.
