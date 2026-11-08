# security-txt-location

The `security.txt` file must be served at `/.well-known/security.txt`.

- Severity: WARN
- Fixed in: the web server or application that serves the host, or the website's static files

## Why it matters

RFC 9116 defines `/.well-known/security.txt` as the location, and tools look there first.
The legacy location `/security.txt` is only allowed for backwards compatibility, and some tools do not check it.
The file is still graded, and the other `security-txt-*` findings apply to it.

## Fix

Serve the same file at `https://<host>/.well-known/security.txt`.
The legacy path can stay, or redirect to the new one.

## Verify

```sh
curl -sI https://www.example.com/.well-known/security.txt
```
