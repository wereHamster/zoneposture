# security-txt-canonical

If the `security.txt` file has a `Canonical` field, one value must be the URL that the file was served from.

- Severity: WARN
- Fixed in: the `security.txt` file of the host

## Why it matters

`Canonical` lists the URLs where the file is authoritative.
When none of them is the URL that was fetched, the copy at this URL is not authoritative, e.g. a file copied from another host without updating the field.
A reader cannot tell whether to trust it.

## Fix

Add the URL of the host to the `Canonical` field, or remove the field.

```text
Canonical: https://www.example.com/.well-known/security.txt
```

## Verify

```sh
curl -s https://www.example.com/.well-known/security.txt | grep -i '^canonical'
zoneposture audit --zone example.com.zone
```
