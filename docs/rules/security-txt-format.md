# security-txt-format

The `security.txt` file must be small UTF-8 text, served with `charset=utf-8`.

- Severity: FAIL when the file is larger than 64 KiB or is not valid UTF-8, WARN when the `Content-Type` does not declare `charset=utf-8`
- Fixed in: the web server or application that serves the host, or the website's static files

## Why it matters

RFC 9116 requires UTF-8 and the `text/plain` media type with a `charset` parameter.
Parsers that cannot detect the encoding can misread names or contact addresses.
A file over the size limit is not read by zoneposture and is unlikely to be a real `security.txt`.

If the file is larger than the limit or not valid UTF-8, zoneposture grades nothing else in it.

## Fix

- For a large file, keep only the fields that RFC 9116 defines, plus short comments.
- For invalid UTF-8, re-save the file as UTF-8.
- For a missing charset, serve the file with `Content-Type: text/plain; charset=utf-8`.
  Most servers set the charset for a `.txt` file from a configuration option.

## Verify

```sh
curl -sI https://www.example.com/.well-known/security.txt | grep -i content-type
```
