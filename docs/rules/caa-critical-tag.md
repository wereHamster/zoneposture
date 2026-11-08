# caa-critical-tag

A CAA record has the critical flag set on a tag that is not registered with IANA.

- Severity: FAIL
- Fixed in: the DNS zone

## Why it matters

A CA must refuse to issue a certificate when a record set contains a critical tag that the CA does not understand (RFC 8659, section 4.1).
The record set therefore blocks every CA from issuing certificates for the name and its subdomains, and renewals fail.

The registered tags are `issue`, `issuewild`, `iodef`, `issuemail`, `issuevmc`, `contactemail`, and `contactphone`.
A common cause is a misspelled tag, e.g. `issues` instead of `issue`.

## Fix

Correct the tag name if it is misspelled.
Otherwise set the flags value to `0` so that CAs ignore the tag, or remove the record.

```text
example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
```

## Verify

```sh
dig +short CAA example.com
```

The flags value, the first number of each record, is `0` for every record whose tag is not registered.
