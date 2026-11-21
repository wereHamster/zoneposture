# caa-missing

The zone apex has no CAA record set.

- Severity: FAIL when a host in the zone is not covered by any CAA record set, WARN when every host is covered by a record set elsewhere or cannot be checked
- Fixed in: the DNS zone

## Why it matters

A certification authority (CA) that finds no CAA records may issue certificates for the domain and all of its subdomains.
A CAA record set limits issuance to the CAs that the domain owner chose, which reduces the risk of a mis-issued certificate.

CAs search for CAA records from the requested name up towards the root and use the first record set they find.
A record set at the apex therefore covers every name in the zone that has no record set of its own.

The lookup at each name follows CNAMEs.
A host that is a CNAME, e.g. to a hosting provider, uses the record set at the end of its alias chain if one exists there.
Such a host cannot have a record set of its own, since a CNAME cannot coexist with other records.
A zone file cannot hold the records of names outside the zone, so the audit looks up the CAA records where an alias chain leaves the zone.

The message names the hosts that no record set covers, the hosts that a record set other than the apex covers and where that record set is, and the hosts whose lookup outside the zone failed.
When every host is covered by a record set elsewhere, the finding is a warning: names added to the zone later, and names that a wildcard answers, are still not covered.
A host whose lookup failed gets a warning of its own with the error.

## Fix

Add CAA records at the zone apex.
Name the CA that issues the certificates of the zone by its CAA domain, e.g. `letsencrypt.org` for Let's Encrypt.
The CA's documentation lists its CAA domain.

```text
example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issuewild ";"
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"
```

Use `issuewild ";"` only if the zone needs no wildcard certificates.
Otherwise name the CA that issues them.

Hosts that are covered through a CNAME use the record set of their alias target and ignore the one at the apex.
If the target stops publishing CAA records, the record set at the apex applies to them, so it is safest to allow their CAs there as well.
A host with A or AAAA records at another provider needs either its CA in the record set at the apex, or a record set of its own.

Find the CA of every current certificate before publishing.
A record set that excludes the current CA makes the next renewal fail, which `certificate-caa` reports.

## Verify

```sh
dig +short CAA example.com
zoneposture audit --zone example.com.zone
```
