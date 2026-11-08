# zoneposture

**zoneposture** audits a DNS zone against modern web security standards.

---

## Key Features

- **Exhaustive Discovery:** Ingests standard BIND-formatted `.zone` files to automatically inventory all `A`, `AAAA`, and `CNAME` records.
- **Security & Compliance Audits:**
  - **Vulnerability Disclosure:** Checks for RFC 9116 compliance (`/.well-known/security.txt`).
  - **TLS/SSL Health:** Validates certificate validity, chain integrity, and expiration warnings, and checks CAA records restricting which certificate authorities may issue certificates.
  - **Security Headers:** Audits HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), and clickjacking protections (`X-Frame-Options`).
  - **Email Posture:** Audits DNS-level records (DMARC, SPF) to prevent domain spoofing.

---

## Quick Start

Run an audit against your zone file, which must be in standard BIND format:

```bash
zoneposture audit --zone example.com.zone
```

Results are printed to the terminal.

### Without a zone file

If the zone belongs to someone else, `snapshot` looks up the names you know in DNS and writes a partial zone file, which `audit` can then read:

```bash
zoneposture snapshot www.example.com app.example.com > example.com.zone
zoneposture audit --zone example.com.zone
```

The snapshot contains only what the lookups return:

- The SOA record of the enclosing zone. All names must be in the same zone.
- The `A`, `AAAA`, or `CNAME` records of each name. A `CNAME` target inside the zone is followed, a target outside it is not.
- The `CAA` records at each name and its parents up to the zone apex.
- The mail records of the zone apex and of each name that has MX or SPF records of its own:
  - `MX` and SPF (`TXT`) records.
  - The records at the conventional names `_dmarc`, `_mta-sts`, `_smtp._tls`, and `default._bimi`.
  - The host `mta-sts` if an MTA-STS record exists.
  - The `CNAME` or `TXT` records at the `_domainkey` names of common DKIM selectors, such as `google`, `selector1`, `s1`, `k1`, and `protonmail`.
- A wildcard record, if the zone has one.

Only records that exist are written.
DKIM selectors are chosen by the sender and cannot be listed in DNS, so a selector that is not on the built-in list is missing from the snapshot.
Other TXT records, such as site verification tokens, are left out.
Warnings, such as a name without records, go to stderr.
