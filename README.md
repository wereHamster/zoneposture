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
