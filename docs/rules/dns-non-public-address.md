# dns-non-public-address

A public DNS record points a host only to addresses that are not on the public internet.

- Severity: WARN
- Fixed in: the DNS zone

## Why it matters

The message lists the addresses and their range: loopback, private, link-local, carrier-grade NAT, documentation, or unspecified.
zoneposture does not probe them, because they are not reachable from the internet.

- Private and link-local addresses publish the layout of the internal network to everyone.
- A loopback address (`127.0.0.1`, `::1`) makes the name resolve to the visitor's own machine.
  Local services then count as same-site with the apex, which can expose cookies and other site-scoped state to them.

## Fix

Remove the record from the public zone, and serve the name from internal DNS only (split-horizon DNS).
If the host should be public, replace the address with its public one.

## Verify

```sh
dig +short A www.example.com
zoneposture audit --zone example.com.zone
```
