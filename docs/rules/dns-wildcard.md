# dns-wildcard

A wildcard name in the zone is not probed.

- Severity: INFO
- Fixed in: nothing; this is informational

## Why it matters

A wildcard record such as `*.example.com` answers for every name below it, so there is no single host to connect to.
zoneposture therefore does not check its web endpoint, certificate, headers, or security.txt.
Hosts that are only reachable through the wildcard are not audited.

## Fix

No fix is needed.
To audit a host that the wildcard covers, add an explicit record for it to the zone.
When the zone belongs to someone else, list the host's name for `zoneposture snapshot`.

## Verify

```sh
zoneposture audit --zone example.com.zone
```
