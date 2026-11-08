# tls-connection

Every public address of a host must accept a TLS connection on port 443.

- Severity: FAIL when the host cannot be resolved, has no public address, refuses the connection, or fails the handshake, INFO when an IPv6 address cannot be reached from the machine that runs the audit
- Fixed in: the DNS zone, or the server behind the host

## Why it matters

zoneposture connects to each public A and AAAA address of the host separately, because a load balancer or a stale record can leave one address broken while the others work.
The certificate checks need a handshake, so no other certificate finding exists for an address that fails here.

A handshake that fails with an alert such as `internal_error`, `unrecognized_name`, or `handshake_failure` usually means that the server has no certificate configured for this name.

The INFO case says nothing about the server: the audit machine has no IPv6 route.
It is reported so that it is not mistaken for a pass.

## Fix

Find out which address fails; the message names it if the addresses differ.

- Remove records for addresses that no longer serve the host.
- Make the server listen on port 443 for the name, and open the firewall for it.
- Add the host name to the server's certificate and virtual host configuration, so that it answers requests that carry the name (SNI).
- For INFO, run the audit from a machine with IPv6 access if the host has AAAA records.

## Verify

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null
```

The output ends with a certificate chain and a `Verify return code`.
Repeat it with each address listed by `dig +short A www.example.com` and `dig +short AAAA www.example.com`, using the address in place of the host name in `-connect`.
