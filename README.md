# Trustfall

A transparent MitM harness for sniffing and breaking TLS over a network. It ARP-spoofs the target, redirects its TCP flows through a local proxy, and tries several strategies to crack its TLS traffic. Outputs plaintext, findings by category, and a .pcap for analysis. Designed to be as easy as possible to use -- no configuration or preparation necessary.

## Usage

Run it, pick a target from the interactive LAN device picker, and Ctrl-C to stop and output a summary. You can also pass a target IP as the first argument to skip the picker.

```bash
sudo uv run trustfall
```

NixOS:

```bash
sudo nix run .
```

Docker:

```bash
sudo docker build -t trustfall .
sudo docker run --rm -it --privileged --net=host -v "$PWD/out:/out" trustfall --out /out
```

Each run creates a session directory (printed on exit) containing `summary.txt`/`summary.json`, `events.jsonl`, decrypted payloads, `capture.pcap`, and `sslkeys.log`.

## Inspecting results

Browse captured plaintext/decrypted payloads:

```bash
uv run trustfall show <session-dir>
```

Open the capture in Wireshark, decrypting the intercepted TLS with the key log:

```bash
wireshark -r <session-dir>/capture.pcap -o tls.keylog_file:<session-dir>/sslkeys.log
```

Or dump decrypted HTTP from the terminal:

```bash
tshark -nr <session-dir>/capture.pcap -o tls.keylog_file:<session-dir>/sslkeys.log -Y http
```

## Common options

```text
--out DIR                      session directory
--strategy NAME                test one strategy group (default: all). groups:
                               self-signed, private-ca, cn-only, wildcard,
                               weak-key, weak-sig, not-yet-valid, bad-eku,
                               non-ca-issuer, null-cn, weak-crypto, expired,
                               public-wrong-host
--cert/--key PEM               operator cert for public-wrong-host testing
--redirect-ports 80,443        restrict redirected TCP ports
--no-funnel                    don't block QUIC/DoH/DoT or run the DNS responder
--no-dtls                      don't intercept CoAP/DTLS on UDP 5684
--no-pcap                      don't write capture.pcap / sslkeys.log
--firewall auto|iptables|nft   Linux firewall backend (default: auto)
--verbose / --quiet / --jsonl  stdout verbosity
--cleanup-only                 remove leftover firewall rules and exit
```

## What it does

- **Cert strategies** — each isolates one validation defect, tried one per connection and rotated across reconnects: chain/trust (`self-signed`, `private-ca`, `non-ca-issuer`), hostname (`cn-only`, `wildcard`, `partial-wildcard`, `null-cn`), validity (`expired`, `not-yet-valid`), and key/signature/extension (`weak-key`, `weak-sig` SHA-1/MD5, `bad-eku`), plus `public-wrong-host` with `--cert/--key`. Rejections are classified by the client's TLS alert, and endpoints that refuse everything opaquely are flagged as **likely certificate pinning**.
- **Weak-crypto probes** — offers anonymous (`aNULL`, no certificate) and NULL-encryption (`eNULL`) ciphers; acceptance means a device can be MITM'd with no cert at all, or talks cleartext on the wire.
- **DTLS interception** — transparently MITMs **CoAP/DTLS** (UDP 5684) with the same forged-cert strategies, decrypting and capturing the CoAP underneath (X.509-mode only; PSK/raw-public-key can't be MITM'd). Requires `pyOpenSSL` and conntrack visibility (the `conntrack` tool or `/proc/net/nf_conntrack`).
- **Traffic funnel** (on by default, active mode) — blocks QUIC/HTTP3, DoH/DoT, suppresses AAAA, and strips STARTTLS so traffic falls back into the interceptable TCP+TLS path. Flags **TLS fail-open** if a device retries in cleartext after its handshake is refused.
- **Passive recon** — decodes SNI/ALPN/**JA3**, DNS, mDNS service names, and plaintext **CoAP**; flags **IPv6 escape** (traffic outside IPv4 ARP scope). Captures the *real* upstream cert for ground-truth comparison and scans payloads for secrets.
- **Outputs** — `summary.json` (per-endpoint findings + a device inventory of domains/endpoints/protocols/JA3), `events.jsonl`, per-session payloads, and a Wireshark-decryptable pcap.

## Platform support

Linux is the fully-supported platform; the firewall backend (iptables or nftables) is auto-selected. On a host whose existing nftables forward chain has a `drop` policy, the target may need to be explicitly allowed to forward (`nft list ruleset`).

macOS is **recon-only**: discovery and passive monitoring work, but transparent interception does not — macOS does not deliver pf-`rdr`'d forwarded traffic to a local listener. Use Linux to intercept.
