# trustfall

A transparent MitM harness for sniffing and breaking TLS over a network. It ARP poisons a target to get MitM between it and its gateway, redirects its TCP flows through a local proxy, and tries several strategies to crack its TLS traffic. Outputs plaintext, findings by category, and a .pcap for analysis. Designed to be as easy as possible to use - no configuration necessary, just point and shoot.

## What it does

- **Strategies**: tries several strategies to try to bypass valid TLS certificate handling from a MitM position, including:
    - chain/trust (self-signed, private CA, non-CA issuer)
    - hostname (CN-only, wildcard, partial wildcard, null CN)
    - validity (expired, not yet valid)
    - crypto (weak key, weak SHA-1/MD5 signature, bad EKU, anonymous and NULL-encryption ciphers)
    - presenting a cert you own (requires `--cert` and `--key`)
    - [eMudhra: forges a cert under the compromised eMudhra  "EM OV TLS CA - G3C" intermediate cert that was broken October 2026](https://en.wikipedia.org/wiki/EMudhra#2026_weak_key_incident)
- **DTLS interception**: MitMs CoAP/DTLS on UDP 5684 with the same strategies
- **Traffic funneling**: blocks QUIC/HTTP3, DoH/DoT, AAAA, and strips STARTTLS to see if a device's traffic falls back into an interceptable TCP+TLS path.
- **Passive recon**: decodes SNI, ALPN, JA3, DNS, mDNS names, and plaintext CoAP passively.

## Network changes

trustfall performs ARP spoofing to intercept and modify bidirectional traffic between a target device and its gateway. It presents itself to the target as the gateway and forwards its traffic to the real gateway with MASQUERADE. On exit, these rules are cleaned up and restored.

ARP spoofing only works within a Layer 2 broadcast domain on a network without dynamic ARP inspection or client isolation. However, this is a surprisingly common configuration, especially on home networks and many public WiFi hotspots.

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
                               public-wrong-host, emudhra
--cert/--key PEM               operator cert for public-wrong-host testing
--redirect-ports 80,443        restrict redirected TCP ports
--no-funnel                    don't block QUIC/DoH/DoT or run the DNS responder
--no-dtls                      don't intercept CoAP/DTLS on UDP 5684
--no-pcap                      don't write capture.pcap / sslkeys.log
--firewall auto|iptables|nft   Linux firewall backend (default: auto)
--verbose / --quiet / --jsonl  stdout verbosity
--cleanup-only                 remove leftover firewall rules and exit
```

## Platform support

trustfall fully supports Linux (iptables- and nftables-compatible).

macOS support is passive-only since it does not deliver pf-`rdr`'d forwarded traffic to a local listener.
