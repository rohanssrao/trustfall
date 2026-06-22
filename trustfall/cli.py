from __future__ import annotations

import argparse
import atexit
import json
import signal
import sys
import threading
import time
from pathlib import Path

from . import APP, __version__
from .logging import EventLogger

BANNER = f"{APP.capitalize()}: use only on devices/networks you own or are authorized to test."
DEFAULT_REDIRECT_PORTS = "80,443,8080,8443,8883"
FINDING_LABELS = {
    "self_signed_match": "HIGH missing chain validation",
    "private_ca_match": "HIGH accepts unknown/private CA",
    "private_ca_wrong_host": "HIGH accepts unknown CA and wrong hostname",
    "cn_only_match": "MEDIUM accepts cert without SAN (CN-only matching)",
    "wildcard_mismatch": "HIGH broken wildcard hostname matching",
    "partial_wildcard": "HIGH accepts partial-label wildcard",
    "weak_key": "MEDIUM accepts undersized (1024-bit) RSA key",
    "public_wrong_host": "HIGH missing hostname validation",
    "expired_match": "MEDIUM missing validity-period check",
    "not_yet_valid": "MEDIUM accepts not-yet-valid certificate",
    "weak_sig_sha1": "MEDIUM accepts SHA-1-signed certificate",
    "weak_sig_md5": "HIGH accepts MD5-signed certificate",
    "bad_eku": "MEDIUM accepts cert without serverAuth EKU",
    "non_ca_issuer": "HIGH accepts non-CA issuer (broken path validation)",
    "null_byte_cn": "HIGH accepts null-byte in certificate name",
    "anon_cipher": "HIGH negotiates anonymous cipher (MITM without any cert)",
    "null_cipher": "HIGH negotiates NULL cipher (cleartext on the wire)",
}


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog=APP, description="Transparent IoT TLS certificate-validation test harness")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("target_ip", nargs="?", help="target device IP; omit to launch the interactive picker")
    p.add_argument("cert", nargs="?", help="optional operator public certificate/fullchain PEM")
    p.add_argument("key", nargs="?", help="optional operator private key PEM")
    p.add_argument("--cert", dest="cert_opt", help="operator public certificate/fullchain PEM")
    p.add_argument("--key", dest="key_opt", help="operator private key PEM")
    p.add_argument("--mode", choices=["passive", "active"], default="active")
    p.add_argument("--strategy", choices=["all", "self-signed", "private-ca", "cn-only", "wildcard", "weak-key", "weak-sig", "not-yet-valid", "bad-eku", "non-ca-issuer", "null-cn", "weak-crypto", "public-wrong-host", "expired"], default="all")
    p.add_argument("--retest", choices=["wait", "rst", "auto"], default="wait")
    p.add_argument("--continue-after-success", action="store_true", help="keep rotating strategies after one succeeds")
    p.add_argument("--jsonl", action="store_true", help="emit full JSONL event stream on stdout")
    p.add_argument("--verbose", action="store_true", help="show low-level DNS/TCP/TLS events on stdout")
    p.add_argument("--quiet", action="store_true", help="only print important findings and final summary")
    p.add_argument("--pcap", action=argparse.BooleanOptionalAction, default=True, help="write all target packets to capture.pcap in the session dir (default: on; intercepted-TLS legs are decryptable via the sslkeys.log NSS key log)")
    p.add_argument("--no-payloads", action="store_true")
    p.add_argument("--out", help="output/session directory")
    p.add_argument("--include-udp", action="store_true")
    p.add_argument("--listen-port", type=int, default=9900)
    p.add_argument("--redirect-ports", default=DEFAULT_REDIRECT_PORTS, help="comma-separated TCP destination ports to redirect; use 'all' for all TCP")
    p.add_argument("--on-exhausted", choices=["passthrough", "close"], default="passthrough", help="what to do after all cert strategies are exhausted for an endpoint")
    p.add_argument("--no-netfilter", action="store_true", help="do not install firewall redirect rules")
    p.add_argument("--firewall", choices=["auto", "iptables", "nft"], default="auto", help="Linux firewall backend (default: auto \u2014 iptables if present, else native nftables)")
    p.add_argument("--no-arp", action="store_true", help="do not ARP spoof; useful if target already routes through this host")
    p.add_argument("--funnel", action=argparse.BooleanOptionalAction, default=True, help="block QUIC/DoH/DoT and run a DNS responder to funnel traffic into the interceptable TCP+TLS path (default: on in active mode)")
    p.add_argument("--dns-spoof-ip", help="answer A queries with this IP (full DNS redirection); default is passthrough resolve with AAAA suppressed")
    p.add_argument("--dns-spoof-domains", help="comma-separated domain suffixes to spoof with --dns-spoof-ip (default: all)")
    p.add_argument("--dns-upstream", help="upstream resolver for DNS passthrough (default: gateway)")
    p.add_argument("--dns-listen-port", type=int, default=9953)
    p.add_argument("--dtls", action=argparse.BooleanOptionalAction, default=True, help="intercept CoAP/DTLS on UDP 5684 (active mode; requires pyOpenSSL)")
    p.add_argument("--dtls-listen-port", type=int, default=9856)
    p.add_argument("--suppress-ipv6", action="store_true", help="RA-kill the real IPv6 router so the target falls back to IPv4 (aggressive, LAN-wide)")
    p.add_argument("--cleanup-only", action="store_true", help="discover target/interface, purge Trustfall netfilter rules, restore forwarding, then exit")
    return p.parse_args(argv)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "show":
        from .show import main as show_main
        return show_main(argv[1:])

    from .certs import CertificateFactory
    from .dns import DNSResponder
    from .dtls import DtlsProxy, HAVE_PYOPENSSL
    from .proxy import ProxyServer, State
    from .netos import IS_MACOS, detect_firewall
    from .system import ArpSpoofer, IPv6Suppressor, Netfilter, NfTables, discover, require_root, start_dns_sniffer

    args = parse_args(argv)
    print(BANNER, file=sys.stderr)
    require_root()

    backend = detect_firewall(args.firewall)
    Redirector = {"nft": NfTables, "iptables": Netfilter}.get(backend, Netfilter)
    if backend == "pf":
        from .pf import PacketFilter
        Redirector = PacketFilter

    cert, key = args.cert_opt or args.cert, args.key_opt or args.key
    if bool(cert) != bool(key):
        raise SystemExit("provide both cert and key, or neither")

    if not args.target_ip:
        if args.cleanup_only:
            raise SystemExit("--cleanup-only requires a target IP")
        from .picker import pick_target
        args.target_ip = pick_target()
        if not args.target_ip:
            print("no device selected", file=sys.stderr)
            return 0
        print(f"targeting {args.target_ip}", file=sys.stderr)

    session_dir = Path(args.out) if args.out else default_session_dir(args.target_ip)
    session_dir.mkdir(parents=True, exist_ok=True)
    log = EventLogger(args.jsonl, session_dir=str(session_dir), verbose=args.verbose, quiet=args.quiet)

    stop = threading.Event()
    env = discover(args.target_ip)
    log.emit("INFO", target=env.target_ip, target_mac=env.target_mac, gateway=env.gateway_ip, gateway_mac=env.gateway_mac, iface=env.iface, local_ip=env.local_ip, session_dir=str(session_dir))
    log.emit("INFO", msg="full event log", path=str(session_dir / "events.jsonl"))

    redirect_ports = parse_redirect_ports(args.redirect_ports)
    nf = None
    spoofer: ArpSpoofer | None = None
    dns_responder: DNSResponder | None = None
    ipv6_suppressor: IPv6Suppressor | None = None
    dtls_proxy = None

    if args.cleanup_only:
        Redirector(env, args.listen_port, [], dns_port=args.dns_listen_port, dtls_port=args.dtls_listen_port).purge_stale()
        log.emit("INFO", msg="cleanup_only_done", listen_port=args.listen_port)
        log.close()
        return 0

    certs = CertificateFactory(str(session_dir), cert, key)
    strategies = certs.available_strategies(args.strategy)
    if not strategies:
        raise SystemExit("no certificate strategies available; did you forget --cert/--key for public-wrong-host?")

    log.emit("INFO", strategies=",".join(strategies), mode=args.mode, retest=args.retest)
    state = State(strategies, stop_on_success=not args.continue_after_success)
    funnel = args.funnel and args.mode == "active" and not args.no_netfilter
    dns_port = args.dns_listen_port if funnel else 0
    dtls_active = args.dtls and args.mode == "active" and not args.no_netfilter and not IS_MACOS and HAVE_PYOPENSSL
    dtls_port = args.dtls_listen_port if dtls_active else 0
    keylog_path = str(session_dir / "sslkeys.log") if args.pcap else None
    proxy = ProxyServer(
        args.listen_port,
        str(session_dir),
        certs,
        state,
        log,
        mode=args.mode,
        retest=args.retest,
        no_payloads=args.no_payloads,
        on_exhausted=args.on_exhausted,
        strip_starttls=funnel,
        bind_host=env.local_ip if IS_MACOS else "0.0.0.0",
        keylog_path=keylog_path,
    )

    cleaned = False

    def cleanup():
        nonlocal cleaned, nf, spoofer, dns_responder, ipv6_suppressor, dtls_proxy
        if cleaned:
            return
        cleaned = True
        stop.set()
        proxy.stop.set()
        if dtls_proxy:
            dtls_proxy.stop.set()
        if ipv6_suppressor:
            log.emit("INFO", msg="stopping ipv6 suppression")
            ipv6_suppressor.restore()
        if dns_responder:
            log.emit("INFO", msg="stopping dns responder")
            dns_responder.restore()
        if spoofer:
            log.emit("INFO", msg="restoring arp")
            spoofer.restore()
        if nf:
            log.emit("INFO", msg="removing netfilter")
            nf.cleanup()
        print_summary(log, state, session_dir)
        log.close()

    atexit.register(cleanup)
    def handle_signal(_signo, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pcap_path = str(session_dir / "capture.pcap") if args.pcap else None
    if pcap_path:
        log.emit("INFO", msg="pcap enabled", path=pcap_path, keylog=keylog_path,
                 hint="open in Wireshark; set TLS (Pre)-Master-Secret log to sslkeys.log to decrypt intercepted TLS")
    start_dns_sniffer(env, log, stop, include_udp=args.include_udp, pcap_path=pcap_path)

    if args.mode == "active" and not args.no_netfilter:
        nf = Redirector(env, args.listen_port, redirect_ports, funnel=funnel, dns_port=dns_port, dtls_port=dtls_port)
        nf.install()
        log.emit("INFO", msg="netfilter installed", backend=backend, redirect_ports=args.redirect_ports, funnel=funnel)
        if IS_MACOS:
            log.emit("WARN", msg=(
                "macOS: transparent interception of ARP-spoofed traffic does NOT work \u2014 a macOS "
                "limitation, not a tool bug. The kernel never delivers pf-rdr'd forwarded packets to "
                "a local listener (connections stall at SYN_SENT; the rewritten packet is dropped). "
                "Verified directly that bettercap's http/https proxy fails identically here. "
                "Discovery and passive monitoring (SNI/ALPN/JA3/DNS/mDNS/CoAP) work; use Linux for "
                "TLS interception."
            ))
        elif backend == "nft":
            log.emit("INFO", msg=(
                "nftables backend active (table 'ip trustfall'). If the host already runs a forward "
                "chain with a drop policy, allow the target to forward \u2014 nft base chains don't "
                "override one another. Inspect with `nft list ruleset`."
            ))
    elif not args.no_arp:
        nf = Redirector(env, args.listen_port, redirect_ports)
        nf.enable_forwarding()
        log.emit("INFO", msg="ip_forward enabled")

    if funnel:
        upstream = args.dns_upstream or env.gateway_ip
        spoof_domains = [d.strip() for d in args.dns_spoof_domains.split(",") if d.strip()] if args.dns_spoof_domains else None
        dns_responder = DNSResponder(env, log, args.dns_listen_port, upstream,
                                     suppress_aaaa=True, spoof_ip=args.dns_spoof_ip, spoof_domains=spoof_domains,
                                     bind_host=env.local_ip if IS_MACOS else "0.0.0.0")
        dns_responder.start()
        log.emit("INFO", msg="funnel active: QUIC/DoH/DoT blocked, DNS responder up", dns_upstream=upstream,
                 dns_spoof_ip=args.dns_spoof_ip, suppress_aaaa=True)

    if dtls_active:
        dtls_proxy = DtlsProxy(args.dtls_listen_port, certs, state, log, str(session_dir),
                               bind_host="0.0.0.0", no_payloads=args.no_payloads)
        threading.Thread(target=dtls_proxy.serve, daemon=True).start()
        log.emit("INFO", msg="dtls interception active (CoAP/DTLS :5684)")
    elif args.dtls and args.mode == "active" and not args.no_netfilter and not IS_MACOS and not HAVE_PYOPENSSL:
        log.emit("WARN", msg="DTLS interception requested but pyOpenSSL not installed; CoAP/DTLS detected only")

    if not args.no_arp:
        spoofer = ArpSpoofer(env, log)
        spoofer.start()
        log.emit("INFO", msg="arp_spoofing started")
    if args.suppress_ipv6:
        ipv6_suppressor = IPv6Suppressor(env, log)
        ipv6_suppressor.start()
        log.emit("INFO", msg="ipv6 suppression started (RA-kill)")
    if args.mode == "passive":
        log.emit("INFO", msg="passive mode: sniffing only, no TCP redirect/TLS interception")

    threading.Thread(target=proxy.serve, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.emit("INFO", msg="stopping")
        return 0


def default_session_dir(target_ip: str) -> Path:
    return Path("out") / f"{time.strftime('%Y-%m-%d_%H%M%S', time.localtime())}_{target_ip}"


def parse_redirect_ports(value: str) -> list[int]:
    if value == "all":
        return []
    try:
        return [int(x) for x in value.split(",") if x.strip()]
    except ValueError as e:
        raise SystemExit(f"invalid --redirect-ports value: {value!r}") from e


def build_summary(state: State, session_dir: Path) -> dict:
    """Structured, machine-readable summary suitable for cross-device aggregation."""
    from .proxy import PINNING_ALERTS
    endpoints = []
    findings = 0
    for (ip, port, sni), st in state.summary().items():
        label = FINDING_LABELS.get(st.success_strategy) if st.success_strategy else None
        if label:
            findings += 1
        alerts = {a.alert for a in st.attempts if a.alert}
        validation_alerts = alerts & {"unknown_ca", "certificate_expired", "certificate_revoked"}
        # No strategy accepted, the client rejected with pinning-flavored alerts, and
        # never gave a normal PKI-validation alert -> likely pinning, not validation.
        likely_pinning = bool(not st.success_strategy and (alerts & PINNING_ALERTS) and not validation_alerts)
        endpoints.append({
            "endpoint": f"{ip}:{port}",
            "ip": ip,
            "port": port,
            "sni": sni,
            "accepted_strategy": st.success_strategy,
            "finding": label,
            "likely_pinning": likely_pinning,
            "attempts": [
                {"strategy": a.strategy, "result": a.result, "alert": a.alert, "error": a.error, "session": a.session}
                for a in st.attempts
            ],
        })
    return {
        "session_dir": str(session_dir),
        "findings": findings,
        "tls_endpoints": len(endpoints),
        "endpoints": endpoints,
        "inventory": build_inventory(session_dir),
        "behavioral_findings": _behavioral_findings(session_dir),
    }


def _behavioral_findings(session_dir: Path) -> dict:
    """Active-attack / coverage findings recorded as events during the run."""
    path = Path(session_dir) / "events.jsonl"
    fail_open, starttls, ipv6_escape = [], [], set()
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            kind = ev.get("kind")
            if kind == "FAIL_OPEN":
                fail_open.append({"dest": ev.get("dest"), "tls_port": ev.get("tls_port"), "sni": ev.get("sni")})
            elif kind == "STARTTLS_STRIP":
                starttls.append({"dest": ev.get("dest")})
            elif kind == "IPV6_ESCAPE" and ev.get("src"):
                ipv6_escape.add(ev["src"])
    return {"fail_open": fail_open, "starttls_stripped": starttls, "ipv6_escape": sorted(ipv6_escape)}


def build_inventory(session_dir: Path) -> dict:
    """Aggregate a behavioral profile of the target device from the event stream."""
    path = Path(session_dir) / "events.jsonl"
    domains, endpoints, mdns, protocols, ja3, secrets = set(), set(), set(), set(), set(), set()
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            kind = ev.get("kind")
            if kind == "DNS" and ev.get("query"):
                domains.add(ev["query"])
            elif kind == "TLS_CLIENTHELLO":
                if ev.get("sni") and ev["sni"] != "none":
                    domains.add(ev["sni"])
                if ev.get("ja3"):
                    ja3.add(ev["ja3"])
            elif kind == "MDNS" and ev.get("services"):
                mdns.update(ev["services"].split(","))
            elif kind == "SECRET" and ev.get("kind"):
                secrets.add(ev.get("value", ev["kind"]))
            elif kind == "COAP":
                protocols.add("coap")
            elif kind == "DTLS_CLIENTHELLO":
                protocols.add("coap-dtls")
            if ev.get("dest") and kind in ("TCP", "TCP_SYN", "TLS", "UPSTREAM_TLS", "TLS_CLIENTHELLO", "UDP", "COAP", "DTLS_CLIENTHELLO"):
                endpoints.add(ev["dest"])
            if kind in ("PAYLOAD", "UDP") and ev.get("proto"):
                protocols.add(ev["proto"])
    return {
        "domains": sorted(domains),
        "endpoints": sorted(endpoints),
        "mdns_services": sorted(mdns),
        "protocols": sorted(protocols),
        "ja3": sorted(ja3),
        "secrets_seen": len(secrets),
    }


def print_summary(log: EventLogger, state: State, session_dir: Path):
    data = build_summary(state, session_dir)
    inv = data["inventory"]
    findings, rejected = [], []
    for ep in data["endpoints"]:
        ip, port, sni = ep["ip"], ep["port"], ep["sni"]
        attempts = ";".join(f"{a['strategy']}:{a['result']}" + (f"({a['alert']})" if a["alert"] else "") for a in ep["attempts"]) or "none"
        if ep["finding"]:
            findings.append((ip, port, sni, ep["accepted_strategy"], ep["finding"], attempts))
        else:
            rejected.append((ip, port, sni, attempts, ep["likely_pinning"]))
        log.emit("SUMMARY_TLS", endpoint=f"{ip}:{port}", sni=sni or "none", attempts=attempts, finding=ep["finding"], likely_pinning=ep["likely_pinning"] or None)

    lines = ["Trustfall Summary", "==================", "", f"Session dir: {session_dir}", "", f"Findings: {len(findings)}"]
    for ip, port, sni, strategy, finding, attempts in findings:
        lines += [f"  {finding}", f"    endpoint: {ip}:{port}", f"    sni: {sni or 'none'}", f"    accepted_strategy: {strategy}", f"    attempts: {attempts}", ""]
    lines.append(f"Rejected TLS endpoints: {len(rejected)}")
    for ip, port, sni, attempts, pinning in rejected:
        tag = "  [likely certificate pinning]" if pinning else ""
        lines += [f"  {ip}:{port} sni={sni or 'none'}{tag}", f"    attempts: {attempts}"]
    lines += [
        "", "Device inventory:",
        f"  domains: {', '.join(inv['domains']) or 'none'}",
        f"  endpoints: {', '.join(inv['endpoints']) or 'none'}",
        f"  mdns: {', '.join(inv['mdns_services']) or 'none'}",
        f"  protocols: {', '.join(inv['protocols']) or 'none'}",
        f"  ja3: {', '.join(inv['ja3']) or 'none'}",
        f"  secrets captured: {inv['secrets_seen']}",
    ]
    bf = data["behavioral_findings"]
    if bf["fail_open"] or bf["starttls_stripped"] or bf["ipv6_escape"]:
        lines += ["", "Active-attack / coverage findings:"]
        for fo in bf["fail_open"]:
            lines.append(f"  HIGH TLS fail-open to cleartext: {fo['dest']} (refused TLS on :{fo['tls_port']}, retried plaintext)")
        for st in bf["starttls_stripped"]:
            lines.append(f"  HIGH STARTTLS strippable: {st['dest']} (stayed cleartext after capability removed)")
        for src in bf["ipv6_escape"]:
            lines.append(f"  INFO IPv6 escape: {src} (traffic outside IPv4 ARP scope; use --suppress-ipv6)")
    lines += ["", "Files:", f"  events: {session_dir / 'events.jsonl'}", f"  summary: {session_dir / 'summary.txt'}", f"  summary (json): {session_dir / 'summary.json'}", f"  show payloads: uv run {APP} show {session_dir}"]

    summary = "\n".join(lines) + "\n"
    (session_dir / "summary.txt").write_text(summary)
    (session_dir / "summary.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    log.emit("SUMMARY", session_dir=str(session_dir), summary=str(session_dir / "summary.txt"), summary_json=str(session_dir / "summary.json"))
    print(f"\n{summary}", flush=True)
    print(f"To view captured plaintext/decrypted payloads:\n  uv run {APP} show {session_dir}\n", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
