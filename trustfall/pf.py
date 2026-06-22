from __future__ import annotations

import tempfile
from pathlib import Path

from .netos import DOH_IPS, enable_forwarding, restore_forwarding, run

PF_CONF = "/etc/pf.conf"


class PacketFilter:
    """macOS pf backend mirroring the Linux Netfilter interface.

    Transparent interception on macOS uses pf `rdr` rules pointing at the local
    proxy; the original destination is later recovered by parsing `pfctl -s state`
    (see netos.original_dst). Loading a ruleset with `pfctl -f` replaces the
    active ruleset for the session; cleanup restores /etc/pf.conf.

    NOTE: rule generation is correct and matches bettercap's recipe, but on recent
    macOS the kernel does not deliver pf-rdr'd *forwarded* (ARP-spoofed) packets to
    a local listener (connections stall at SYN_SENT) — a platform limitation that
    also affects bettercap. macOS is therefore recon-only; use Linux to intercept.
    """

    def __init__(self, env, port: int, redirect_ports: list[int] | None = None,
                 funnel: bool = False, dns_port: int = 0, dtls_port: int = 0):
        self.env = env
        self.port = port
        self.redirect_ports = redirect_ports or []
        self.funnel = funnel
        self.dns_port = dns_port
        self.dtls_port = dtls_port  # accepted for backend parity; macOS interception is recon-only
        self._was_enabled = False
        self._conf_path: str | None = None

    def enable_forwarding(self):
        enable_forwarding()

    def install(self):
        self.enable_forwarding()
        self._was_enabled = "Status: Enabled" in run(["pfctl", "-s", "info"], check=False).stdout
        fd, path = tempfile.mkstemp(prefix="trustfall-pf-", suffix=".conf")
        Path(path).write_text(self.ruleset())
        self._conf_path = path
        run(["pfctl", "-f", path])
        if not self._was_enabled:
            run(["pfctl", "-e"], check=False)

    def cleanup(self):
        run(["pfctl", "-f", PF_CONF], check=False)   # restore the system ruleset
        if not self._was_enabled:
            run(["pfctl", "-d"], check=False)
        restore_forwarding(self.env.old_forward)
        if self._conf_path:
            try:
                Path(self._conf_path).unlink()
            except OSError:
                pass

    def purge_stale(self):
        # Best-effort: reloading the system ruleset drops any rules we left behind.
        run(["pfctl", "-f", PF_CONF], check=False)

    def ruleset(self) -> str:
        """Generate a minimal pf ruleset (mitmproxy-style).

        Deliberately does NOT import Apple's com.apple anchors: those carry
        block/quick rules that drop forwarded (transit) traffic, which black-holes
        the target. pf order is translation (rdr) then filtering; funnel blocks use
        `quick` so they aren't overridden by the trailing default `pass`.
        """
        e = self.env
        to = e.local_ip  # rdr to the en0 IP AND bind the proxy there (see ProxyServer
        # bind_host): on macOS a forwarded packet rewritten to the iface IP is only
        # delivered to a socket bound to that exact IP, not INADDR_ANY; loopback rdr
        # doesn't match forwarded traffic at all. This is bettercap's approach.
        lines: list[str] = []
        # --- translation (rdr) ---
        if self.dns_port:
            lines.append(
                f"rdr pass on {e.iface} inet proto udp from {e.target_ip} to any port 53 "
                f"-> {to} port {self.dns_port}"
            )
        if self.redirect_ports:
            portspec = "{ " + ", ".join(str(p) for p in self.redirect_ports) + " }"
            lines.append(
                f"rdr pass on {e.iface} inet proto tcp from {e.target_ip} to any port {portspec} "
                f"-> {to} port {self.port}"
            )
        else:
            lines.append(
                f"rdr pass on {e.iface} inet proto tcp from {e.target_ip} to any "
                f"-> {to} port {self.port}"
            )
        # --- filtering ---
        # NOTE: emit NO bare `pass`. pf already defaults to pass for unmatched
        # traffic, and an explicit stateful `pass` matches both directions and
        # creates state that conflicts with the rdr'd flow, silently breaking
        # forwarding/redirection (bettercap's working ruleset is rdr-only).
        if self.funnel:
            lines.append(f"block drop quick on {e.iface} inet proto udp from {e.target_ip} to any port 443")   # QUIC
            lines.append(f"block drop quick on {e.iface} inet proto {{ tcp udp }} from {e.target_ip} to any port 853")  # DoT/DoQ
            for ip in DOH_IPS:
                lines.append(f"block drop quick on {e.iface} inet proto tcp from {e.target_ip} to {ip} port 443")  # DoH
        return "\n".join(lines) + "\n"
