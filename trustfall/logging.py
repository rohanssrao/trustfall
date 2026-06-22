from __future__ import annotations

import json, time
from collections import OrderedDict
from pathlib import Path

from rich.console import Console
from rich.text import Text

from . import APP


class _BoundedSet:
    """Membership set with an LRU cap, so long-running sessions don't leak memory."""

    def __init__(self, maxsize: int = 4096):
        self.maxsize = maxsize
        self._items: OrderedDict = OrderedDict()

    def __contains__(self, key) -> bool:
        if key in self._items:
            self._items.move_to_end(key)
            return True
        return False

    def add(self, key):
        self._items[key] = None
        self._items.move_to_end(key)
        while len(self._items) > self.maxsize:
            self._items.popitem(last=False)


# Accepted-cert findings -> the validation defect they prove (shown on VULN lines).
FINDINGS = {
    "missing_chain_validation": "no chain validation (accepts self-signed)",
    "trusts_unknown_ca_or_missing_chain_validation": "accepts unknown/private CA",
    "accepted_unknown_ca_wrong_host": "accepts unknown CA + wrong hostname",
    "accepts_cn_without_san": "accepts CN-only cert (no SAN)",
    "broken_wildcard_hostname_matching": "broken wildcard hostname matching",
    "accepts_undersized_rsa_key": "accepts undersized (1024-bit) RSA key",
    "missing_hostname_validation": "no hostname validation",
    "missing_validity_period_check": "no validity-period check",
    "accepts_not_yet_valid_cert": "no validity check (accepts not-yet-valid)",
    "accepts_partial_label_wildcard": "accepts partial-label wildcard (RFC 6125 violation)",
    "accepts_weak_sig_algorithm": "accepts weak signature (SHA-1/MD5)",
    "accepts_cert_without_serverauth_eku": "ignores EKU (no serverAuth)",
    "accepts_non_ca_issuer": "broken path validation (non-CA issuer)",
    "accepts_null_byte_in_cn": "null-byte CN truncation",
    "accepts_anonymous_cipher_no_cert": "negotiates anonymous cipher \u2014 MITM with no cert",
    "accepts_null_cipher_cleartext": "negotiates NULL cipher \u2014 cleartext on the wire",
    "certificate_validation_bypass": "certificate validation bypass",
}

# tag -> (tag style, message style). Findings/attacks pop; rejections read calm
# (the device behaved correctly); recon/setup stay quiet.
_TAG_STYLE = {
    "VULN":   ("bold white on red3",     "bold red"),
    "ATTACK": ("bold white on red3",     "bold red"),
    "SECRET": ("bold white on magenta",  "magenta"),
    "REJECT": ("green",                  "green"),
    "DNS":    ("cyan",                   "dim"),
    "MDNS":   ("cyan",                   "dim"),
    "COAP":   ("cyan",                   "dim"),
    "CERT":   ("cyan",                   "dim"),
    "CAPTURE":("bold cyan",              "cyan"),
    "TCP":    ("dim cyan",               "dim"),
    "INFO":   ("blue",                   "dim"),
    "WARN":   ("bold yellow",            "yellow"),
    "ERROR":  ("bold white on red3",     "red"),
    "IPV6":   ("dim yellow",             "dim"),
}
_TAG_WIDTH = 7


def _pretty_strategy(name: str | None) -> str:
    return (name or "").replace("_match", "").replace("_", "-")


class EventLogger:
    # Per-connection plumbing that's only useful when debugging -> --verbose only.
    QUIET_KINDS = {"TCP_SYN", "TLS_CLIENTHELLO", "UDP", "UPSTREAM_TLS", "TCP"}

    def __init__(self, jsonl: bool = False, session_dir: str | None = None, verbose: bool = False, quiet: bool = False):
        self.jsonl = jsonl
        self.verbose = verbose
        self.quiet = quiet
        self.seen = _BoundedSet()
        self.console = Console(highlight=False, soft_wrap=True)
        self.events_file = None
        if session_dir:
            Path(session_dir).mkdir(parents=True, exist_ok=True)
            self.events_file = open(Path(session_dir) / "events.jsonl", "a", buffering=1)

    def emit(self, kind: str, **fields):
        fields = {k: v for k, v in fields.items() if v is not None}
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **fields}
        line = json.dumps(record, default=str)
        if self.events_file:
            self.events_file.write(line + "\n")
        if self.jsonl:
            print(line, flush=True); return
        if not self._should_print(kind, fields):
            return
        self.console.print(self._styled(dict(record)))

    def _should_print(self, kind: str, f: dict) -> bool:
        if self.verbose:
            return True
        if self.quiet:
            return kind in {"WARN", "ERROR", "SECRET", "FAIL_OPEN", "STARTTLS_STRIP", "SUMMARY", "SUMMARY_TLS"} or (
                kind == "TLS" and f.get("result") == "accepted"
            ) or (kind == "INFO" and f.get("msg") in {"stopping", "cleanup_only_done"})
        if kind in self.QUIET_KINDS:
            return False
        dedup = {
            "DNS": ("query", "dest"), "MDNS": ("services",), "DNS_SPOOF": ("query", "action"),
            "COAP": ("method", "uri"), "DTLS_CLIENTHELLO": ("dest", "version"), "IPV6_ESCAPE": ("src",),
            "TLS": ("dest", "sni", "strategy", "result", "action"),
        }.get(kind)
        if dedup:
            key = (kind, *(f.get(x) for x in dedup))
            if key in self.seen:
                return False
            self.seen.add(key)
        return True

    # --- rendering -----------------------------------------------------------

    def _styled(self, record: dict) -> Text:
        tag, msg, lines = self._parts(record)
        if lines is not None:  # multi-line header
            return lines
        ts = self._short_ts(record.get("ts", ""))
        tag_style, msg_style = _TAG_STYLE.get(tag, ("", ""))
        t = Text()
        t.append(f"{ts}  ", style="dim")
        t.append(f"{tag:<{_TAG_WIDTH}}", style=tag_style)
        t.append("  ")
        t.append(msg, style=msg_style)
        return t

    def _format_human(self, record: dict) -> str:
        """Plain-text line (used by tests and as the no-color fallback)."""
        tag, msg, lines = self._parts(dict(record))
        if lines is not None:
            return lines.plain
        ts = self._short_ts(record.get("ts", ""))
        return f"{ts}  {tag:<{_TAG_WIDTH}}  {msg}"

    @staticmethod
    def _short_ts(ts: str) -> str:
        return ts[11:19] if len(ts) >= 19 else ts

    def _parts(self, record: dict):
        """Return (tag, message, None) for a normal line, or (None, None, Text) for a header."""
        kind = record.get("kind")
        f = record

        if kind == "INFO" and "target" in f:
            return None, None, self._header(f)

        if kind == "TLS":
            dest, sni = f.get("dest"), f.get("sni", "none")
            result = f.get("result")
            if result == "accepted":
                phrase = FINDINGS.get(f.get("finding"), "certificate accepted")
                return "VULN", f"{dest} ({sni}) accepts {_pretty_strategy(f.get('strategy'))} \u2014 {phrase}", None
            if result == "rejected":
                meaning = f.get("alert_meaning") or f.get("alert") or "no accepted match"
                msg = f"{dest} ({sni}) rejected {_pretty_strategy(f.get('strategy'))} \u2014 {meaning}"
                rem = f.get("remaining")
                if isinstance(rem, int):
                    word = "strategy" if rem == 1 else "strategies"
                    tail = "awaiting reconnect" if rem else "endpoint exhausted"
                    msg += f"  [{rem} {word} left; {tail}]"
                return "REJECT", msg, None
            # skipped / no_strategy_left
            extra = f" ({f.get('action')})" if f.get("action") else ""
            return "INFO", f"{dest} ({sni}) {result}{extra}", None

        if kind == "PAYLOAD":
            label = {"tcp": "cleartext", "plaintext": "cleartext", "tls": "decrypted TLS"}.get(
                f.get("proto"), f"{f.get('proto')} (not decrypted)")
            path = f.get("path")
            where = f" \u2192 {path}" if path and path != "disabled" else " (payloads off)"
            return "CAPTURE", f"{f.get('dest')} {label}{where}", None
        if kind == "SECRET":
            return "SECRET", f"{f.get('secret')} ({f.get('direction')}) {f.get('dest')}  {f.get('value')}", None
        if kind == "FAIL_OPEN":
            return "ATTACK", f"TLS fail-open {f.get('dest')} \u2014 retried cleartext after TLS refused (sni {f.get('sni')})", None
        if kind == "STARTTLS_STRIP":
            return "ATTACK", f"STARTTLS stripped {f.get('dest', '')} \u2014 session stays cleartext".replace("  ", " "), None
        if kind == "DNS":
            return "DNS", f"{f.get('query')} \u2192 {f.get('dest')}", None
        if kind == "DNS_SPOOF":
            ans = f" \u2192 {f.get('answer')}" if f.get("answer") else ""
            return "DNS", f"{f.get('query')} {f.get('action')}{ans}", None
        if kind == "MDNS":
            return "MDNS", str(f.get("services")), None
        if kind == "COAP":
            payload = f" payload={f.get('payload')}" if f.get("payload") else ""
            return "COAP", f"{f.get('dest')} {f.get('summary')}{payload}", None
        if kind == "DTLS_CLIENTHELLO":
            return "COAP", f"{f.get('dest')} DTLS {f.get('version')} (encrypted CoAP; not decrypted)", None
        if kind == "UPSTREAM_CERT":
            flags = ",".join(n for n, on in (("self-signed", f.get("self_signed")), ("expired", f.get("expired"))) if on) or "ok"
            return "CERT", f"{f.get('dest')} real cert: {f.get('subject')} / issuer {f.get('issuer')} [{flags}]", None
        if kind == "IPV6_ESCAPE":
            return "IPV6", f"{f.get('src')} \u2192 {f.get('dst')} (IPv6, outside IPv4 ARP scope)", None
        if kind == "TCP":
            return "TCP", f"{f.get('dest')} plaintext", None
        if kind == "WARN":
            return "WARN", self._msg_with_extras(f, drop={"msg"}), None
        if kind == "ERROR":
            return "ERROR", self._msg_with_extras(f, drop={"msg"}), None
        # INFO and any unrecognized kind
        return "INFO", self._msg_with_extras(f, drop={"msg"}) or kind, None

    @staticmethod
    def _msg_with_extras(f: dict, drop: set) -> str:
        msg = f.get("msg", "")
        skip = {"ts", "kind", "hint"} | drop
        extras = {k: v for k, v in f.items() if k not in skip}
        def short(v):
            s = str(v)
            return s if len(s) <= 50 else s[:47] + "..."
        tail = "  ".join(f"{k}={short(v)}" for k, v in extras.items())
        return f"{msg}  {tail}".strip() if msg else tail

    def _header(self, f: dict) -> Text:
        t = Text()
        t.append(APP, style="bold")
        t.append("  \u2192  ")
        t.append(str(f.get("target")), style="bold cyan")
        t.append(f"  via {f.get('iface')}  (gw {f.get('gateway')}, self {f.get('local_ip')})", style="dim")
        t.append(f"\n            session  {f.get('session_dir')}", style="dim")
        return t

    def close(self):
        if self.events_file:
            self.events_file.close(); self.events_file = None
