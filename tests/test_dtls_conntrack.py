from __future__ import annotations

import trustfall.dtls as dtls

# A representative REDIRECT'd UDP flow: original dst is the real CoAP server, the
# reply tuple shows the DNAT to our proxy port.
SAMPLE = [
    "ipv4 2 udp 17 29 src=10.13.37.10 dst=10.13.37.1 sport=54321 dport=5684 "
    "[UNREPLIED] src=10.13.37.66 dst=10.13.37.10 sport=9856 dport=54321 mark=0 use=1",
    "ipv4 2 tcp 6 431999 ESTABLISHED src=10.13.37.10 dst=1.2.3.4 sport=5555 dport=443 ...",
]


def test_origdst_recovered_from_conntrack(monkeypatch):
    monkeypatch.setattr(dtls, "_conntrack_lines", lambda: SAMPLE)
    assert dtls.origdst_via_conntrack("10.13.37.10", 54321) == ("10.13.37.1", 5684)


def test_origdst_no_match_returns_none(monkeypatch):
    monkeypatch.setattr(dtls, "_conntrack_lines", lambda: SAMPLE)
    assert dtls.origdst_via_conntrack("10.0.0.99", 12345) is None
    # wrong dport (not a DTLS flow)
    assert dtls.origdst_via_conntrack("10.13.37.10", 54321, dport=9999) is None


def test_origdst_empty_table(monkeypatch):
    monkeypatch.setattr(dtls, "_conntrack_lines", lambda: [])
    assert dtls.origdst_via_conntrack("10.13.37.10", 54321) is None
