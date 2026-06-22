from __future__ import annotations

from trustfall.system import DOH_IPS, Env, NfTables


def _env():
    return Env(target_ip="10.0.0.50", target_mac="aa:bb:cc:dd:ee:ff", gateway_ip="10.0.0.1",
               gateway_mac="11:22:33:44:55:66", iface="eth0", local_ip="10.0.0.171", old_forward="0")


def _ruleset(**kw):
    return NfTables(_env(), 9900, **kw)._ruleset()


def test_single_table_with_all_three_chains():
    rs = _ruleset(redirect_ports=[80, 443])
    assert "table ip trustfall {" in rs
    assert "type nat hook prerouting priority dstnat" in rs
    assert "hook input priority filter" in rs
    assert "hook forward priority filter" in rs
    assert rs.count("table ip trustfall {") == 1


def test_redirect_uses_dport_set_and_to_proxy_port():
    rs = _ruleset(redirect_ports=[80, 443, 8883])
    assert "ip saddr 10.0.0.50 tcp dport { 80, 443, 8883 } redirect to :9900" in rs
    # the proxy port is accepted on input so the redirected flow reaches the listener
    assert "ip saddr 10.0.0.50 tcp dport 9900 accept" in rs


def test_redirect_all_tcp_when_no_ports():
    rs = _ruleset(redirect_ports=[])
    assert "ip saddr 10.0.0.50 tcp redirect to :9900" in rs


def test_target_forwarded_both_directions():
    rs = _ruleset(redirect_ports=[443])
    assert "ip saddr 10.0.0.50 accept" in rs
    assert "ip daddr 10.0.0.50 accept" in rs


def test_no_funnel_drops_by_default():
    assert "drop" not in _ruleset(redirect_ports=[443])


def test_funnel_blocks_quic_dot_doq_and_doh():
    rs = _ruleset(redirect_ports=[443], funnel=True)
    assert "ip saddr 10.0.0.50 udp dport 443 drop" in rs        # QUIC
    assert "ip saddr 10.0.0.50 tcp dport 853 drop" in rs        # DoT
    assert "ip saddr 10.0.0.50 udp dport 853 drop" in rs        # DoQ
    for ip in DOH_IPS:
        assert ip in rs                                          # DoH set
    assert "tcp dport 443 drop" in rs


def test_funnel_drops_precede_accept():
    rs = _ruleset(redirect_ports=[443], funnel=True)
    assert rs.index("udp dport 443 drop") < rs.index("ip saddr 10.0.0.50 accept")


def test_dns_redirect_and_input_accept():
    rs = _ruleset(redirect_ports=[443], funnel=True, dns_port=9953)
    assert "ip saddr 10.0.0.50 udp dport 53 redirect to :9953" in rs
    assert "ip saddr 10.0.0.50 udp dport 9953 accept" in rs


def test_install_loads_via_nft_stdin(monkeypatch):
    calls = []

    def fake_run(cmd, check=True, input_text=None):
        calls.append((cmd, input_text))
        class R:
            returncode = 0
            stdout = ""
        return R()

    import trustfall.system as system
    monkeypatch.setattr(system, "run", fake_run)
    monkeypatch.setattr(system.Path, "write_text", lambda self, *_a, **_k: None)
    NfTables(_env(), 9900, redirect_ports=[443]).install()
    loaded = [c for c in calls if c[0][:2] == ["nft", "-f"]]
    assert loaded and "table ip trustfall {" in loaded[0][1]


def test_detect_firewall_prefers_iptables_then_nft(monkeypatch):
    import trustfall.netos as netos
    monkeypatch.setattr(netos, "IS_MACOS", False)
    monkeypatch.setattr(netos.shutil, "which", lambda b: "/usr/sbin/" + b if b == "nft" else None)
    assert netos.detect_firewall("auto") == "nft"
    monkeypatch.setattr(netos.shutil, "which", lambda b: "/sbin/" + b)
    assert netos.detect_firewall("auto") == "iptables"
    assert netos.detect_firewall("nft") == "nft"


def test_dtls_redirect_and_input_accept():
    rs = _ruleset(redirect_ports=[443], funnel=True, dtls_port=9856)
    assert "ip saddr 10.0.0.50 udp dport 5684 redirect to :9856" in rs
    assert "ip saddr 10.0.0.50 udp dport 9856 accept" in rs
