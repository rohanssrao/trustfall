from __future__ import annotations

from trustfall.system import DOH_IPS, Env, Netfilter


def _env():
    return Env(target_ip="10.0.0.50", target_mac="aa:bb:cc:dd:ee:ff", gateway_ip="10.0.0.1",
               gateway_mac="11:22:33:44:55:66", iface="eth0", local_ip="10.0.0.171", old_forward="0")


def _rule_strings(nf):
    return [" ".join(r) for r in nf._desired_rules()]


def test_base_rules_have_redirect_and_accepts():
    rules = _rule_strings(Netfilter(_env(), 9900, [80, 443]))
    assert any("PREROUTING" in r and "REDIRECT" in r and "--to-ports 9900" in r for r in rules)
    assert any("FORWARD" in r and "-s 10.0.0.50" in r and "ACCEPT" in r for r in rules)
    # no funnel drops when funnel is off
    assert not any("DROP" in r for r in rules)


def test_funnel_blocks_quic_dot_doh():
    rules = _rule_strings(Netfilter(_env(), 9900, [443], funnel=True))
    assert any("udp --dport 443 -j DROP" in r for r in rules)          # QUIC
    assert any("tcp --dport 853 -j DROP" in r for r in rules)          # DoT
    assert any("udp --dport 853 -j DROP" in r for r in rules)          # DoQ
    # DoH IPs dropped on tcp/443
    for ip in DOH_IPS:
        assert any(f"-d {ip} -p tcp --dport 443 -j DROP" in r for r in rules)


def test_dns_redirect_rules():
    rules = _rule_strings(Netfilter(_env(), 9900, [443], funnel=True, dns_port=9953))
    assert any("udp --dport 53 -j REDIRECT --to-ports 9953" in r for r in rules)
    assert any("INPUT" in r and "udp --dport 9953 -j ACCEPT" in r for r in rules)


def test_delete_cmd_strips_insert_index_for_drop():
    nf = Netfilter(_env(), 9900, [443], funnel=True)
    drop = next(r for r in nf._desired_rules() if "DROP" in r and "udp" in r and "443" in r)
    deleted = Netfilter._delete_cmd(drop)
    assert "-D" in deleted and "-I" not in deleted
    assert "1" not in deleted[: deleted.index("-D") + 2]  # the insert index was removed


def test_dtls_redirect_rules():
    rules = _rule_strings(Netfilter(_env(), 9900, [443], funnel=True, dtls_port=9856))
    assert any("udp --dport 5684 -j REDIRECT --to-ports 9856" in r for r in rules)
    assert any("INPUT" in r and "udp --dport 9856 -j ACCEPT" in r for r in rules)
