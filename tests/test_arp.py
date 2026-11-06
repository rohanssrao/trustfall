"""ArpSpoofer: router mode only ever lies to the target, from our own MAC."""
from __future__ import annotations

from scapy.all import ARP, Ether  # type: ignore

from trustfall import system
from trustfall.system import ArpSpoofer, Env

OURS = "02:00:00:00:00:aa"


class _Log:
    def emit(self, *a, **k):
        pass


def _spoofer(monkeypatch):
    sent = []
    monkeypatch.setattr(system, "get_if_hwaddr", lambda iface: OURS)
    monkeypatch.setattr(system, "sendp", lambda frame, **kw: sent.append(frame))
    env = Env(target_ip="192.0.2.50", target_mac="02:00:00:00:00:50", gateway_ip="192.0.2.1",
              gateway_mac="02:00:00:00:00:01", iface="eth0", local_ip="192.0.2.10", old_forward="0")
    return ArpSpoofer(env, _Log()), env, sent


def test_poison_reaches_only_the_target(monkeypatch):
    sp, env, sent = _spoofer(monkeypatch)
    sp._poison()
    assert sent
    for f in sent:
        assert f[Ether].src == OURS and f[Ether].dst == env.target_mac
        assert f[ARP].psrc == env.gateway_ip and f[ARP].hwsrc == OURS
        assert f[ARP].pdst == env.target_ip


def test_restore_tells_the_truth_from_our_own_mac(monkeypatch):
    sp, env, sent = _spoofer(monkeypatch)
    sp.restore()
    assert sent and all(f[Ether].src == OURS for f in sent)
    claims = {(f[ARP].psrc, f[ARP].hwsrc) for f in sent}
    assert claims == {(env.gateway_ip, env.gateway_mac), (env.target_ip, env.target_mac)}
    assert any(f[Ether].dst == env.target_mac for f in sent)
