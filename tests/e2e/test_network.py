"""Milestone 3: NetBooty's network step over the firmware's own stack.

QEMU's user-mode network gives the guest DHCP (10.0.2.15) and forwards its
UDP, including the 255.255.255.255 broadcast, to this host, where
echo_responder.py stands in for the boot server. Replies are only reported
in milestone 3; the boot decision must never change because of them.

The firmware network stack (EDK2 2025.02+) only starts when the machine has
a random number generator, hence virtio-rng on every networked boot.
"""

import io
import re
import socket
import subprocess
import threading
import time

import pytest

import harness
import echo_responder

NIC = "user,model=virtio-net-pci"
RNG = ["-device", "virtio-rng-pci"]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


@pytest.fixture
def responder():
    """Start the stand-in responder; yields (port, log)."""
    port = free_port()
    log = io.StringIO()
    threading.Thread(target=echo_responder.serve, args=(port,), kwargs={"out": log}, daemon=True).start()
    time.sleep(0.2)
    yield port, log


def client_id(efi) -> str:
    out = subprocess.run([str(harness.SETUP_BIN), "show", str(efi)], check=True, capture_output=True, text=True).stdout
    return re.search(r"client id:\s+([0-9a-f]{32})", out).group(1)


def test_reply_is_reported_not_acted_on(scenario, responder):
    port, log = responder
    s = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "3", "--net-port", str(port))
    r = s.boot(nic=NIC, extra=RNG)
    assert r.has("network: asking server (from 10.0.2.15)")
    assert r.has("network: reply from")
    assert r.has("decision=default target=beta")
    assert r.target() == "beta"
    # Saved for `netbooty-setup doctor` on the OS side.
    assert r.has("NetBootyNetStatus=reply from")
    # The broadcast request carried this install's client ID.
    assert f"client {client_id(s.a.files[chr(92) + 'EFI' + chr(92) + 'netbooty' + chr(92) + 'netbooty.efi'])}" in log.getvalue()


def test_unicast_server_configured(scenario, responder):
    port, log = responder
    s = scenario.prepare("--default", "beta", "--net-port", str(port), "--net-server", "10.0.2.2")
    r = s.boot(nic=NIC, extra=RNG)
    assert r.has("network: reply from")
    assert log.getvalue().count("request from") >= 1


def test_counter_nonce_without_hardware_rng(scenario, responder):
    # Without any RNG the network step still runs, with a never-repeating
    # counter nonce (first 8 bytes count up across boots).
    port, log = responder
    s = scenario.prepare("--default", "beta", "--net-port", str(port), script_extra="hook counter-nonce\n")
    first = s.boot(nic=NIC, extra=RNG)
    # Outlast NetBooty's 20 s reset-loop guard, as any real OS boot would.
    time.sleep(21)
    second = s.boot(nic=NIC, extra=RNG)
    for r in (first, second):
        assert r.has("network: no hardware RNG; using a counter nonce")
        assert r.has("network: reply from")
    nonces = re.findall(r"nonce ([0-9a-f]{32})", log.getvalue())
    counters = [int.from_bytes(bytes.fromhex(n[:16]), "little") for n in nonces]
    assert len(set(nonces)) == len(nonces), "a nonce repeated"
    assert counters == sorted(counters) and counters[0] >= 1


def test_no_responder_times_out_to_default(scenario):
    s = scenario.prepare("--default", "beta", "--net-port", str(free_port()))
    t0 = time.monotonic()
    r = s.boot(nic=NIC, extra=RNG)
    assert r.has("network: no reply")
    assert r.target() == "beta"
    assert time.monotonic() - t0 < 30


def test_dhcp_timeout_reported(scenario):
    # Too short to get an address: reported, default boot, no hang.
    s = scenario.prepare("--default", "beta", "--net-port", str(free_port()), "--net-timeout", "500")
    r = s.boot(nic=NIC, extra=RNG)
    assert r.has("network: no address (DHCP) within 0.5 s")
    assert r.target() == "beta"


def test_no_nic(scenario):
    r = scenario.prepare("--default", "beta").boot()
    assert r.has("network: no network stack; handles: SNP 0")
    assert r.has("NetBootyNetStatus=no network stack; handles: SNP 0")
    assert r.has("network: no network stack")
    assert r.target() == "beta"


def test_no_rng_means_no_firmware_stack(scenario):
    # Modern EDK2 keeps its network stack down without an RNG; NetBooty
    # explains that instead of hanging.
    r = scenario.prepare("--default", "beta").boot(nic=NIC)
    assert r.has("network: no network stack; handles: SNP 1 MNP 0")
    assert r.has("random number generator")
    assert r.target() == "beta"


def test_network_off(scenario, responder):
    port, log = responder
    r = scenario.prepare("--default", "beta", "--network", "off", "--net-port", str(port)).boot(nic=NIC, extra=RNG)
    assert not r.has("NETBOOTY: network")
    assert "request from" not in log.getvalue()
    assert r.target() == "beta"


def test_menu_pick_while_query_pending(scenario):
    # A pick during the network step drops the query cleanly.
    s = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "10",
                         "--net-port", str(free_port()), "--net-timeout", "8000")
    r = s.boot(nic=NIC, extra=RNG, keys=[("Network: asking server", "1")])
    assert r.has("decision=menu target=alpha")
    assert r.target() == "alpha"


def test_countdown_not_lengthened(scenario, responder):
    port, _ = responder
    s = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "3", "--net-port", str(port))
    t0 = time.monotonic()
    r = s.boot(nic=NIC, extra=RNG)
    with_net = time.monotonic() - t0
    assert r.has("network: reply from")
    s2 = scenario.__class__(scenario.tmp / "off")
    (scenario.tmp / "off").mkdir()
    s2.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "3", "--network", "off")
    t0 = time.monotonic()
    s2.boot(nic=NIC, extra=RNG)
    without = time.monotonic() - t0
    assert with_net < without + 2.0, (with_net, without)
