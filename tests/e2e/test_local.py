"""Milestones 1-2: BootNext + reset, target resolution, menu, OS requests,
BootOrder re-assert and the reset-loop guard. No network involved."""


def test_default_target(scenario):
    r = scenario.prepare("--default", "beta").boot()
    assert r.has("NETBOOTY: decision=default target=beta")
    assert r.target() == "beta"
    assert r.has("BootNext=None")


def test_default_exit_continues_boot_order(scenario):
    r = scenario.prepare("--default", "exit").boot()
    assert r.has("NETBOOTY: decision=default exit")
    # Next BootOrder entry after NetBooty.
    assert r.target() == "alpha"


def test_stale_hint_resolves_by_path(scenario):
    targets = ["name=alpha,path=\\EFI\\alpha\\a.efi,hint=0109"]
    r = scenario.prepare("--default", "alpha", targets=targets).boot()
    assert r.has("target=alpha -> Boot0101")


def test_separate_windows_disk(scenario):
    r = scenario.prepare("--default", "windows").boot()
    assert r.has("target=windows -> Boot0103")
    assert r.target() == "Windows Boot Manager"
    # The same loader path on both disks is ambiguous unless pinned to a partition.
    assert r.has("target fb unavailable (Ambiguous)")


def test_partition_pin_picks_second_disk(scenario):
    r = scenario.prepare("--default", "fbb").boot()
    assert r.has("target=fbb -> Boot0105")
    assert r.has("BootCurrent=Some(0105)")


def test_detached_disk_is_skipped(scenario):
    s = scenario.prepare("--default", "windows")
    r = s.boot(attach=[s.a])
    assert r.has("target windows unavailable (partition not present)")
    assert r.has("decision=default exit")
    assert r.target() == "alpha"


def test_missing_loader_file_entry(scenario):
    # Entry exists and its partition is present, but the file is gone: the
    # firmware fails that boot and continues; NetBooty must not loop.
    r = scenario.prepare("--default", "gone").boot(timeout=90)
    assert r.has("target=gone -> Boot0106")
    assert r.exited


def test_menu_on_key(scenario):
    r = scenario.prepare("--default", "beta").boot(
        keys=[("starting Boot0100", "x"), ("Use the", "a")])
    assert r.has("decision=menu target=alpha")
    assert r.target() == "alpha"


def test_menu_always_times_out_to_automatic(scenario):
    r = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "2").boot()
    assert r.has("Automatic boot in 2s")
    assert r.has("decision=default target=beta")


def test_menu_key_restarts_countdown_once(scenario):
    # The first key restarts the countdown at 20 s; later keys (a stuck key) do not.
    down = "\x1b[B"
    r = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "2").boot(
        timeout=90, keys=[("Automatic boot in", down), ("Automatic boot in 19s", down)])
    assert r.output.count("Automatic boot in 20s") == 1
    assert r.has("decision=default target=beta")


def test_menu_always_keypress_picks(scenario):
    r = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "10").boot(
        keys=[("Automatic boot in", "1")])
    assert r.has("decision=menu target=alpha")


def test_menu_arrow_keys_and_enter(scenario):
    # Down twice from "Automatic" (alpha, beta), up once (alpha), Enter.
    down, up = "\x1b[B", "\x1b[A"
    r = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "10").boot(
        keys=[("Automatic boot in", down), ("1) alpha", down), ("2) beta", up), ("1) alpha", "\r")])
    assert r.has("decision=menu target=alpha")


def test_menu_enter_on_automatic(scenario):
    r = scenario.prepare("--default", "beta", "--menu", "always", "--menu-timeout", "10").boot(
        keys=[("Automatic boot in", "\r")])
    assert r.has("decision=default target=beta")


def test_netbooty_next_is_consumed(scenario):
    r = scenario.prepare("--default", "beta", script_extra="nbnext alpha\n").boot()
    assert r.has("decision=os-request target=alpha")
    assert r.has("NetBootyNext=false")


def test_unknown_request_falls_through(scenario):
    r = scenario.prepare("--default", "beta", script_extra="nbnext nosuch\n").boot()
    assert r.has("OS requested unknown target nosuch")
    assert r.has("decision=default target=beta")


def test_native_boot_next_bypasses_netbooty(scenario):
    r = scenario.prepare("--default", "beta", script_extra="bootnext 0101\n").boot()
    assert not r.has("NETBOOTY:")
    assert r.target() == "alpha"
    assert r.has("BootNext=None")


def test_menu_overrides_os_request(scenario):
    r = scenario.prepare("--default", "beta", "--menu", "always", script_extra="nbnext alpha\n").boot(
        keys=[("Automatic boot in", "2")])
    assert r.has("pending request from OS: alpha")
    assert r.has("decision=menu target=beta")
    assert r.has("NetBootyNext=false")


def test_boot_order_reasserted(scenario):
    # A broken first entry (file deleted after setup) stands in for an OS
    # that moved itself ahead of NetBooty.
    r = scenario.prepare("--default", "beta", script_extra="order 0106 0100 0101\n").boot()
    assert r.target() == "beta"
    assert r.has("BootOrder=0100,0106,0101")


def test_loop_guard_exits(scenario):
    r = scenario.prepare("--default", "beta", script_extra="hook ignore-bootnext\n").boot()
    assert r.has("test hook: discarding BootNext")
    assert r.has("loop guard: BootNext=Boot0102 was not honored")
    assert r.target() == "alpha"


def test_loop_guard_chainload(scenario):
    r = scenario.prepare("--default", "beta", "--fallback", "chainload",
                         script_extra="hook ignore-bootnext\n").boot()
    assert r.has("chainloading Boot0102")
    assert r.target() == "NetBooty"  # BootCurrent stays NetBooty's entry
    assert r.has("BootCurrent=Some(0100)")
