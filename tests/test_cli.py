"""Tests for firecracker.cli (the fcpy debug tool).

These tests use a temporary data directory with hand-written config.json
fixtures and real-but-short-lived subprocesses for alive/dead PID checks.
No KVM, Docker, or nftables is required.
"""

import json
import os
import subprocess
import sys
import threading
import time

import pytest

from firecracker.cli import (
    VmIdError,
    _find_orphan_taps,
    _follow,
    _human_size,
    _tail_lines,
    append_event,
    build_parser,
    cmd_delete,
    diff_scans,
    parse_since,
    read_events,
    resolve_vm_id,
    scan_vms,
)


def write_config(
    data_path,
    vmm_id,
    name="test-vm",
    pid=None,
    running=True,
    paused=False,
    ports=None,
    ip_addr="172.16.0.2",
):
    vmm_dir = os.path.join(data_path, vmm_id)
    os.makedirs(vmm_dir, exist_ok=True)
    config = {
        "ID": vmm_id,
        "Name": name,
        "CreatedAt": "2026-09-24T09:12:03Z",
        "Rootfs": "/var/lib/firecracker/rootfs.img",
        "Kernel": "/var/lib/firecracker/vmlinux",
        "State": {"Pid": pid, "Running": running, "Paused": paused},
        "Network": {f"tap_{vmm_id}": {"IPAddress": ip_addr}},
        "Ports": ports if ports is not None else {"22/tcp": [{"HostPort": 10222, "DestPort": 22}]},
        "Labels": {"app": "worker"},
        "LogPath": f"{vmm_dir}/logs",
    }
    with open(os.path.join(vmm_dir, "config.json"), "w") as f:
        json.dump(config, f)
    return vmm_dir


@pytest.fixture
def alive_pid_for():
    """Factory fixture: alive_pid_for("vmm_id") spawns a process whose cmdline
    includes "--id <vmm_id>", matching how process.py actually invokes
    Firecracker, so _is_vm_process() correctly treats it as that VM's own
    process rather than just an arbitrary alive PID."""
    procs = []

    def _spawn(vmm_id):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)", "--id", vmm_id]
        )
        procs.append(proc)
        return proc.pid

    yield _spawn

    for proc in procs:
        proc.kill()
        proc.wait()


@pytest.fixture
def dead_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


class FakeNetworkManager:
    """Stand-in for firecracker.network.NetworkManager, no pyroute2/nftables needed."""

    def __init__(
        self,
        tap_names=(),
        nftables_available=True,
        filter_rules=None,
        masquerade_handle=None,
        fail_steps=(),
    ):
        self._tap_names = list(tap_names)
        self._nftables_available = nftables_available
        self._filter_rules = filter_rules or []
        self._masquerade_handle = masquerade_handle
        self._fail_steps = set(fail_steps)
        self.deleted_taps = []
        self.deleted_nat_rules_for = []
        self.deleted_port_forwards_for = []
        self.masquerade_deleted = False
        self.cleanup_called_with = []
        self.closed = False

    def is_nftables_available(self):
        return self._nftables_available

    def get_filter_rules(self):
        return self._filter_rules

    def get_links(self):
        return [{"ifname": name} for name in self._tap_names]

    def get_masquerade_handle(self):
        return self._masquerade_handle

    def find_tap_interface_rules(self, rules, tap_name):
        return [r for r in rules if r.get("tap") == tap_name]

    def check_tap_device(self, name):
        return name in self._tap_names

    def delete_tap(self, name):
        if "delete_tap" in self._fail_steps:
            raise Exception("simulated delete_tap failure")
        self.deleted_taps.append(name)

    def delete_nat_rules(self, tap_name):
        if "delete_nat_rules" in self._fail_steps:
            raise Exception("simulated delete_nat_rules failure")
        self.deleted_nat_rules_for.append(tap_name)

    def delete_all_port_forward(self, vmm_id):
        if "delete_all_port_forward" in self._fail_steps:
            raise Exception("simulated delete_all_port_forward failure")
        self.deleted_port_forwards_for.append(vmm_id)

    def delete_masquerade(self):
        self.masquerade_deleted = True

    def cleanup(self, tap_device):
        self.cleanup_called_with.append(tap_device)

    def close(self):
        self.closed = True


def _patch_network_manager(monkeypatch, fake_nm):
    monkeypatch.setattr("firecracker.cli._lazy_network_manager", lambda: (lambda: fake_nm))


class TestScanVms:
    def test_running_vm(self, tmp_path, alive_pid_for):
        write_config(
            str(tmp_path), "a1b2c3d4", pid=alive_pid_for("a1b2c3d4"), running=True, paused=False
        )

        vms = scan_vms(str(tmp_path))

        assert vms["a1b2c3d4"]["state"] == "running"
        assert vms["a1b2c3d4"]["name"] == "test-vm"
        assert vms["a1b2c3d4"]["ip_addr"] == "172.16.0.2"

    def test_paused_vm(self, tmp_path, alive_pid_for):
        write_config(
            str(tmp_path), "b2c3d4e5", pid=alive_pid_for("b2c3d4e5"), running=True, paused=True
        )

        vms = scan_vms(str(tmp_path))

        assert vms["b2c3d4e5"]["state"] == "paused"

    def test_does_not_trust_a_recycled_pid(self, tmp_path):
        """A PID match alone isn't enough: Linux can hand a dead VM's PID to
        an unrelated process (e.g. after a reboot). Without checking the
        process's own --id, this would misreport it as running."""
        proc = subprocess.Popen(["sleep", "30"])
        try:
            write_config(str(tmp_path), "a1b2c3d4", pid=proc.pid, running=True)

            vms = scan_vms(str(tmp_path))

            assert vms["a1b2c3d4"]["state"] == "dead"
        finally:
            proc.kill()
            proc.wait()

    def test_dead_vm(self, tmp_path, dead_pid):
        write_config(str(tmp_path), "c3d4e5f6", pid=dead_pid, running=True, paused=False)

        vms = scan_vms(str(tmp_path))

        assert vms["c3d4e5f6"]["state"] == "dead"

    def test_broken_vm_no_config(self, tmp_path):
        os.makedirs(str(tmp_path / "d4e5f6g7"))

        vms = scan_vms(str(tmp_path))

        assert vms["d4e5f6g7"]["state"] == "broken"
        assert vms["d4e5f6g7"]["name"] is None

    def test_broken_vm_corrupt_config(self, tmp_path):
        vmm_dir = tmp_path / "e5f6g7h8"
        vmm_dir.mkdir()
        (vmm_dir / "config.json").write_text("{not valid json")

        vms = scan_vms(str(tmp_path))

        assert vms["e5f6g7h8"]["state"] == "broken"

    def test_ignores_non_vmm_directories(self, tmp_path):
        (tmp_path / "snapshots").mkdir()
        (tmp_path / "events.log").write_text("")

        vms = scan_vms(str(tmp_path))

        assert vms == {}

    def test_missing_data_path_returns_empty(self, tmp_path):
        vms = scan_vms(str(tmp_path / "does-not-exist"))

        assert vms == {}


class TestDiffScans:
    def test_new_vm_is_created(self):
        prev = {}
        curr = {"a1b2c3d4": {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}}

        events = diff_scans(prev, curr)

        assert len(events) == 1
        assert events[0]["event"] == "created"
        assert events[0]["id"] == "a1b2c3d4"

    def test_new_broken_vm_is_broken_detected(self):
        prev = {}
        curr = {"a1b2c3d4": {"id": "a1b2c3d4", "name": None, "pid": None, "state": "broken", "paused": False}}

        events = diff_scans(prev, curr)

        assert events[0]["event"] == "broken_detected"

    def test_running_to_dead_is_crashed(self):
        vm_running = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}
        vm_dead = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "dead", "paused": False}

        events = diff_scans({"a1b2c3d4": vm_running}, {"a1b2c3d4": vm_dead})

        assert events[0]["event"] == "crashed"
        assert "123" in events[0]["detail"]

    def test_unpaused_to_paused_is_paused_event(self):
        before = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}
        after = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "paused", "paused": True}

        events = diff_scans({"a1b2c3d4": before}, {"a1b2c3d4": after})

        assert events[0]["event"] == "paused"

    def test_paused_to_unpaused_is_resumed_event(self):
        before = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "paused", "paused": True}
        after = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}

        events = diff_scans({"a1b2c3d4": before}, {"a1b2c3d4": after})

        assert events[0]["event"] == "resumed"

    def test_disappeared_vm_is_deleted_external(self):
        before = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}

        events = diff_scans({"a1b2c3d4": before}, {})

        assert events[0]["event"] == "deleted"
        assert events[0]["reason"] == "external"

    def test_unchanged_vm_emits_nothing(self):
        vm = {"id": "a1b2c3d4", "name": "vm", "pid": 123, "state": "running", "paused": False}

        events = diff_scans({"a1b2c3d4": vm}, {"a1b2c3d4": dict(vm)})

        assert events == []


class TestEventsLog:
    def test_append_and_read_roundtrip(self, tmp_path):
        append_event(str(tmp_path), {"ts": "2026-09-24T09:12:03Z", "id": "a1b2c3d4", "name": "vm", "event": "created", "detail": ""})
        append_event(str(tmp_path), {"ts": "2026-09-24T10:02:15Z", "id": "a1b2c3d4", "name": "vm", "event": "crashed", "detail": "pid gone"})

        events = read_events(str(tmp_path))

        assert len(events) == 2
        assert events[0]["event"] == "created"
        assert events[1]["event"] == "crashed"

    def test_read_filters_by_id_prefix(self, tmp_path):
        append_event(str(tmp_path), {"ts": "2026-09-24T09:12:03Z", "id": "a1b2c3d4", "name": "vm1", "event": "created", "detail": ""})
        append_event(str(tmp_path), {"ts": "2026-09-24T09:12:03Z", "id": "b2c3d4e5", "name": "vm2", "event": "created", "detail": ""})

        events = read_events(str(tmp_path), vmm_id="a1b2")

        assert len(events) == 1
        assert events[0]["id"] == "a1b2c3d4"

    def test_read_filters_by_since(self, tmp_path):
        append_event(str(tmp_path), {"ts": "2020-01-01T00:00:00Z", "id": "a1b2c3d4", "name": "vm", "event": "created", "detail": ""})
        append_event(str(tmp_path), {"ts": "2099-01-01T00:00:00Z", "id": "a1b2c3d4", "name": "vm", "event": "crashed", "detail": ""})

        events = read_events(str(tmp_path), since=parse_since("2026-01-01"))

        assert len(events) == 1
        assert events[0]["event"] == "crashed"

    def test_read_missing_log_returns_empty(self, tmp_path):
        assert read_events(str(tmp_path)) == []

    def test_read_skips_corrupt_lines(self, tmp_path):
        log_path = tmp_path / "events.log"
        log_path.write_text(
            '{"ts": "2026-09-24T09:12:03Z", "id": "a1b2c3d4", "name": "vm", "event": "created", "detail": ""}\n'
            "not json\n"
        )

        events = read_events(str(tmp_path))

        assert len(events) == 1


class TestParseSince:
    def test_relative_hours(self):
        since = parse_since("2h")
        assert since.tzinfo is not None

    @pytest.mark.parametrize("value", ["30m", "1d", "45s"])
    def test_relative_units(self, value):
        parse_since(value)

    def test_absolute_date(self):
        since = parse_since("2026-10-01")
        assert since.year == 2026
        assert since.month == 10

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            parse_since("not-a-duration")


class TestCmdDelete:
    def _make_args(self, data_path, vmm_id):
        parser = build_parser()
        return parser.parse_args(["--data-path", data_path, "delete", vmm_id])

    def test_delete_dead_vm_removes_directory_and_logs_event(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", pid=dead_pid, running=True, paused=False)

        args = self._make_args(data_path, "c3d4e5f6")
        rc = cmd_delete(args)

        assert rc == 0
        assert not os.path.exists(os.path.join(data_path, "c3d4e5f6"))

        events = read_events(data_path)
        assert len(events) == 1
        assert events[0]["event"] == "deleted"
        assert events[0]["reason"] == "manual"

    def test_delete_by_name(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", name="eager-lovelace", pid=dead_pid)

        args = self._make_args(data_path, "eager-lovelace")
        rc = cmd_delete(args)

        assert rc == 0
        assert not os.path.exists(os.path.join(data_path, "c3d4e5f6"))

    def test_delete_unknown_id_fails(self, tmp_path):
        args = self._make_args(str(tmp_path), "nosuchvm")
        rc = cmd_delete(args)

        assert rc == 1

    def test_delete_ambiguous_prefix_fails(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "aaaa1111", pid=dead_pid)
        write_config(data_path, "aaaa2222", pid=dead_pid)

        args = self._make_args(data_path, "aaaa")
        rc = cmd_delete(args)

        assert rc == 1
        assert os.path.exists(os.path.join(data_path, "aaaa1111"))
        assert os.path.exists(os.path.join(data_path, "aaaa2222"))

    def test_kills_live_process_on_delete(self, tmp_path, monkeypatch):
        import psutil

        # Trailing argv mimics how process.py actually invokes Firecracker
        # (--id <vmm_id>), which is what _is_vm_process checks for before
        # trusting a PID enough to kill it.
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)", "--id", "c3d4e5f6"]
        )
        try:
            data_path = str(tmp_path)
            write_config(data_path, "c3d4e5f6", pid=proc.pid)
            _patch_network_manager(monkeypatch, FakeNetworkManager())

            args = self._make_args(data_path, "c3d4e5f6")
            cmd_delete(args)

            # Reap the child ourselves: we're its direct parent, so psutil would
            # otherwise report the killed process as a still-existing zombie.
            proc.wait(timeout=5)

            assert not psutil.pid_exists(proc.pid)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_delete_does_not_kill_a_process_with_a_recycled_pid(self, tmp_path, monkeypatch):
        """A bare PID match is not enough: Linux can recycle a dead VM's PID
        onto an unrelated process. delete must only kill it if the process's
        own cmdline proves it's actually this VM's Firecracker instance."""
        proc = subprocess.Popen(["sleep", "30"])
        try:
            data_path = str(tmp_path)
            write_config(data_path, "a1b2c3d4", pid=proc.pid)
            _patch_network_manager(monkeypatch, FakeNetworkManager())

            args = self._make_args(data_path, "a1b2c3d4")
            rc = cmd_delete(args)

            assert rc == 0
            assert proc.poll() is None
        finally:
            proc.kill()
            proc.wait()

    def test_delete_cleans_up_nat_and_port_forward_rules_not_just_tap(
        self, tmp_path, dead_pid, monkeypatch
    ):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)
        fake_nm = FakeNetworkManager(tap_names=["tap_a1b2c3d4"])
        _patch_network_manager(monkeypatch, fake_nm)

        args = self._make_args(data_path, "a1b2c3d4")
        rc = cmd_delete(args)

        assert rc == 0
        assert fake_nm.deleted_nat_rules_for == ["tap_a1b2c3d4"]
        assert fake_nm.deleted_port_forwards_for == ["a1b2c3d4"]
        assert fake_nm.deleted_taps == ["tap_a1b2c3d4"]
        # NetworkManager.cleanup()/delete_masquerade() must never be used here:
        # delete_masquerade() removes the one shared rule every other running
        # VM's outbound traffic depends on.
        assert fake_nm.masquerade_deleted is False
        assert fake_nm.cleanup_called_with == []
        assert fake_nm.closed is True

    def test_delete_network_cleanup_continues_after_a_step_fails_and_warns(
        self, tmp_path, dead_pid, monkeypatch, capsys
    ):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)
        fake_nm = FakeNetworkManager(tap_names=["tap_a1b2c3d4"], fail_steps={"delete_nat_rules"})
        _patch_network_manager(monkeypatch, fake_nm)

        args = self._make_args(data_path, "a1b2c3d4")
        rc = cmd_delete(args)

        err = capsys.readouterr().err
        assert rc == 0
        # Later steps still ran despite the earlier one failing.
        assert fake_nm.deleted_port_forwards_for == ["a1b2c3d4"]
        assert fake_nm.deleted_taps == ["tap_a1b2c3d4"]
        assert "network cleanup for a1b2c3d4 was incomplete" in err


class TestCliIntegration:
    def test_events_list_via_parser(self, tmp_path, capsys):
        data_path = str(tmp_path)
        append_event(data_path, {"ts": "2026-09-24T09:12:03Z", "id": "a1b2c3d4", "name": "vm", "event": "created", "detail": ""})

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "events"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "a1b2c3d4" in out
        assert "created" in out

    def test_events_json_output(self, tmp_path, capsys):
        data_path = str(tmp_path)
        append_event(data_path, {"ts": "2026-09-24T09:12:03Z", "id": "a1b2c3d4", "name": "vm", "event": "created", "detail": ""})

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "events", "--json"])
        args.func(args)

        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed[0]["id"] == "a1b2c3d4"


class TestHelpers:
    def test_human_size_bytes(self):
        assert _human_size(500) == "500 B"

    def test_human_size_kb(self):
        assert _human_size(14540) == "14.2 KB"

    def test_human_size_none(self):
        assert _human_size(None) == "-"

    def test_find_orphan_taps(self):
        class FakeNM:
            def get_links(self):
                return [{"ifname": "tap_a1b2c3d4"}, {"ifname": "tap_zzzzzzzz"}, {"ifname": "eth0"}]

        orphans = _find_orphan_taps(FakeNM(), {"a1b2c3d4": {}})
        assert orphans == ["tap_zzzzzzzz"]

    def test_find_orphan_taps_no_network_manager(self):
        assert _find_orphan_taps(None, {}) == []


class TestResolveVmId:
    def test_full_id_match(self):
        vms = {"a1b2c3d4": {"name": "vm1"}, "e5f6g7h8": {"name": "vm2"}}
        assert resolve_vm_id(vms, "a1b2c3d4") == "a1b2c3d4"

    def test_prefix_match(self):
        vms = {"a1b2c3d4": {"name": "vm1"}}
        assert resolve_vm_id(vms, "a1b2") == "a1b2c3d4"

    def test_name_match(self):
        vms = {"a1b2c3d4": {"name": "eager-lovelace"}}
        assert resolve_vm_id(vms, "eager-lovelace") == "a1b2c3d4"

    def test_no_match_raises(self):
        with pytest.raises(VmIdError) as exc:
            resolve_vm_id({}, "nosuchvm")
        assert exc.value.code == 1
        assert "No VM matching" in str(exc.value)

    def test_ambiguous_raises(self):
        vms = {"aaaa1111": {"name": "vm1"}, "aaaa2222": {"name": "vm2"}}
        with pytest.raises(VmIdError) as exc:
            resolve_vm_id(vms, "aaaa")
        assert "Ambiguous" in str(exc.value)


class TestCmdList:
    def test_list_shows_all_states(self, tmp_path, alive_pid_for, dead_pid):
        data_path = str(tmp_path)
        write_config(
            data_path, "a1b2c3d4", name="running-vm", pid=alive_pid_for("a1b2c3d4"), running=True
        )
        write_config(data_path, "b2c3d4e5", name="dead-vm", pid=dead_pid, running=True)
        (tmp_path / "c3d4e5f6").mkdir()  # broken: no config.json

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "list"])
        rc = args.func(args)

        assert rc == 0

    def test_list_json_output(self, tmp_path, alive_pid_for, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=alive_pid_for("a1b2c3d4"))

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "list", "--json"])
        args.func(args)

        parsed = json.loads(capsys.readouterr().out)
        assert parsed[0]["id"] == "a1b2c3d4"

    def test_list_empty(self, tmp_path, capsys):
        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "list"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "No VMs found" in out


class TestCmdInspect:
    def test_inspect_dead_vm(self, tmp_path, dead_pid, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", name="eager-lovelace", pid=dead_pid, running=True)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "inspect", "c3d4e5f6"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "not running" in out
        assert "Not available: connection refused on socket" in out

    def test_inspect_json_structure(self, tmp_path, dead_pid, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", pid=dead_pid)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "inspect", "c3d4e5f6", "--json"])
        args.func(args)

        data = json.loads(capsys.readouterr().out)
        assert data["id"] == "c3d4e5f6"
        assert data["process"]["running"] is False
        assert data["live_api_error"] == "connection refused on socket"
        assert data["files"]["vmm_log"]["exists"] is False

    def test_inspect_live_process_unreachable_socket(self, tmp_path, alive_pid_for, capsys):
        data_path = str(tmp_path)
        vmm_dir = write_config(data_path, "a1b2c3d4", pid=alive_pid_for("a1b2c3d4"), running=True)
        # Socket file exists but nothing is listening on it -> a real connection failure,
        # exercising the APIError path without needing a working Firecracker socket server.
        open(os.path.join(vmm_dir, "firecracker.socket"), "w").close()

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "inspect", "a1b2c3d4", "--json"])
        args.func(args)

        data = json.loads(capsys.readouterr().out)
        assert data["process"]["running"] is True
        assert data["live_api"] is None
        assert data["live_api_error"] is not None

    def test_inspect_unknown_id(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "inspect", "nosuchvm"])
        rc = args.func(args)
        assert rc == 1


class TestCmdLogs:
    def test_tail_lines_returns_last_n(self, tmp_path):
        path = tmp_path / "test.log"
        path.write_text("\n".join(f"line{i}" for i in range(20)) + "\n")

        lines = _tail_lines(str(path), 3)

        assert len(lines) == 3
        assert lines[-1].strip() == "line19"

    def test_logs_vmm_log(self, tmp_path, dead_pid, capsys):
        data_path = str(tmp_path)
        vmm_dir = write_config(data_path, "a1b2c3d4", pid=dead_pid)
        os.makedirs(os.path.join(vmm_dir, "logs"), exist_ok=True)
        with open(os.path.join(vmm_dir, "logs", "a1b2c3d4.log"), "w") as f:
            f.write("line1\nline2\n")

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "logs", "a1b2c3d4"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "line1" in out and "line2" in out

    def test_logs_console(self, tmp_path, dead_pid, capsys):
        data_path = str(tmp_path)
        vmm_dir = write_config(data_path, "a1b2c3d4", pid=dead_pid)
        with open(os.path.join(vmm_dir, "firecracker.log"), "w") as f:
            f.write("boot message\n")

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "logs", "a1b2c3d4", "--console"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "boot message" in out

    def test_logs_missing_file(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "logs", "a1b2c3d4"])
        rc = args.func(args)

        assert rc == 1

    def test_follow_picks_up_new_lines(self, tmp_path, capsys):
        path = tmp_path / "live.log"
        path.write_text("")

        thread = threading.Thread(target=_follow, args=(str(path),), daemon=True)
        thread.start()
        time.sleep(0.2)

        with open(path, "a") as f:
            f.write("new line\n")

        time.sleep(1.0)
        out = capsys.readouterr().out
        assert "new line" in out


class TestCmdSsh:
    def test_ssh_unknown_id(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "ssh", "nosuchvm"])
        rc = args.func(args)
        assert rc == 1

    def test_ssh_no_ip(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid, ip_addr=None)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "ssh", "a1b2c3d4"])
        rc = args.func(args)

        assert rc == 1

    def test_ssh_execs_with_correct_argv(self, tmp_path, dead_pid, monkeypatch):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid, ip_addr="172.16.0.5")

        captured = {}
        monkeypatch.setattr(
            "firecracker.cli.os.execvp",
            lambda file, argv: captured.update(file=file, argv=argv),
        )

        parser = build_parser()
        args = parser.parse_args(
            ["--data-path", data_path, "ssh", "a1b2c3d4", "-i", "key.pem", "-u", "admin"]
        )
        args.func(args)

        assert captured["file"] == "ssh"
        assert "-i" in captured["argv"] and "key.pem" in captured["argv"]
        assert "172.16.0.5" in captured["argv"]
        assert "-l" in captured["argv"] and "admin" in captured["argv"]

    def test_ssh_with_trailing_command(self, tmp_path, dead_pid, monkeypatch):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid, ip_addr="172.16.0.5")

        captured = {}
        monkeypatch.setattr(
            "firecracker.cli.os.execvp",
            lambda file, argv: captured.update(file=file, argv=argv),
        )

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "ssh", "a1b2c3d4", "--", "ls", "-la"])
        args.func(args)

        assert captured["argv"][-2:] == ["ls", "-la"]


class TestCmdApi:
    def test_api_unknown_id(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "api", "nosuchvm", "/"])
        rc = args.func(args)
        assert rc == 1

    def test_api_missing_socket(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "api", "a1b2c3d4", "/"])
        rc = args.func(args)

        assert rc == 1

    def test_api_invalid_json_body(self, tmp_path, dead_pid):
        data_path = str(tmp_path)
        vmm_dir = write_config(data_path, "a1b2c3d4", pid=dead_pid)
        open(os.path.join(vmm_dir, "firecracker.socket"), "w").close()

        parser = build_parser()
        args = parser.parse_args(
            ["--data-path", data_path, "api", "a1b2c3d4", "/", "-d", "not json"]
        )
        rc = args.func(args)

        assert rc == 1


class TestCmdNet:
    def test_net_for_one_vm(self, tmp_path, dead_pid, monkeypatch, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)

        fake_nm = FakeNetworkManager(tap_names=["tap_a1b2c3d4"], masquerade_handle=42)
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "net", "a1b2c3d4"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "tap_a1b2c3d4" in out
        assert "up" in out
        assert fake_nm.closed is True

    def test_net_json(self, tmp_path, dead_pid, monkeypatch, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=dead_pid)
        fake_nm = FakeNetworkManager(tap_names=[])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "net", "a1b2c3d4", "--json"])
        args.func(args)

        data = json.loads(capsys.readouterr().out)
        assert data["interfaces"][0]["tap_exists"] is False

    def test_net_unknown_id(self, tmp_path, monkeypatch):
        fake_nm = FakeNetworkManager(tap_names=[])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "net", "nosuchvm"])
        rc = args.func(args)

        assert rc == 1


class TestCmdDoctor:
    def test_doctor_runs_all_checks(self, tmp_path, monkeypatch, capsys):
        fake_nm = FakeNetworkManager(tap_names=[])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "doctor"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc in (0, 1)
        assert "Firecracker binary" in out
        assert "KVM" in out
        assert fake_nm.closed is True

    def test_doctor_json(self, tmp_path, monkeypatch, capsys):
        fake_nm = FakeNetworkManager(tap_names=[])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", str(tmp_path), "doctor", "--json"])
        args.func(args)

        checks = json.loads(capsys.readouterr().out)
        labels = [c["label"] for c in checks]
        assert "KVM" in labels
        assert "Orphan TAP devices" in labels


class TestCmdPrune:
    def test_nothing_to_prune(self, tmp_path, alive_pid_for, monkeypatch, capsys):
        data_path = str(tmp_path)
        write_config(data_path, "a1b2c3d4", pid=alive_pid_for("a1b2c3d4"), running=True)
        fake_nm = FakeNetworkManager(tap_names=["tap_a1b2c3d4"])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "prune", "-y"])
        rc = args.func(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "Nothing to prune" in out
        assert fake_nm.deleted_taps == []

    def test_prune_removes_dead_vm_dir(self, tmp_path, dead_pid, monkeypatch):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", pid=dead_pid, running=True)
        fake_nm = FakeNetworkManager(tap_names=["tap_c3d4e5f6"])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "prune", "-y"])
        rc = args.func(args)

        assert rc == 0
        assert not os.path.exists(os.path.join(data_path, "c3d4e5f6"))

    def test_prune_does_not_touch_paused_vm_tap(self, tmp_path, alive_pid_for, monkeypatch):
        """The one real correctness trap: a present-but-paused VM's tap must
        NOT be swept up as an 'orphan' just because it isn't running."""
        data_path = str(tmp_path)
        write_config(data_path, "paused01", pid=alive_pid_for("paused01"), running=True, paused=True)

        fake_nm = FakeNetworkManager(tap_names=["tap_paused01", "tap_zzzzzzzz"])
        _patch_network_manager(monkeypatch, fake_nm)

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "prune", "-y"])
        rc = args.func(args)

        assert rc == 0
        assert "tap_paused01" not in fake_nm.deleted_taps
        assert "tap_zzzzzzzz" in fake_nm.deleted_taps
        assert os.path.exists(os.path.join(data_path, "paused01"))

    def test_prune_confirmation_prompt_abort(self, tmp_path, dead_pid, monkeypatch):
        data_path = str(tmp_path)
        write_config(data_path, "c3d4e5f6", pid=dead_pid, running=True)
        fake_nm = FakeNetworkManager(tap_names=[])
        _patch_network_manager(monkeypatch, fake_nm)
        monkeypatch.setattr("builtins.input", lambda _: "n")

        parser = build_parser()
        args = parser.parse_args(["--data-path", data_path, "prune"])
        rc = args.func(args)

        assert rc == 1
        assert os.path.exists(os.path.join(data_path, "c3d4e5f6"))
