"""Tests for the fd leak and the FORWARD rule leak on VM delete.

See the 2026-10-29 incident: every unclosed pyroute2 IPRoute leaked two pipes,
and every delete left the VM's FORWARD rules in the ip filter table.
"""

import gc
import os
import sys
import tempfile
from unittest.mock import MagicMock, call, patch

import pytest

from firecracker.exceptions import ProcessError, VMMError
from firecracker.microvm import MicroVM
from firecracker.network import NetworkManager
from firecracker.process import ProcessManager


def _rule(handle, *matches, comment=None):
    rule = {
        "family": "ip",
        "table": "filter",
        "chain": "FORWARD",
        "handle": handle,
        "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}}
            for key, value in matches
        ]
        + [{"accept": None}],
    }
    if comment:
        rule["comment"] = comment
    return {"rule": rule}


FILTER_LISTING = [
    {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
    {"table": {"family": "ip", "name": "filter", "handle": 1}},
    {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 1}},
    _rule(10, ("iifname", "docker0"), ("oifname", "docker0")),
    _rule(11, ("iifname", "tap_abc12345"), ("oifname", "eno1")),
    _rule(12, ("iifname", "eno1"), ("oifname", "tap_abc12345")),
    _rule(13, ("oifname", "tap_abc12345"), comment="inbound to abc12345"),
    # Another VM whose tap name starts with the same characters.
    _rule(14, ("iifname", "tap_abc123456"), ("oifname", "eno1")),
]


class TestForwardRuleCleanup:
    def test_find_tap_rules_matches_exact_name_only(self, network_manager):
        rules = network_manager.find_tap_interface_rules(FILTER_LISTING, "tap_abc12345")
        assert [r["handle"] for r in rules] == [11, 12, 13]

    def test_delete_nat_rules_deletes_forward_rules_in_filter_table(
        self, network_manager
    ):
        network_manager._nft = MagicMock()
        network_manager._nft.cmd.return_value = (0, "", "")

        with patch.object(network_manager, "get_nat_rules", return_value=[]):
            with patch.object(
                network_manager, "get_filter_rules", return_value=FILTER_LISTING
            ):
                assert network_manager.delete_nat_rules("tap_abc12345") == []

        assert [c.args[0] for c in network_manager._nft.cmd.call_args_list] == [
            "delete rule ip filter FORWARD handle 11",
            "delete rule ip filter FORWARD handle 12",
            "delete rule ip filter FORWARD handle 13",
        ]

    def test_delete_nat_rules_reports_failed_handles_without_raising(
        self, network_manager
    ):
        network_manager._nft = MagicMock()
        network_manager._nft.cmd.side_effect = [
            (0, "", ""),
            (1, None, "err"),
            (0, "", ""),
        ]

        with patch.object(network_manager, "get_nat_rules", return_value=[]):
            with patch.object(
                network_manager, "get_filter_rules", return_value=FILTER_LISTING
            ):
                assert network_manager.delete_nat_rules("tap_abc12345") == ["12"]

    def test_delete_rule_uses_rule_table(self, network_manager):
        network_manager._nft = MagicMock()
        network_manager._nft.cmd.return_value = (0, "", "")

        network_manager.delete_rule(
            {"family": "ip", "table": "nat", "chain": "PREROUTING", "handle": 7}
        )

        network_manager._nft.cmd.assert_called_once_with(
            "delete rule ip nat PREROUTING handle 7"
        )

    def test_list_table_missing_table_is_empty(self, network_manager):
        with patch.object(
            network_manager,
            "_safe_nft_cmd",
            return_value=(1, None, "Error: No such file or directory"),
        ):
            assert network_manager.list_table("ip", "filter") == []


class TestIPRouteIsClosed:
    def test_network_manager_holds_no_iproute(self, network_manager):
        assert not hasattr(network_manager, "_ipr")

    def test_check_tap_device_closes_iproute(self):
        with patch("firecracker.network.IPRoute") as iproute:
            NetworkManager().check_tap_device("tap_abc12345")

        iproute.return_value.__exit__.assert_called_once()

    def test_microvm_context_manager_closes(self):
        with patch("firecracker.microvm.docker"):
            with MicroVM() as vm:
                api = vm._api = MagicMock()
                docker_client = vm._docker

        api.close.assert_called_once()
        docker_client.close.assert_called_once()


def _pipe_count():
    count = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}").startswith("pipe:"):
                count += 1
        except OSError:
            pass
    return count


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs netlink")
class TestNoPipeLeak:
    """The measurement from the incident, with the real pyroute2."""

    def _assert_no_growth(self, make):
        make()  # warm up lazy imports
        gc.collect()
        before = _pipe_count()
        for _ in range(20):
            make()
        gc.collect()
        assert _pipe_count() == before

    def test_network_manager(self):
        def make():
            nm = NetworkManager()
            nm.check_tap_device("tap_none0000")
            nm.get_links()

        self._assert_no_growth(make)

    def test_microvm_list(self):
        self._assert_no_growth(MicroVM.list)

    def test_microvm(self):
        def make():
            with patch("firecracker.microvm.docker"):
                MicroVM()

        self._assert_no_growth(make)


@pytest.fixture
def vm():
    with patch("firecracker.network.IPRoute"):
        with patch("firecracker.microvm.docker"):
            yield MicroVM()


class TestForceDelete:
    def test_force_delete_cleans_dead_vm(self, vm):
        with patch.object(vm._vmm, "list_vmm", return_value=[]):
            with patch.object(vm._vmm, "cleanup", return_value=[]) as cleanup:
                result = vm.delete(id="abc12345", force=True)

        assert result == "VMM abc12345 is deleted"
        # The shared masquerade rule stays for the other VMs.
        cleanup.assert_called_once_with("abc12345", delete_masquerade=False)

    def test_force_delete_without_nftables(self, vm):
        network = vm._vmm._network
        network._nft = None
        with patch.object(vm._vmm._process, "stop"):
            with patch.object(vm._vmm, "delete_vmm_dir"):
                with patch.object(network, "delete_tap"):
                    result = vm.delete(id="abc12345", force=True)

        assert result == "VMM abc12345 is deleted"

    def test_force_delete_raises_on_cleanup_errors(self, vm):
        with patch.object(
            vm._vmm, "cleanup", return_value=["Network cleanup failed: x"]
        ):
            with pytest.raises(VMMError, match="incomplete"):
                vm.delete(id="abc12345", force=True)

    @pytest.mark.parametrize("bad_id", ["../etc000", "abc/1234", "abc1234", "."])
    def test_force_delete_rejects_invalid_id(self, vm, bad_id):
        with patch.object(vm._vmm, "cleanup") as cleanup:
            with pytest.raises(VMMError, match="Invalid VMM ID"):
                vm.delete(id=bad_id, force=True)

        cleanup.assert_not_called()

    def test_force_delete_with_all_is_rejected(self, vm):
        with pytest.raises(ValueError):
            vm.delete(all=True, force=True)

    def test_delete_without_force_keeps_old_behaviour(self, vm):
        with patch.object(vm._vmm, "list_vmm", return_value=[{"id": "zzz99999"}]):
            assert vm.delete(id="abc12345") == "VMM with ID abc12345 not found"


class TestCleanupOrder:
    def test_directory_removed_right_after_process(self, vmm_manager):
        order = MagicMock()
        order.network_cleanup.return_value = []
        with patch.object(vmm_manager._process, "stop", order.stop):
            with patch.object(vmm_manager, "delete_vmm_dir", order.delete_vmm_dir):
                with patch.object(
                    vmm_manager._network, "cleanup", order.network_cleanup
                ):
                    assert vmm_manager.cleanup("abc12345") == []

        assert order.mock_calls == [
            call.stop("abc12345"),
            call.delete_vmm_dir("abc12345"),
            call.network_cleanup("tap_abc12345", delete_masquerade=True),
        ]

    def test_directory_removed_when_process_stop_fails(self, vmm_manager):
        stop_error = ProcessError("still running")
        with patch.object(vmm_manager._process, "stop", side_effect=stop_error):
            with patch.object(vmm_manager, "delete_vmm_dir") as delete_dir:
                with patch.object(vmm_manager._network, "cleanup", return_value=[]):
                    errors = vmm_manager.cleanup("abc12345")

        delete_dir.assert_called_once_with("abc12345")
        assert len(errors) == 1


class TestStopChecksPidOwner:
    def test_recycled_pid_is_not_killed(self):
        manager = ProcessManager()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(f"{tmpdir}/abc12345")
            # This test process stands in for an unrelated process that got
            # the dead VM's PID.
            with open(f"{tmpdir}/abc12345/firecracker.pid", "w") as f:
                f.write(str(os.getpid()))

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager, "_find_running_process", return_value=None):
                    with patch.object(manager, "_try_stop_process") as try_stop:
                        assert manager.stop("abc12345") is True

            try_stop.assert_not_called()
            assert not os.path.exists(f"{tmpdir}/abc12345/firecracker.pid")


class TestForceDeleteReportsLeftovers:
    def test_failed_forward_rule_delete_raises(self, vm):
        network = vm._vmm._network
        network._nft = MagicMock()
        network._nft.cmd.side_effect = [(0, "", ""), (1, None, "err"), (0, "", "")]
        quiet_steps = patch.multiple(
            network,
            get_nat_rules=MagicMock(return_value=[]),
            get_filter_rules=MagicMock(return_value=FILTER_LISTING),
            delete_masquerade=MagicMock(),
            delete_all_port_forward=MagicMock(),
            delete_tap=MagicMock(),
        )

        with patch.object(vm._vmm._process, "stop"):
            with patch.object(vm._vmm, "delete_vmm_dir"):
                with quiet_steps:
                    with pytest.raises(VMMError, match="handles 12"):
                        vm.delete(id="abc12345", force=True)

    def test_unreadable_pid_file_does_not_block_cleanup(self, vmm_manager):
        process = vmm_manager._process
        with tempfile.TemporaryDirectory() as tmpdir:
            vm_dir = f"{tmpdir}/abc12345"
            os.makedirs(vm_dir)
            with open(f"{vm_dir}/firecracker.pid", "w") as f:
                f.write("garbage")

            with patch.object(vmm_manager._config, "data_path", tmpdir):
                with patch.object(process._config, "data_path", tmpdir):
                    with patch.object(
                        process, "_find_running_process", return_value=None
                    ):
                        with patch.object(
                            vmm_manager._network, "cleanup", return_value=[]
                        ):
                            assert vmm_manager.cleanup("abc12345") == []

            assert not os.path.exists(vm_dir)
