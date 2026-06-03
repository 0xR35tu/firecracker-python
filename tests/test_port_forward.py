"""Tests for port forwarding functionality."""

import json
import os
from unittest.mock import patch

import pytest

from firecracker import MicroVM
from firecracker.network import NetworkManager


class TestPreroutingRuleBuild:
    """Unit tests for the PREROUTING DNAT rule builder (no nftables/KVM needed).

    Guards the `ip daddr 0.0.0.0` regression: the rule must match
    `fib daddr type local`, never an exact host-IP daddr payload.
    """

    def _build(self, **kwargs):
        with patch("firecracker.network.IPRoute"):
            nm = NetworkManager()
        defaults = dict(
            id="9fngkuf7",
            family="ip",
            host_port=37699,
            dest_ip="172.115.48.209",
            dest_port=22,
            protocol="tcp",
        )
        defaults.update(kwargs)
        return nm._build_prerouting_rule(**defaults)

    def test_uses_fib_daddr_type_local(self):
        """Rule matches any local address via fib, not a single host IP."""
        expr = self._build()["add"]["rule"]["expr"]
        fib_matches = [
            e
            for e in expr
            if "match" in e and "fib" in e["match"].get("left", {})
        ]
        assert len(fib_matches) == 1
        m = fib_matches[0]["match"]
        assert m["op"] == "=="
        assert m["left"]["fib"]["result"] == "type"
        assert "daddr" in m["left"]["fib"]["flags"]
        assert m["right"] == "local"

    def test_no_exact_daddr_payload_match(self):
        """Regression: no `ip daddr <addr>` payload match remains in the rule."""
        expr = self._build()["add"]["rule"]["expr"]
        for e in expr:
            left = e.get("match", {}).get("left", {})
            if "payload" in left:
                assert left["payload"]["field"] != "daddr"

    def test_dport_and_dnat_preserved(self):
        """dport match and dnat target unchanged."""
        expr = self._build()["add"]["rule"]["expr"]
        dport = next(
            e["match"]
            for e in expr
            if "match" in e
            and e["match"]["left"].get("payload", {}).get("field") == "dport"
        )
        assert dport["right"] == 37699
        dnat = next(e["dnat"] for e in expr if "dnat" in e)
        assert dnat == {"addr": "172.115.48.209", "port": 22}

    def test_comment_format_unchanged(self):
        """Comment key is unchanged -- deletion/idempotency paths depend on it."""
        rule = self._build()["add"]["rule"]
        assert rule["comment"] == "machine_id=9fngkuf7 host_port=37699 vm_port=22"
        assert rule["chain"] == "PREROUTING"
        assert rule["table"] == "nat"

KERNEL_FILE = "/var/lib/firecracker/vmlinux-6.1.159"
BASE_ROOTFS = "/var/lib/firecracker/devsecops-box.img"


def check_kvm_available():
    """Check if KVM is available and accessible."""
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


def check_nftables_available():
    """Check if nftables is available."""
    try:
        from nftables import Nftables

        nft = Nftables()
        nft.set_json_output(True)
        rc, _, _ = nft.cmd("list ruleset")
        return rc == 0
    except Exception:
        return False


class TestPortForwardingSetup:
    """Tests for _setup_port_forwarding method."""

    @pytest.mark.skipif(not check_nftables_available(), reason="nftables not available")
    def test_setup_port_forwarding_single_port(self):
        """Test _setup_port_forwarding with single port"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
            ip_addr="172.22.0.10",
        )

        result = vm._setup_port_forwarding(8080, 80, update_config=False)

        assert result == {"80/tcp": [{"HostPort": 8080, "DestPort": 80}]}

    def test_setup_port_forwarding_multiple_ports(self):
        """Test _setup_port_forwarding with multiple ports"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
            ip_addr="172.22.0.11",
        )

        result = vm._setup_port_forwarding([8080, 8081], [80, 443], update_config=False)

        assert result == {
            "80/tcp": [{"HostPort": 8080, "DestPort": 80}],
            "443/tcp": [{"HostPort": 8081, "DestPort": 443}],
        }

    def test_setup_port_forwarding_mismatched_counts(self):
        """Test _setup_port_forwarding with mismatched port counts"""
        vm = MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)

        with pytest.raises(
            ValueError,
            match="Number of host ports must match number of destination ports",
        ):
            vm._setup_port_forwarding([8080, 8081], [80], update_config=False)

    def test_setup_port_forwarding_with_vmm_id(self):
        """Test _setup_port_forwarding with explicit vmm_id"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
            ip_addr="172.22.0.12",
        )

        test_vmm_id = "test-vmm-id"
        result = vm._setup_port_forwarding(
            9090, 90, vmm_id=test_vmm_id, update_config=False
        )

        assert result == {"90/tcp": [{"HostPort": 9090, "DestPort": 90}]}

    def test_setup_port_forwarding_with_dest_ip(self):
        """Test _setup_port_forwarding with explicit dest_ip"""
        vm = MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)

        test_dest_ip = "192.168.1.100"
        result = vm._setup_port_forwarding(
            7070, 70, dest_ip=test_dest_ip, update_config=False
        )

        assert result == {"70/tcp": [{"HostPort": 7070, "DestPort": 70}]}


class TestPortForwardingRemoval:
    """Tests for _remove_port_forwarding method."""

    def test_remove_port_forwarding_single_port(self):
        """Test _remove_port_forwarding with single port"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS, ip_addr="172.22.0.13"
        )

        # This test verifies method doesn't raise an error
        result = vm._remove_port_forwarding(8080, 80, update_config=False)

        # The method should complete without error
        assert result is None

    def test_remove_port_forwarding_multiple_ports(self):
        """Test _remove_port_forwarding with multiple ports"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS, ip_addr="172.22.0.14"
        )

        # This test verifies method doesn't raise an error
        result = vm._remove_port_forwarding(
            [8080, 8081], [80, 443], update_config=False
        )

        # The method should complete without error
        assert result is None

    def test_remove_port_forwarding_with_vmm_id(self):
        """Test _remove_port_forwarding with explicit vmm_id"""
        vm = MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)

        test_vmm_id = "test-vmm-id"
        result = vm._remove_port_forwarding(
            9090, 90, vmm_id=test_vmm_id, update_config=False
        )

        # The method should complete without error
        assert result is None


class TestPortForwardingIntegration:
    """Integration tests for port forwarding."""

    @pytest.mark.skipif(not check_kvm_available(), reason="KVM not available")
    def test_port_forwarding(self, cleanup_vms):
        """Test port forwarding for a VM"""
        vm = MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)
        vm.create()
        id = vm._microvm_id

        host_port = 8080
        dest_port = 80

        # Add port forwarding
        result = vm.port_forward(host_port=host_port, dest_port=dest_port)
        assert f"Port forwarding added successfully for VMM {id}" in result

        # Remove port forwarding
        result = vm.port_forward(host_port=host_port, dest_port=dest_port, remove=True)
        assert f"Port forwarding removed successfully for VMM {id}" in result

    @pytest.mark.skipif(not check_kvm_available(), reason="KVM not available")
    def test_port_forwarding_existing_vmm(self, cleanup_vms):
        """Test port forwarding for an existing VMM"""
        vm = MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)
        vm.create()
        id = vm._microvm_id
        config = f"{vm._config.data_path}/{id}/config.json"

        vm.port_forward(host_port=10222, dest_port=22)
        with open(config, "r") as file:
            config = json.load(file)
            expected_ports = {"22/tcp": [{"HostPort": 10222, "DestPort": 22}]}
            assert config["Ports"] == expected_ports

    @pytest.mark.skipif(not check_kvm_available(), reason="KVM not available")
    def test_port_forwarding_remove_existing_port(self, cleanup_vms):
        """Test port forwarding removal for an existing VMM"""
        vm = MicroVM(
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
            ip_addr="172.16.0.2",
            expose_ports=True,
            host_port=10222,
            dest_port=22,
        )
        vm.create()
        id = vm._microvm_id
        config = f"{vm._config.data_path}/{id}/config.json"

        vm.port_forward(id=id, host_port=10222, dest_port=22, remove=True)
        with open(config, "r") as file:
            config = json.load(file)
            assert "22/tcp" not in config["Ports"]

    @pytest.mark.skipif(not check_kvm_available(), reason="KVM not available")
    def test_vmm_expose_single_port(self, cleanup_vms):
        """Test exposing a single port to host"""
        vm = MicroVM(
            ip_addr="172.21.0.2",
            expose_ports=True,
            host_port=10024,
            dest_port=22,
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
        )
        vm.create()
        id = vm._microvm_id
        json_path = f"{vm._config.data_path}/{id}/config.json"
        with open(json_path, "r") as json_file:
            config_data = json.load(json_file)
            expected_ports = {"22/tcp": [{"HostPort": 10024, "DestPort": 22}]}
            assert config_data["Ports"] == expected_ports

    @pytest.mark.skipif(not check_kvm_available(), reason="KVM not available")
    def test_vmm_expose_multiple_ports(self, cleanup_vms):
        """Test exposing multiple ports to host"""
        vm = MicroVM(
            ip_addr="172.21.0.2",
            expose_ports=True,
            host_port=10024,
            dest_port=22,
            kernel_file=KERNEL_FILE,
            base_rootfs=BASE_ROOTFS,
            verbose=True,
            level="DEBUG",
        )
        vm.create()
        id = vm._microvm_id

        # Add another port forwarding
        vm.port_forward(host_port=10025, dest_port=80)

        json_path = f"{vm._config.data_path}/{id}/config.json"
        with open(json_path, "r") as json_file:
            config_data = json.load(json_file)
            expected_ports = {
                "22/tcp": [{"HostPort": 10024, "DestPort": 22}],
                "80/tcp": [{"HostPort": 10025, "DestPort": 80}],
            }
            assert config_data["Ports"] == expected_ports
