"""Shared fixtures and utilities for all test modules."""

import os
import random
import string
from unittest.mock import patch

import pytest

from firecracker import MicroVM
from firecracker.network import NetworkManager
from firecracker.vmm import VMMManager

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


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: mark test as an integration test")


@pytest.fixture(scope="session", autouse=True)
def pre_test_cleanup():
    """Clean up orphaned resources before test session starts."""
    cleanup_all_resources()
    yield


@pytest.fixture(scope="session", autouse=True)
def session_cleanup():
    """Clean up all resources at the end of the test session."""
    yield
    cleanup_all_resources()


@pytest.fixture
def cleanup_vms():
    """Ensure all VMs are cleaned up after tests.
    This fixture should be used by tests that create VMs."""
    yield

    try:
        import subprocess

        subprocess.run(
            ["nft", "flush", "chain", "ip", "filter", "FORWARD"],
            capture_output=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    cleanup_all_resources()


@pytest.fixture
def mock_vm():
    """Fixture that provides a mock MicroVM instance for unit tests.
    
    Note: This fixture mocks IPRoute to avoid netlink socket issues on non-Linux platforms.
    Tests that need actual network operations should mark themselves with @pytest.mark.integration
    """
    with patch('firecracker.network.IPRoute'):
        yield MicroVM(kernel_file=KERNEL_FILE, base_rootfs=BASE_ROOTFS)


@pytest.fixture
def network_manager():
    """Fixture that provides a NetworkManager instance.
    
    Note: This fixture mocks IPRoute to avoid netlink socket issues on non-Linux platforms.
    Tests that need actual network operations should mark themselves with @pytest.mark.integration
    """
    with patch('firecracker.network.IPRoute'):
        yield NetworkManager()


@pytest.fixture
def vmm_manager():
    """Fixture that provides a VMMManager instance.
    
    Note: This fixture mocks IPRoute to avoid netlink socket issues on non-Linux platforms.
    Tests that need actual network operations should mark themselves with @pytest.mark.integration
    """
    with patch('firecracker.network.IPRoute'):
        yield VMMManager()


def generate_random_id(length=8):
    """Generate a random alphanumeric ID of specified length."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def cleanup_network_resources():
    """Clean up TAP devices and nftables rules created during tests."""
    network = None
    try:
        network = NetworkManager()

        try:
            for link in network.get_links():
                ifname = link.get("ifname", "")
                if ifname.startswith("tap_"):
                    try:
                        network.delete_tap(ifname)
                    except Exception:
                        pass
        except Exception:
            pass

        if network._nft:
            try:
                import subprocess

                subprocess.run(
                    ["nft", "flush", "chain", "ip", "nat", "PREROUTING"],
                    capture_output=True,
                    timeout=5,
                )
                subprocess.run(
                    ["nft", "flush", "chain", "ip", "nat", "POSTROUTING"],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if network:
            network.close()


def cleanup_firecracker_processes():
    """Kill all Firecracker processes."""
    import psutil

    try:
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                if proc.name() == "firecracker":
                    try:
                        proc.kill()
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass


def cleanup_vmm_directories():
    """Clean up all VMM directories."""
    import shutil

    try:
        from firecracker.config import MicroVMConfig

        config = MicroVMConfig()
        data_path = config.data_path

        if os.path.exists(data_path):
            for item in os.listdir(data_path):
                item_path = os.path.join(data_path, item)
                if os.path.isdir(item_path):
                    try:
                        shutil.rmtree(item_path)
                    except Exception:
                        pass
    except Exception:
        pass


def cleanup_all_resources():
    """Clean up all Firecracker-related resources."""
    cleanup_firecracker_processes()
    cleanup_network_resources()
    cleanup_vmm_directories()
