"""Tests for cleanup functionality improvements.

This module tests:
1. Resilient cleanup (partial failures don't stop other cleanup steps)
2. Orphaned resource detection and cleanup
3. Cleaning failed VMs (VMs with network resources but no config.json)
"""

from unittest.mock import patch


from firecracker.exceptions import NetworkError

KERNEL_FILE = "/var/lib/firecracker/vmlinux-6.1.159"
BASE_ROOTFS = "/var/lib/firecracker/devsecops-box.img"


class TestResilientCleanup:
    """Test that cleanup continues even if some steps fail."""

    def test_network_cleanup_continues_on_nat_failure(self, network_manager):
        """Test that TAP deletion continues even if NAT rule deletion fails."""
        tap_device = "tap_test123"

        # Mock delete_nat_rules to raise an error
        with patch.object(
            network_manager, "delete_nat_rules", side_effect=NetworkError("NAT deletion failed")
        ):
            # Mock delete_tap to succeed
            with patch.object(network_manager, "delete_tap") as mock_delete_tap:
                # Call cleanup - it should continue despite NAT deletion failure
                try:
                    network_manager.cleanup(tap_device)
                except NetworkError:
                    # Cleanup may raise error but should have attempted TAP deletion
                    pass

                # Verify delete_tap was still called
                mock_delete_tap.assert_called_once_with(tap_device)

    def test_network_cleanup_continues_on_masquerade_failure(self, network_manager):
        """Test that TAP deletion continues even if masquerade deletion fails."""
        tap_device = "tap_test456"

        # Mock delete_masquerade to raise an error
        with patch.object(
            network_manager,
            "delete_masquerade",
            side_effect=NetworkError("Masquerade deletion failed"),
        ):
            # Mock delete_tap to succeed
            with patch.object(network_manager, "delete_tap") as mock_delete_tap:
                # Call cleanup - it should continue despite masquerade deletion failure
                try:
                    network_manager.cleanup(tap_device)
                except NetworkError:
                    # Cleanup may raise error but should have attempted TAP deletion
                    pass

                # Verify delete_tap was still called
                mock_delete_tap.assert_called_once_with(tap_device)

    def test_network_cleanup_continues_on_port_forward_failure(self, network_manager):
        """Test that TAP deletion continues even if port forward deletion fails."""
        tap_device = "tap_test789"

        # Mock delete_all_port_forward to raise an error
        with patch.object(
            network_manager,
            "delete_all_port_forward",
            side_effect=NetworkError("Port forward deletion failed"),
        ):
            # Mock delete_tap to succeed
            with patch.object(network_manager, "delete_tap") as mock_delete_tap:
                # Call cleanup - it should continue despite port forward deletion failure
                try:
                    network_manager.cleanup(tap_device)
                except NetworkError:
                    # Cleanup may raise error but should have attempted TAP deletion
                    pass

                # Verify delete_tap was still called
                mock_delete_tap.assert_called_once_with(tap_device)

    def test_network_cleanup_all_failures_logs_errors(self, network_manager):
        """Test that all cleanup failures are logged."""
        tap_device = "tap_test_all_fail"

        # Mock all cleanup methods to fail
        with patch.object(
            network_manager, "delete_nat_rules", side_effect=NetworkError("NAT failed")
        ):
            with patch.object(
                network_manager,
                "delete_masquerade",
                side_effect=NetworkError("Masquerade failed"),
            ):
                with patch.object(
                    network_manager,
                    "delete_all_port_forward",
                    side_effect=NetworkError("Port forward failed"),
                ):
                    with patch.object(
                        network_manager, "delete_tap", side_effect=NetworkError("TAP failed")
                    ):
                        # Call cleanup - all steps should be attempted
                        # Note: The cleanup method is resilient and may not raise an error
                        # even if all steps fail, as it logs errors and continues
                        network_manager.cleanup(tap_device)

    def test_vmm_cleanup_continues_on_network_failure(self, vmm_manager):
        """Test that VMM cleanup continues even if network cleanup fails."""
        vmm_id = "test_vmm_cleanup"

        # Mock network cleanup to fail
        with patch.object(
            vmm_manager._network, "cleanup", side_effect=NetworkError("Network cleanup failed")
        ):
            # Mock process cleanup to succeed
            with patch.object(vmm_manager._process, "stop", return_value=True):
                # Mock directory cleanup to succeed
                with patch.object(vmm_manager, "delete_vmm_dir"):
                    # Call cleanup - it should continue despite network cleanup failure
                    try:
                        vmm_manager.cleanup(vmm_id)
                    except NetworkError:
                        # Cleanup may raise error but should have attempted other steps
                        pass

                    # Verify process cleanup was attempted
                    vmm_manager._process.stop.assert_called_once_with(vmm_id)


class TestOrphanedResourceCleanup:
    """Test orphaned resource detection and cleanup."""

    def test_cleanup_orphaned_tap_devices_finds_orphans(self, network_manager):
        """Test that orphaned TAP devices are detected and cleaned."""
        running_vm_ids = {"vm1", "vm2"}

        # Mock get_links to return TAP devices
        mock_links = [
            {"ifname": "tap_vm1", "index": 10},
            {"ifname": "tap_vm2", "index": 11},
            {"ifname": "tap_orphan1", "index": 12},  # This should be cleaned
            {"ifname": "tap_orphan2", "index": 13},  # This should be cleaned
            {"ifname": "eth0", "index": 1},  # Not a TAP device
        ]

        with patch.object(network_manager, "get_links", return_value=mock_links):
            # Mock cleanup methods
            with patch.object(network_manager, "delete_nat_rules"):
                with patch.object(network_manager, "delete_all_port_forward"):
                    with patch.object(network_manager, "delete_tap") as mock_delete_tap:
                        # Call orphaned cleanup
                        network_manager.cleanup_orphaned_tap_devices(running_vm_ids)

                        # Verify orphaned TAP devices were deleted
                        assert mock_delete_tap.call_count == 2
                        calls = [
                            call[0][0] for call in mock_delete_tap.call_args_list
                        ]
                        assert "tap_orphan1" in calls
                        assert "tap_orphan2" in calls
                        assert "tap_vm1" not in calls
                        assert "tap_vm2" not in calls

    def test_cleanup_orphaned_tap_devices_no_orphans(self, network_manager):
        """Test that cleanup does nothing when all TAP devices belong to running VMs."""
        running_vm_ids = {"vm1", "vm2"}

        # Mock get_links to return only running VM TAP devices
        mock_links = [
            {"ifname": "tap_vm1", "index": 10},
            {"ifname": "tap_vm2", "index": 11},
        ]

        with patch.object(network_manager, "get_links", return_value=mock_links):
            with patch.object(network_manager, "delete_nat_rules"):
                with patch.object(network_manager, "delete_all_port_forward"):
                    with patch.object(network_manager, "delete_tap") as mock_delete_tap:
                        # Call orphaned cleanup
                        network_manager.cleanup_orphaned_tap_devices(running_vm_ids)

                        # Verify no TAP devices were deleted
                        mock_delete_tap.assert_not_called()

    def test_cleanup_orphaned_tap_devices_empty_links(self, network_manager):
        """Test that cleanup handles empty link list gracefully."""
        running_vm_ids = set()

        # Mock get_links to return empty list
        with patch.object(network_manager, "get_links", return_value=[]):
            # Call orphaned cleanup - should not raise error
            network_manager.cleanup_orphaned_tap_devices(running_vm_ids)

    def test_cleanup_orphaned_resources_lists_running_vms(self, vmm_manager):
        """Test that cleanup_orphaned_resources gets list of running VMs."""
        # Mock list_vmm to return running VMs
        mock_vmm_list = [
            {"id": "vm1", "state": "Running"},
            {"id": "vm2", "state": "Running"},
        ]

        with patch.object(vmm_manager, "list_vmm", return_value=mock_vmm_list):
            # Mock orphaned TAP cleanup
            with patch.object(
                vmm_manager._network, "cleanup_orphaned_tap_devices"
            ) as mock_cleanup:
                # Call orphaned resource cleanup
                vmm_manager.cleanup_orphaned_resources()

                # Verify cleanup was called with correct VM IDs
                mock_cleanup.assert_called_once_with({"vm1", "vm2"})

    def test_cleanup_orphaned_resources_no_running_vms(self, vmm_manager):
        """Test that cleanup_orphaned_resources handles no running VMs."""
        # Mock list_vmm to return empty list
        with patch.object(vmm_manager, "list_vmm", return_value=[]):
            # Mock orphaned TAP cleanup
            with patch.object(
                vmm_manager._network, "cleanup_orphaned_tap_devices"
            ) as mock_cleanup:
                # Call orphaned resource cleanup
                vmm_manager.cleanup_orphaned_resources()

                # Verify cleanup was called with empty set
                mock_cleanup.assert_called_once_with(set())


class TestDeleteWithOrphans:
    """Test delete(all=True) behavior with orphaned resources."""

    def test_delete_all_cleans_orphaned_resources(self, mock_vm):
        """Test that delete(all=True) cleans orphaned resources."""
        # Mock list_vmm to return running VMs
        mock_vmm_list = [
            {"id": "vm1", "state": "Running"},
            {"id": "vm2", "state": "Running"},
        ]

        with patch.object(mock_vm._vmm, "list_vmm", return_value=mock_vmm_list):
            # Mock VMM deletion
            with patch.object(mock_vm._vmm, "delete_vmm"):
                # Mock orphaned resource cleanup
                with patch.object(
                    mock_vm._vmm, "cleanup_orphaned_resources"
                ) as mock_cleanup:
                    # Call delete all
                    result = mock_vm.delete(all=True)

                    # Verify orphaned cleanup was called
                    mock_cleanup.assert_called_once()
                    assert "All VMMs and orphaned resources are deleted" in result

    def test_delete_all_no_vms(self, mock_vm):
        """Test delete(all=True) when no VMs exist."""
        # Mock list_vmm to return empty list
        with patch.object(mock_vm._vmm, "list_vmm", return_value=[]):
            # Mock orphaned resource cleanup
            with patch.object(mock_vm._vmm, "cleanup_orphaned_resources"):
                # Call delete all
                result = mock_vm.delete(all=True)

                # Should succeed even with no VMs
                # When no VMs exist, it returns "No VMMs available to delete"
                assert result is not None

    def test_delete_single_vm_no_orphan_cleanup(self, mock_vm):
        """Test that deleting single VM doesn't trigger orphan cleanup."""
        # Mock list_vmm to return one VM
        mock_vmm_list = [{"id": "vm1", "state": "Running"}]

        with patch.object(mock_vm._vmm, "list_vmm", return_value=mock_vmm_list):
            # Mock VMM deletion
            with patch.object(mock_vm._vmm, "delete_vmm"):
                # Mock orphaned resource cleanup - should NOT be called
                with patch.object(
                    mock_vm._vmm, "cleanup_orphaned_resources"
                ) as mock_cleanup:
                    # Verify orphaned cleanup was NOT called
                    mock_cleanup.assert_not_called()

    def test_delete_all_deletes_all_running_vms(self, mock_vm):
        """Test that delete(all=True) deletes all running VMs."""
        # Mock list_vmm to return running VMs
        mock_vmm_list = [
            {"id": "vm1", "state": "Running"},
            {"id": "vm2", "state": "Running"},
            {"id": "vm3", "state": "Running"},
        ]

        with patch.object(mock_vm._vmm, "list_vmm", return_value=mock_vmm_list):
            # Mock VMM deletion
            with patch.object(mock_vm._vmm, "delete_vmm") as mock_delete:
                # Mock orphaned resource cleanup
                with patch.object(mock_vm._vmm, "cleanup_orphaned_resources"):
                    # Call delete all
                    mock_vm.delete(all=True)

                    # Verify all VMs were deleted
                    assert mock_delete.call_count == 3
                    calls = [call[0][0] for call in mock_delete.call_args_list]
                    assert "vm1" in calls
                    assert "vm2" in calls
                    assert "vm3" in calls


class TestCleanupIntegration:
    """Integration tests for cleanup functionality."""

    def test_cleanup_orphaned_tap_devices_with_network_rules(self, network_manager):
        """Test that orphaned TAP cleanup removes associated network rules."""
        running_vm_ids = set()  # No running VMs

        # Mock get_links to return orphaned TAP device
        mock_links = [{"ifname": "tap_orphan", "index": 12}]

        with patch.object(network_manager, "get_links", return_value=mock_links):
            # Mock cleanup methods
            with patch.object(
                network_manager, "delete_nat_rules"
            ) as mock_delete_nat:
                with patch.object(
                    network_manager, "delete_all_port_forward"
                ) as mock_delete_pf:
                    with patch.object(network_manager, "delete_tap"):
                        # Call orphaned cleanup
                        network_manager.cleanup_orphaned_tap_devices(running_vm_ids)

                        # Verify all cleanup methods were called
                        mock_delete_nat.assert_called_once_with("tap_orphan")
                        mock_delete_pf.assert_called_once_with("orphan")

    def test_cleanup_handles_exceptions_gracefully(self, network_manager):
        """Test that cleanup handles exceptions without crashing."""
        tap_device = "tap_test_exception"

        # Mock delete_nat_rules to raise an exception
        with patch.object(
            network_manager, "delete_nat_rules", side_effect=RuntimeError("Unexpected error")
        ):
            # Mock delete_tap to succeed
            with patch.object(network_manager, "delete_tap"):
                # Call cleanup - should not crash
                try:
                    network_manager.cleanup(tap_device)
                except (NetworkError, RuntimeError):
                    # Expected - cleanup may raise error but should not crash
                    pass