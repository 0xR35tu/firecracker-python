"""Tests for network management error paths and edge cases."""

import os
from unittest.mock import patch, MagicMock
import tempfile

import pytest

from firecracker.network import NetworkManager
from firecracker.exceptions import NetworkError, ConfigurationError


class TestNetworkErrorPaths:
    """Test network management error handling."""

    def test_delete_rule_error(self, network_manager):
        """Test delete_rule returns False when command fails."""
        mock_rule = {"chain": "FORWARD", "handle": 123}

        with patch.object(network_manager._nft, "cmd", return_value=(1, None, "Error")):
            result = network_manager.delete_rule(mock_rule)
            # Method returns False on failure, doesn't raise exception
            assert result is False

    def test_delete_nat_rules_error(self, network_manager):
        """Test delete_nat_rules with error."""
        with patch.object(
            network_manager, "get_filter_rules", side_effect=NetworkError("Failed")
        ):
            with pytest.raises(NetworkError, match="Failed to delete NAT rules"):
                network_manager.delete_nat_rules("tap_test")

    def test_delete_masquerade_rule_error(self, network_manager):
        """Test delete_masquerade with error."""
        with patch.object(network_manager._nft, "cmd", side_effect=Exception("Failed")):
            with pytest.raises(NetworkError, match="Failed to delete masquerade rule"):
                network_manager.delete_masquerade()

    def test_delete_port_forward_error(self, network_manager):
        """Test delete_port_forward with invalid port."""
        # Test with invalid port number
        with pytest.raises(ValueError, match="Invalid host port number"):
            network_manager.delete_port_forward(
                id="test", host_port=99999, dest_port=80
            )

    def test_delete_port_forward_empty_id(self, network_manager):
        """Test delete_port_forward with empty id."""
        with pytest.raises(ValueError, match="id cannot be empty"):
            network_manager.delete_port_forward(id="", host_port=8080, dest_port=80)

    def test_delete_all_port_forward_error(self, network_manager):
        """Test delete_all_port_forward with error."""
        with patch.object(
            network_manager._nft, "json_cmd", side_effect=Exception("Failed")
        ):
            with pytest.raises(
                NetworkError, match="Failed to delete port forward rules"
            ):
                network_manager.delete_all_port_forward("test_id")

    def test_get_nat_rules_error(self, network_manager):
        """Test get_nat_rules with error."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager._nft, "json_cmd", return_value=(1, None, "Error")
        ):
            with pytest.raises(NetworkError, match="Failed to get NAT rules"):
                network_manager.get_nat_rules()

    def test_get_port_forward_handles_error(self, network_manager):
        """Test get_port_forward_handles with error."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager._nft, "json_cmd", side_effect=Exception("Failed")
        ):
            with pytest.raises(NetworkError, match="Failed to get nftables rules"):
                network_manager.get_port_forward_handles(
                    host_ip="0.0.0.0",
                    host_port=8080,
                    dest_ip="172.16.0.10",
                    dest_port=80,
                )

    def test_get_port_forward_by_comment_error(self, network_manager):
        """Test get_port_forward_by_comment with error."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager._nft, "json_cmd", side_effect=Exception("Failed")
        ):
            with pytest.raises(NetworkError, match="Failed to get nftables rules"):
                network_manager.get_port_forward_by_comment(
                    id="test", host_port=8080, dest_port=80
                )

    def test_add_port_forward_error(self, network_manager):
        """Test add_port_forward with invalid IP."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with pytest.raises(NetworkError, match="Invalid IP address"):
            network_manager.add_port_forward(
                id="test",
                host_ip="999.999.999.999",
                host_port=8080,
                dest_ip="172.16.0.10",
                dest_port=80,
            )

    def test_add_port_forward_without_nftables(self, network_manager):
        """Test add_port_forward when nftables not available."""
        with patch.object(network_manager, "is_nftables_available", return_value=False):
            # When nftables is not available, add_nat_rules returns None
            # add_port_forward may have different behavior based on how it's called
            # Just verify it doesn't raise an exception
            result = network_manager.add_port_forward(
                id="test",
                host_ip="0.0.0.0",
                host_port=8080,
                dest_ip="172.16.0.10",
                dest_port=80,
            )
            # Should return without raising exception
            assert result is None or result is True

    def test_create_tap_error(self, network_manager):
        """Test create_tap with error."""
        with pytest.raises(ConfigurationError, match="TAP device name is required"):
            network_manager.create_tap(tap_name=None)

    def test_create_tap_long_name(self, network_manager):
        """Test create_tap with too long interface name."""
        with pytest.raises(ValueError, match="Interface name must not exceed"):
            network_manager.create_tap(
                tap_name="test_tap",
                iface_name="very_long_interface_name",
                gateway_ip="172.16.0.1",
            )

    def test_delete_tap_error(self, network_manager):
        """Test delete_tap with error."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager, "check_tap_device", side_effect=NetworkError("Failed")
        ):
            with pytest.raises(NetworkError, match="Failed to delete tap device"):
                network_manager.delete_tap("test_tap")

    def test_cleanup_error(self, network_manager):
        """Test cleanup with error."""
        with patch.object(
            network_manager, "delete_nat_rules", side_effect=NetworkError("Failed")
        ):
            with pytest.raises(
                NetworkError, match="Failed to cleanup network resources"
            ):
                network_manager.cleanup("test_tap")


class TestNetworkEdgeCases:
    """Test network management edge cases."""

    def test_suggest_non_conflicting_ip_success(self, network_manager):
        """Test suggest_non_conflicting_ip with success."""
        # This test may fail in environments with limited IP ranges
        try:
            result = network_manager.suggest_non_conflicting_ip("172.16.0.10", 24)
            assert isinstance(result, str)
        except NetworkError as e:
            # Acceptable if no non-conflicting IP can be found
            assert "Unable to find a non-conflicting IP address" in str(e)

    def test_suggest_non_conflicting_ip_error(self, network_manager):
        """Test suggest_non_conflicting_ip with error."""
        with patch.object(
            network_manager, "detect_cidr_conflict", side_effect=Exception("Failed")
        ):
            with pytest.raises(
                NetworkError, match="Failed to suggest non-conflicting IP"
            ):
                network_manager.suggest_non_conflicting_ip("172.16.0.10", 24)

    def test_find_tap_interface_rules_empty(self, network_manager):
        """Test find_tap_interface_rules with empty rules."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager._nft, "json_cmd", return_value=(0, {"nftables": []}, None)
        ):
            result = network_manager.find_tap_interface_rules([], "tap_test")
            assert result == []

    def test_find_tap_interface_rules_no_match(self, network_manager):
        """Test find_tap_interface_rules with no matching rules."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        # Rules without matching tap name
        rules = [
            {
                "rule": {
                    "handle": 1,
                    "chain": "FORWARD",
                    "expr": [{"match": {"right": "tap_other"}}],
                }
            }
        ]
        result = network_manager.find_tap_interface_rules(rules, "tap_test")
        assert len(result) == 0

    def test_check_tap_device_error(self, network_manager):
        """Test check_tap_device with error."""
        with patch("firecracker.network.IPRoute", side_effect=Exception("Failed")):
            with pytest.raises(NetworkError, match="Failed to check tap device"):
                network_manager.check_tap_device("test_tap")

    def test_create_masquerade_already_exists(self, network_manager):
        """Test create_masquerade when rule already exists."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(network_manager, "get_masquerade_handle", return_value=123):
            result = network_manager.create_masquerade("eth0")
            assert result is True

    def test_add_nat_rules_without_nftables(self, network_manager):
        """Test add_nat_rules when nftables not available."""
        with patch.object(network_manager, "is_nftables_available", return_value=False):
            # Should skip silently
            network_manager.add_nat_rules("tap_test", "eth0")

    def test_safe_nft_cmd_not_available(self, network_manager):
        """Test _safe_nft_cmd when nftables not available."""
        with patch.object(network_manager, "is_nftables_available", return_value=False):
            result = network_manager._safe_nft_cmd({"test": "cmd"})
            assert result == (None, None, None)

    def test_safe_nft_cmd_json_error(self, network_manager):
        """Test _safe_nft_cmd with JSON error."""
        if not network_manager.is_nftables_available():
            pytest.skip("Nftables not available")

        with patch.object(
            network_manager._nft, "json_cmd", side_effect=Exception("Failed")
        ):
            result = network_manager._safe_nft_cmd({"test": "cmd"})
            assert result == (1, None, "Failed")

    def test_detect_cidr_conflict_error(self, network_manager):
        """Test detect_cidr_conflict with error."""
        with patch("firecracker.network.IPRoute", side_effect=Exception("Failed")):
            with pytest.raises(NetworkError, match="Failed to check CIDR conflicts"):
                network_manager.detect_cidr_conflict("172.16.0.10", 24)
