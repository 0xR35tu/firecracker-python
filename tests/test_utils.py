"""Tests for utility functions and helper methods."""

import pytest

from firecracker import MicroVM


class TestMemorySizeConversion:
    """Test memory size conversion functionality."""

    def test_memory_size_conversion(self):
        """Test memory size conversion functionality"""
        # Test various memory size formats
        test_cases = [
            ("512", 512),
            ("512M", 512),
            ("1G", 1024),
            ("2G", 2048),
        ]

        for input_size, expected_mb in test_cases:
            result = MicroVM._convert_memory_size(input_size)
            assert result == expected_mb

    def test_convert_memory_size_minimum(self):
        """Test _convert_memory_size enforces minimum memory size"""
        # Test with value below minimum
        result = MicroVM._convert_memory_size(64)
        assert result == 128, f"Expected minimum of 128, got {result}"

    def test_convert_memory_size_negative(self):
        """Test _convert_memory_size with negative value"""
        # Test with negative value - should enforce minimum
        result = MicroVM._convert_memory_size(-512)
        assert result == 128, (
            f"Expected minimum of 128 for negative value, got {result}"
        )

    def test_convert_memory_size_float_gb(self):
        """Test _convert_memory_size with float GB value"""
        # Test with 1.5 GB
        result = MicroVM._convert_memory_size("1.5G")
        assert result == 1536, f"Expected 1536 MiB for 1.5G, got {result}"

    def test_convert_memory_size_lowercase(self):
        """Test _convert_memory_size with lowercase units"""
        # Test with lowercase units
        result = MicroVM._convert_memory_size("1g")
        assert result == 1024, f"Expected 1024 MiB for 1g, got {result}"

        result = MicroVM._convert_memory_size("512m")
        assert result == 512, f"Expected 512 MiB for 512m, got {result}"

    def test_convert_memory_size_with_spaces(self):
        """Test _convert_memory_size with spaces"""
        # Test with spaces
        result = MicroVM._convert_memory_size(" 1G ")
        assert result == 1024, f"Expected 1024 MiB for ' 1G ', got {result}"

    def test_convert_memory_size_invalid_format(self):
        """Test _convert_memory_size with invalid format"""
        # Test with invalid format
        with pytest.raises(ValueError, match="Invalid memory size format"):
            MicroVM._convert_memory_size("invalid")

    def test_convert_memory_size_invalid_type(self):
        """Test _convert_memory_size with invalid type"""
        # Test with invalid type
        with pytest.raises(ValueError, match="Invalid memory size type"):
            MicroVM._convert_memory_size([1, 2, 3])


class TestPortParsing:
    """Test port parsing functionality."""

    def test_parse_ports_with_integer(self):
        """Test _parse_ports with a single integer"""
        result = MicroVM._parse_ports(8080)
        assert result == [8080]

    def test_parse_ports_with_string_single(self):
        """Test _parse_ports with a single string"""
        result = MicroVM._parse_ports("8080")
        assert result == [8080]

    def test_parse_ports_with_string_comma_separated(self):
        """Test _parse_ports with comma-separated string"""
        result = MicroVM._parse_ports("8080,8081,8082")
        assert result == [8080, 8081, 8082]

    def test_parse_ports_with_string_comma_separated_spaces(self):
        """Test _parse_ports with comma-separated string with spaces"""
        result = MicroVM._parse_ports("8080, 8081, 8082")
        assert result == [8080, 8081, 8082]

    def test_parse_ports_with_list(self):
        """Test _parse_ports with a list of integers"""
        result = MicroVM._parse_ports([8080, 8081, 8082])
        assert result == [8080, 8081, 8082]

    def test_parse_ports_with_list_of_strings(self):
        """Test _parse_ports with a list of strings"""
        result = MicroVM._parse_ports(["8080", "8081", "8082"])
        assert result == [8080, 8081, 8082]

    def test_parse_ports_with_none(self):
        """Test _parse_ports with None value"""
        result = MicroVM._parse_ports(None)
        assert result == []

    def test_parse_ports_with_none_and_default(self):
        """Test _parse_ports with None value and default"""
        result = MicroVM._parse_ports(None, default_value=22)
        assert result == [22]

    def test_parse_ports_with_invalid_string(self):
        """Test _parse_ports with invalid string"""
        result = MicroVM._parse_ports("invalid")
        assert result == []

    def test_parse_ports_with_empty_string(self):
        """Test _parse_ports with empty string"""
        result = MicroVM._parse_ports("")
        assert result == []

    def test_parse_ports_with_mixed_list(self):
        """Test _parse_ports with mixed list of integers and strings"""
        result = MicroVM._parse_ports([8080, "8081", 8082, "8083"])
        assert result == [8080, 8081, 8082, 8083]


class TestUtilsFunctions:
    """Test utility functions in utils.py."""

    def test_safe_kill_process_lookup_error(self):
        """Test safe_kill with ProcessLookupError"""
        import signal
        from firecracker.utils import safe_kill

        result = safe_kill(999999999, signal.SIGTERM)
        assert result is True

    def test_safe_kill_permission_error(self):
        """Test safe_kill with PermissionError"""
        import signal
        from unittest.mock import patch
        from firecracker.utils import safe_kill

        with patch("os.kill", side_effect=PermissionError("Permission denied")):
            result = safe_kill(1, signal.SIGTERM)
            assert result is False

    def test_validate_ip_address_invalid_octet(self):
        """Test validate_ip_address with invalid octet"""
        from firecracker.utils import validate_ip_address

        with pytest.raises(Exception, match="Invalid IP address"):
            validate_ip_address("172.16.0.300")

    def test_requires_id_no_id_in_args_or_kwargs(self):
        """Test requires_id decorator when ID is not in args or kwargs"""
        from firecracker.utils import requires_id

        @requires_id
        def test_func(self, id=None):
            return id

        with pytest.raises(RuntimeError, match="VMM ID required"):
            test_func(None)


class TestGetPublicIP:
    """Tests for get_public_ip validation (never yield 0.0.0.0/empty)."""

    def test_returns_valid_ip(self):
        """A valid IP from the first service is returned."""
        from unittest.mock import patch
        from firecracker.utils import get_public_ip

        with patch(
            "firecracker.utils._try_get_ip_from_url", return_value="138.201.226.62"
        ):
            assert get_public_ip() == "138.201.226.62"

    def test_skips_unspecified_then_returns_valid(self):
        """0.0.0.0 from one service is skipped; next valid IP wins."""
        from unittest.mock import patch
        from firecracker.utils import get_public_ip

        with patch(
            "firecracker.utils._try_get_ip_from_url",
            side_effect=["0.0.0.0", "203.0.113.5", "203.0.113.9"],
        ):
            assert get_public_ip() == "203.0.113.5"

    def test_skips_empty_and_garbage(self):
        """Empty/garbage responses are skipped, not returned."""
        from unittest.mock import patch
        from firecracker.utils import get_public_ip

        with patch(
            "firecracker.utils._try_get_ip_from_url",
            side_effect=["", "not-an-ip", "203.0.113.7"],
        ):
            assert get_public_ip() == "203.0.113.7"

    def test_raises_when_all_unspecified_or_invalid(self):
        """All services returning 0.0.0.0/garbage -> RuntimeError, never 0.0.0.0."""
        from unittest.mock import patch
        from firecracker.utils import get_public_ip

        with patch(
            "firecracker.utils._try_get_ip_from_url",
            side_effect=["0.0.0.0", "", "::"],
        ):
            with pytest.raises(RuntimeError, match="Failed to get public IP"):
                get_public_ip()
