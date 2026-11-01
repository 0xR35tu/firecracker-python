"""Test ProcessManager functionality."""

import os
import tempfile

import psutil
import pytest

from firecracker.process import ProcessManager
from firecracker.exceptions import ProcessError
from unittest.mock import patch, MagicMock, mock_open


class TestProcessManager:
    """Test ProcessManager functionality."""

    def test_process_manager_initialization(self):
        """Test ProcessManager initialization."""
        manager = ProcessManager()
        assert manager._logger is not None
        assert manager._config is not None

    def test_process_manager_verbose_initialization(self):
        """Test ProcessManager initialization with verbose logging."""
        manager = ProcessManager(verbose=True, level="DEBUG")
        assert manager._config.verbose is True
        assert manager._logger.verbose is True
        assert manager._logger.current_level == "DEBUG"

    def test_start_process_success(self):
        """Test successful process start."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager._config, "binary_path", "/bin/echo"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_process = MagicMock()
                        mock_process.pid = 12345
                        mock_process.poll.return_value = None
                        mock_popen.return_value = mock_process

                        with patch("psutil.Process") as mock_psutil:
                            mock_proc = MagicMock()
                            mock_proc.status.return_value = psutil.STATUS_RUNNING
                            mock_proc.wait.side_effect = psutil.TimeoutExpired("test")
                            mock_psutil.return_value = mock_proc

                            result = manager.start(vmm_id, ["test"])
                            assert result == 12345

    def test_start_process_exits_during_startup(self):
        """Test process start when process exits during startup."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager._config, "binary_path", "/bin/echo"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_process = MagicMock()
                        mock_process.pid = 12345
                        mock_process.poll.return_value = 0  # Process exited
                        mock_popen.return_value = mock_process

                        with pytest.raises(
                            ProcessError,
                            match="Firecracker process exited during startup",
                        ):
                            manager.start(vmm_id, ["test"])

    def test_start_process_becomes_zombie(self):
        """Test process start when process becomes zombie."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager._config, "binary_path", "/bin/echo"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_process = MagicMock()
                        mock_process.pid = 12345
                        mock_process.poll.return_value = None
                        mock_popen.return_value = mock_process

                        with patch("psutil.Process") as mock_psutil:
                            mock_proc = MagicMock()
                            mock_proc.status.return_value = psutil.STATUS_ZOMBIE
                            mock_proc.wait.side_effect = psutil.TimeoutExpired("test")
                            mock_psutil.return_value = mock_proc

                            with pytest.raises(
                                ProcessError, match="Firecracker process became defunct"
                            ):
                                manager.start(vmm_id, ["test"])

    def test_start_process_disappears_during_startup(self):
        """Test process start when process disappears during startup."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager._config, "binary_path", "/bin/echo"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_process = MagicMock()
                        mock_process.pid = 12345
                        mock_process.poll.return_value = None
                        mock_popen.return_value = mock_process

                        with patch("psutil.Process") as mock_psutil:
                            mock_proc = MagicMock()
                            mock_proc.status.return_value = psutil.STATUS_RUNNING
                            mock_proc.wait.side_effect = psutil.NoSuchProcess("test")
                            mock_psutil.return_value = mock_proc

                            with pytest.raises(
                                ProcessError,
                                match="Firecracker process disappeared during startup",
                            ):
                                manager.start(vmm_id, ["test"])

    def test_stop_running_process(self):
        """Test stopping a running process."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager, "_is_vm_process", return_value=True):
                    with patch.object(manager, "_try_stop_process", return_value=True):
                        result = manager.stop(vmm_id)
                        assert result is True

    def test_stop_nonexistent_process(self):
        """Test stopping a non-existent process."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "nonexistent"

            with patch.object(manager._config, "data_path", tmpdir):
                result = manager.stop(vmm_id)
                # Should not raise error
                assert result is False

    def test_stop_process_searches_for_running_process(self):
        """Test stopping process when PID file has stale PID."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            socket_file = f"{data_path}/firecracker.socket"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch.object(manager, "_is_vm_process", return_value=True):
                    with patch.object(
                        manager,
                        "_try_stop_process",
                        side_effect=[ProcessError("Not found"), True],
                    ):
                        with patch.object(
                            manager, "_find_running_process", return_value=54321
                        ):
                            with patch.object(manager, "_cleanup_files"):
                                result = manager.stop(vmm_id)
                                assert result is True

    def test_is_running_true(self):
        """Test checking if process is running (true)."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("os.kill", return_value=None):
                    result = manager.is_running(vmm_id)
                    assert result is True

    def test_is_running_false_no_pid_file(self):
        """Test checking if process is running (false, no PID file)."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "nonexistent"

            with patch.object(manager._config, "data_path", tmpdir):
                result = manager.is_running(vmm_id)
                assert result is False

    def test_is_running_false_process_not_running(self):
        """Test checking if process is running (false, process dead)."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("os.kill", side_effect=OSError(3, "No such process")):
                    with patch("os.remove") as mock_remove:
                        result = manager.is_running(vmm_id)
                        assert result is False
                        mock_remove.assert_called()

    def test_get_pid_success(self):
        """Test getting PID successfully."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("psutil.Process") as mock_psutil:
                    mock_proc = MagicMock()
                    mock_proc.is_running.return_value = True
                    mock_proc.name.return_value = "firecracker"
                    mock_proc.create_time.return_value = 1234567890.0
                    mock_psutil.return_value = mock_proc

                    pid, create_time = manager.get_pid(vmm_id)
                    assert pid == 12345
                    assert create_time == "2009-02-13 23:31:30"

    def test_get_pid_no_pid_file(self):
        """Test getting PID when PID file doesn't exist."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "nonexistent"

            with patch.object(manager._config, "data_path", tmpdir):
                with pytest.raises(ProcessError, match="No PID file found"):
                    manager.get_pid(vmm_id)

    def test_get_pid_process_not_running(self):
        """Test getting PID when process is not running."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("psutil.Process") as mock_psutil:
                    mock_proc = MagicMock()
                    mock_proc.is_running.return_value = False
                    mock_psutil.return_value = mock_proc

                    with patch("os.remove") as mock_remove:
                        with pytest.raises(
                            ProcessError,
                            match="Firecracker process 12345 is not running",
                        ):
                            manager.get_pid(vmm_id)
                        mock_remove.assert_called()

    def test_get_pid_process_not_firecracker(self):
        """Test getting PID when process is not Firecracker."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("psutil.Process") as mock_psutil:
                    mock_proc = MagicMock()
                    mock_proc.is_running.return_value = True
                    mock_proc.name.return_value = "other_process"
                    mock_psutil.return_value = mock_proc

                    with patch("os.remove") as mock_remove:
                        with pytest.raises(
                            ProcessError,
                            match="Process 12345 is not a Firecracker process",
                        ):
                            manager.get_pid(vmm_id)
                        mock_remove.assert_called()

    def test_get_pids(self):
        """Test getting Firecracker process PIDs."""
        manager = ProcessManager()

        with patch("psutil.pids") as mock_pids:
            mock_pids.return_value = [12345, 67890]

            with patch("psutil.Process") as MockProcess:
                mock_proc1 = MagicMock()
                mock_proc1.name.return_value = "firecracker"
                mock_proc1.cmdline.return_value = [
                    "firecracker",
                    "--api-sock",
                    "/tmp/socket",
                ]

                mock_proc2 = MagicMock()
                mock_proc2.name.return_value = "other"
                mock_proc2.cmdline.return_value = ["other"]

                MockProcess.side_effect = [mock_proc1, mock_proc2]

                pids = manager.get_pids()
                assert 12345 in pids
                assert 67890 not in pids

    def test_get_pids_no_api_sock(self):
        """Test getting PIDs excludes Firecracker processes without --api-sock."""
        manager = ProcessManager()

        with patch("psutil.process_iter") as mock_iter:
            mock_proc = MagicMock()
            mock_proc.info = {
                "pid": 12345,
                "name": "firecracker",
                "cmdline": ["firecracker"],
            }

            mock_iter.return_value = [mock_proc]

            pids = manager.get_pids()
            assert len(pids) == 0

    def test_try_stop_process_already_dead(self):
        """Test stopping a process that's already dead."""
        manager = ProcessManager()

        with patch("os.kill", side_effect=OSError(3, "No such process")):
            result = manager._try_stop_process(12345, "test_vmm")
            assert result is True

    def test_try_stop_process_sigterm_success(self):
        """Test stopping a process with SIGTERM."""
        manager = ProcessManager()

        with patch("os.kill", return_value=None):
            with patch("time.sleep"):
                with patch(
                    "os.kill", side_effect=[None, OSError(3, "No such process")]
                ):
                    result = manager._try_stop_process(12345, "test_vmm")
                    assert result is True

    def test_try_stop_process_sigkill_required(self):
        """Test stopping a process with SIGKILL after SIGTERM fails."""
        manager = ProcessManager()

        with patch("os.kill") as mock_kill:
            with patch("time.sleep"):
                mock_kill.side_effect = [
                    None,  # First check
                    None,  # SIGTERM
                    OSError(3, "No such process"),  # Check after SIGTERM
                ]
                result = manager._try_stop_process(12345, "test_vmm")
                assert result is True

    def test_find_running_process(self):
        """Test finding a running Firecracker process."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            socket_file = f"{tmpdir}/{vmm_id}/firecracker.socket"

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("psutil.pids") as mock_pids:
                    mock_pids.return_value = [12345, 67890]

                    with patch("psutil.Process") as MockProcess:
                        mock_proc1 = MagicMock()
                        mock_proc1.name.return_value = "firecracker"
                        mock_proc1.cmdline.return_value = [
                            "firecracker",
                            "--api-sock",
                            socket_file,
                        ]

                        mock_proc2 = MagicMock()
                        mock_proc2.name.return_value = "other"
                        mock_proc2.cmdline.return_value = ["other"]

                        MockProcess.side_effect = [mock_proc1, mock_proc2]

                        pid = manager._find_running_process(vmm_id)
                        assert pid == 12345

    def test_find_running_process_not_found(self):
        """Test finding a running process that doesn't exist."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("psutil.process_iter") as mock_iter:
                    mock_iter.return_value = []

                    pid = manager._find_running_process(vmm_id)
                    assert pid is None

    def test_cleanup_files(self):
        """Test cleanup of PID and socket files."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            socket_file = f"{data_path}/firecracker.socket"

            with open(pid_file, "w") as f:
                f.write("12345")
            with open(socket_file, "w") as f:
                f.write("socket")

            with patch.object(manager._config, "data_path", tmpdir):
                manager._cleanup_files(vmm_id)

                assert not os.path.exists(pid_file)
                assert not os.path.exists(socket_file)

    def test_cleanup_files_only_pid(self):
        """Test cleanup when only PID file exists."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            pid_file = f"{data_path}/firecracker.pid"
            with open(pid_file, "w") as f:
                f.write("12345")

            with patch.object(manager._config, "data_path", tmpdir):
                manager._cleanup_files(vmm_id)

                assert not os.path.exists(pid_file)

    def test_cleanup_files_error_handling(self):
        """Test cleanup handles errors gracefully."""
        manager = ProcessManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            vmm_id = "test_vmm"
            data_path = f"{tmpdir}/{vmm_id}"
            os.makedirs(data_path, exist_ok=True)

            with patch.object(manager._config, "data_path", tmpdir):
                with patch("os.remove", side_effect=OSError("Permission denied")):
                    # Should not raise error
                    manager._cleanup_files(vmm_id)
