"""fcpy: a debug CLI for inspecting Firecracker microVMs without a Python REPL.

This module intentionally never constructs firecracker.microvm.MicroVM. It
reads config.json files directly and uses psutil for process liveness, so
read-only commands have no side effects (no Docker client, no route lookups,
no CIDR checks, no ID generation).
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import psutil

from firecracker.config import MicroVMConfig
from firecracker.process import is_vm_process

VMM_ID_PATTERN = re.compile(r"^[a-zA-Z0-9]{8}$")
EVENTS_FILENAME = "events.log"
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime(TS_FORMAT)


def _default_data_path() -> str:
    return MicroVMConfig().data_path


def _human_size(num_bytes) -> str:
    if num_bytes is None:
        return "-"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def print_or_json(data, as_json: bool, text_fn) -> None:
    """Print data as JSON, or call text_fn() to print the human-readable form."""
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        text_fn()


class VmIdError(Exception):
    """Raised by resolve_vm_id on no-match or ambiguous-match; carries an exit code."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def resolve_vm_id(vms: dict, query: str) -> str:
    """Resolve a full ID, unique ID prefix, or VM name to exactly one vmm_id.

    Raises:
        VmIdError: if there is no match, or more than one match.
    """
    matches = [
        vmm_id
        for vmm_id in vms
        if vmm_id == query or vmm_id.startswith(query) or vms[vmm_id].get("name") == query
    ]
    if not matches:
        raise VmIdError(f"No VM matching {query!r} found")
    if len(matches) > 1:
        raise VmIdError(f"Ambiguous ID {query!r} matches: {', '.join(matches)}")
    return matches[0]


_is_vm_process = is_vm_process


def scan_vms(data_path: str) -> dict:
    """Scan data_path for every VM directory and classify its current state.

    Unlike VMMManager.list_vmm(), this includes VMs whose process is dead or
    whose config.json is missing/corrupt, since those are exactly the VMs a
    debugging session needs to see.

    Returns:
        dict: {id: {id, name, pid, state, ip_addr, ports, labels,
                     created_at, running, paused}}, state is one of
                     "running", "paused", "dead", "broken".
    """
    vms = {}

    try:
        entries = os.listdir(data_path)
    except OSError:
        return vms

    for vmm_id in entries:
        if not VMM_ID_PATTERN.match(vmm_id):
            continue

        vmm_path = os.path.join(data_path, vmm_id)
        if not os.path.isdir(vmm_path):
            continue

        config_path = os.path.join(vmm_path, "config.json")
        config = None
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
            except (json.JSONDecodeError, OSError):
                config = None

        if config is None:
            vms[vmm_id] = {
                "id": vmm_id,
                "name": None,
                "pid": None,
                "state": "broken",
                "ip_addr": None,
                "ports": {},
                "labels": {},
                "created_at": None,
                "running": False,
                "paused": False,
            }
            continue

        state_block = config.get("State", {}) or {}
        pid = state_block.get("Pid") or None
        running_flag = bool(state_block.get("Running", False))
        paused_flag = bool(state_block.get("Paused", False))

        alive = bool(pid) and _is_vm_process(pid, vmm_id)

        if not alive:
            state = "dead"
        elif paused_flag:
            state = "paused"
        else:
            state = "running"

        network_key = f"tap_{vmm_id}"
        network_info = (config.get("Network", {}) or {}).get(network_key, {}) or {}

        vms[vmm_id] = {
            "id": config.get("ID", vmm_id),
            "name": config.get("Name") or None,
            "pid": pid,
            "state": state,
            "ip_addr": network_info.get("IPAddress") or None,
            "ports": config.get("Ports", {}) or {},
            "labels": config.get("Labels", {}) or {},
            "created_at": config.get("CreatedAt") or None,
            "running": running_flag,
            "paused": paused_flag,
        }

    return vms


def _event(vm: dict, event: str, detail: str = "", reason: str = None) -> dict:
    record = {
        "ts": _now_iso(),
        "id": vm["id"],
        "name": vm.get("name"),
        "event": event,
        "detail": detail,
    }
    if reason:
        record["reason"] = reason
    return record


def diff_scans(prev: dict, curr: dict) -> list:
    """Compare two scan_vms() snapshots and return newly-observed lifecycle events."""
    events = []

    for vmm_id, now in curr.items():
        before = prev.get(vmm_id)

        if before is None:
            if now["state"] == "broken":
                events.append(_event(now, "broken_detected"))
            else:
                events.append(_event(now, "created"))
            continue

        if before["state"] != "broken" and now["state"] == "broken":
            events.append(_event(now, "broken_detected"))
        elif before["state"] in ("running", "paused") and now["state"] == "dead":
            events.append(
                _event(now, "crashed", f"pid {before.get('pid')} gone, config Running=true")
            )
        elif not before["paused"] and now["paused"]:
            events.append(_event(now, "paused"))
        elif before["paused"] and not now["paused"]:
            events.append(_event(now, "resumed"))

    for vmm_id, before in prev.items():
        if vmm_id not in curr:
            events.append(_event(before, "deleted", reason="external"))

    return events


def append_event(data_path: str, record: dict) -> None:
    os.makedirs(data_path, exist_ok=True)
    path = os.path.join(data_path, EVENTS_FILENAME)
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


def read_events(data_path: str, vmm_id: str = None, since: datetime = None) -> list:
    path = os.path.join(data_path, EVENTS_FILENAME)
    if not os.path.exists(path):
        return []

    events = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if vmm_id and not record.get("id", "").startswith(vmm_id):
                continue

            if since:
                try:
                    ts = datetime.strptime(record["ts"], TS_FORMAT).replace(tzinfo=timezone.utc)
                except (KeyError, ValueError):
                    continue
                if ts < since:
                    continue

            events.append(record)

    return events


def parse_since(value: str) -> datetime:
    """Parse a --since value: a relative duration ('2h', '30m', '1d', '45s')
    or an absolute date/datetime ('2026-10-01', '2026-10-01T10:00:00')."""
    match = re.match(r"^(\d+)(s|m|h|d)$", value)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        delta = {
            "s": timedelta(seconds=amount),
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
        }[unit]
        return datetime.now(timezone.utc) - delta

    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    raise ValueError(f"Invalid --since value: {value!r}")


def _format_event_line(record: dict) -> str:
    ts = record.get("ts", "")
    try:
        ts = datetime.strptime(ts, TS_FORMAT).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    name = record.get("name") or "-"
    detail = record.get("detail") or ""
    reason = f" reason={record['reason']}" if record.get("reason") else ""
    return f"{ts:<19}  {record['id']:<10}{name:<16}{record['event']:<10}{detail}{reason}".rstrip()


def _lazy_network_manager():
    try:
        from firecracker.network import NetworkManager

        return NetworkManager
    except Exception:
        return None


def _try_network_manager():
    """Construct a NetworkManager, returning None if this host can't support
    one (missing pyroute2/nftables, no netlink support, no permissions, etc.)
    instead of letting the constructor's exception propagate as a traceback."""
    network_manager_cls = _lazy_network_manager()
    if network_manager_cls is None:
        return None
    try:
        return network_manager_cls()
    except Exception:
        return None


def cmd_events(args) -> int:
    data_path = args.data_path or _default_data_path()

    if args.watch:
        interval = args.interval
        print(f"Watching {data_path} (interval {interval}s, Ctrl-C to stop)")
        previous = scan_vms(data_path)
        try:
            while True:
                time.sleep(interval)
                current = scan_vms(data_path)
                for record in diff_scans(previous, current):
                    append_event(data_path, record)
                    print(_format_event_line(record))
                previous = current
        except KeyboardInterrupt:
            print("\nStopped watching.")
        return 0

    since = parse_since(args.since) if args.since else None
    events = read_events(data_path, vmm_id=args.id, since=since)

    if args.json:
        print(json.dumps(events, indent=2))
    else:
        for record in events:
            print(_format_event_line(record))

    return 0


def _delete_vm_dir(data_path: str, vmm_id: str, vm: dict, network_manager=None) -> None:
    """Shared body for cmd_delete and cmd_prune: log the deletion, kill the
    process if it's actually this VM's (never trust a bare PID - it can have
    been recycled by an unrelated process), clean up every network resource
    this VM owns, and remove the directory."""
    vmm_path = os.path.join(data_path, vmm_id)

    append_event(data_path, _event(vm, "deleted", reason="manual"))

    pid = vm.get("pid")
    if pid and _is_vm_process(pid, vmm_id):
        try:
            psutil.Process(int(pid)).kill()
        except (TypeError, ValueError, psutil.Error):
            pass

    nm = network_manager or _try_network_manager()
    tap_name = f"tap_{vmm_id}"
    errors = []
    if nm is None:
        errors.append("NetworkManager unavailable")
    else:
        # Deliberately NOT NetworkManager.cleanup(): it also calls
        # delete_masquerade(), which removes the one shared masquerade rule
        # every other running VM's outbound traffic depends on.
        for step in (
            lambda: nm.delete_nat_rules(tap_name),
            lambda: nm.delete_all_port_forward(vmm_id),
            lambda: nm.delete_tap(tap_name),
        ):
            try:
                step()
            except Exception as e:
                errors.append(str(e))
        if network_manager is None:
            nm.close()

    if errors:
        print(
            f"Warning: network cleanup for {vmm_id} was incomplete: {'; '.join(errors)}",
            file=sys.stderr,
        )

    shutil.rmtree(vmm_path, ignore_errors=True)


def cmd_delete(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    try:
        vmm_id = resolve_vm_id(vms, args.id)
    except VmIdError as e:
        print(str(e), file=sys.stderr)
        return e.code

    _delete_vm_dir(data_path, vmm_id, vms[vmm_id])
    print(f"VM {vmm_id} deleted")
    return 0


def _print_list(vms: dict) -> None:
    if not vms:
        print("No VMs found.")
        return

    print(f"{'ID':<10}{'NAME':<17}{'STATE':<9}{'PID':<8}{'IP':<13}{'PORTS':<15}{'CREATED'}")
    counts = {}
    for vmm_id, vm in vms.items():
        counts[vm["state"]] = counts.get(vm["state"], 0) + 1

        ports = vm.get("ports") or {}
        port_str = "-"
        if ports:
            pairs = []
            for mappings in ports.values():
                for m in mappings:
                    pairs.append(f"{m['HostPort']}->{m['DestPort']}")
            port_str = ",".join(pairs) if pairs else "-"

        print(
            f"{vmm_id:<10}{(vm['name'] or '-'):<17}{vm['state']:<9}"
            f"{(str(vm['pid']) if vm['pid'] else '-'):<8}{(vm['ip_addr'] or '-'):<13}"
            f"{port_str:<15}{vm['created_at'] or '-'}"
        )

    total = len(vms)
    summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
    print(f"\n{total} VM{'s' if total != 1 else ''}: {summary}")
    if counts.get("dead") or counts.get("broken"):
        print("Hint: run 'fcpy prune' to remove dead and broken VMs.")


def cmd_list(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)
    print_or_json(list(vms.values()), args.json, lambda: _print_list(vms))
    return 0


def _print_inspect(data: dict) -> None:
    print(f"VM {data['id']} ({data['name'] or '-'})")
    print(f"  State      {data['state']}")
    print(f"  Created    {data['created_at'] or '-'}")
    print(f"  IP         {data['ip_addr'] or '-'}  via tap_{data['id']}")

    ports = data["ports"] or {}
    if ports:
        pairs = [f"{m['HostPort']} -> {m['DestPort']}" for mappings in ports.values() for m in mappings]
        print(f"  Ports      {', '.join(pairs)}")
    else:
        print("  Ports      -")

    labels = data["labels"] or {}
    if labels:
        print(f"  Labels     {' '.join(f'{k}={v}' for k, v in labels.items())}")

    print("\nProcess")
    proc = data["process"]
    if proc["running"]:
        print(
            f"  PID        {proc['pid']}  (running, up {proc['uptime_seconds']}s, "
            f"RSS {_human_size(proc['rss_bytes'])})"
        )
    else:
        print(f"  PID        {proc['pid'] or '-'}  (not running)")

    print("\nFiles")
    for label, key in (("Socket", "socket"), ("VMM log", "vmm_log"), ("Console", "console_log")):
        info = data["files"][key]
        if info["exists"]:
            status = "exists (stale)" if info.get("stale") else "exists"
            print(f"  {label:<10} {info['path']}   {status}   {_human_size(info['size_bytes'])}")
        else:
            print(f"  {label:<10} {info['path']}   not found")

    print("\nLive API")
    if data["live_api"]:
        describe = data["live_api"].get("describe", {})
        machine_config = data["live_api"].get("machine_config", {})
        print(f"  state        {describe.get('state', '-')}")
        print(f"  vcpu_count   {machine_config.get('vcpu_count', '-')}")
        print(f"  mem_size_mib {machine_config.get('mem_size_mib', '-')}")
    else:
        print(f"  Not available: {data['live_api_error']}")


def cmd_inspect(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    try:
        vmm_id = resolve_vm_id(vms, args.id)
    except VmIdError as e:
        print(str(e), file=sys.stderr)
        return e.code

    vm = vms[vmm_id]
    vmm_path = os.path.join(data_path, vmm_id)

    pid = vm.get("pid")
    process_info = {"pid": pid, "running": False}
    if pid:
        try:
            pid_int = int(pid)
            if _is_vm_process(pid_int, vmm_id):
                proc = psutil.Process(pid_int)
                process_info = {
                    "pid": pid_int,
                    "running": True,
                    "cmdline": proc.cmdline(),
                    "create_time": datetime.fromtimestamp(proc.create_time()).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "uptime_seconds": round(time.time() - proc.create_time(), 1),
                    "rss_bytes": proc.memory_info().rss,
                }
        except (TypeError, ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    socket_path = os.path.join(vmm_path, "firecracker.socket")
    vmm_log_path = os.path.join(vmm_path, "logs", f"{vmm_id}.log")
    console_log_path = os.path.join(vmm_path, "firecracker.log")

    def _file_info(path, stale_if_dead=False):
        exists = os.path.exists(path)
        info = {"path": path, "exists": exists, "size_bytes": os.path.getsize(path) if exists else None}
        if stale_if_dead and exists and not process_info["running"]:
            info["stale"] = True
        return info

    files = {
        "socket": _file_info(socket_path, stale_if_dead=True),
        "vmm_log": _file_info(vmm_log_path),
        "console_log": _file_info(console_log_path),
    }

    api_data = None
    api_error = None
    if process_info["running"] and files["socket"]["exists"]:
        from firecracker.api import Api
        from firecracker.exceptions import APIError

        api = None
        try:
            api = Api(socket_path, timeout=2)
            api_data = {
                "describe": api.describe.get().json(),
                "vm_config": api.vm_config.get().json(),
                "machine_config": api.machine_config.get().json(),
            }
        except APIError as e:
            api_error = str(e)
        except Exception as e:
            api_error = f"connection failed: {e}"
        finally:
            if api is not None:
                api.close()
    else:
        api_error = "connection refused on socket"

    data = {
        "id": vmm_id,
        "name": vm.get("name"),
        "state": vm.get("state"),
        "created_at": vm.get("created_at"),
        "ip_addr": vm.get("ip_addr"),
        "ports": vm.get("ports"),
        "labels": vm.get("labels"),
        "process": process_info,
        "files": files,
        "live_api": api_data,
        "live_api_error": api_error,
    }

    print_or_json(data, args.json, lambda: _print_inspect(data))
    return 0


def _tail_lines(path: str, n: int) -> list:
    with open(path, "r", errors="replace") as f:
        return list(collections.deque(f, maxlen=n))


def _follow(path: str) -> None:
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                print(line, end="")
                continue
            if os.path.getsize(path) < f.tell():
                f.seek(0)
            time.sleep(0.5)


def cmd_logs(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    try:
        vmm_id = resolve_vm_id(vms, args.id)
    except VmIdError as e:
        print(str(e), file=sys.stderr)
        return e.code

    vmm_path = os.path.join(data_path, vmm_id)
    path = (
        os.path.join(vmm_path, "firecracker.log")
        if args.console
        else os.path.join(vmm_path, "logs", f"{vmm_id}.log")
    )

    if not os.path.exists(path):
        print(f"No log file at {path}", file=sys.stderr)
        return 1

    for line in _tail_lines(path, args.lines):
        print(line, end="" if line.endswith("\n") else "\n")

    if args.follow:
        try:
            _follow(path)
        except KeyboardInterrupt:
            print("\nStopped.")

    return 0


def cmd_ssh(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    try:
        vmm_id = resolve_vm_id(vms, args.id)
    except VmIdError as e:
        print(str(e), file=sys.stderr)
        return e.code

    vm = vms[vmm_id]
    if not vm.get("ip_addr"):
        print(f"VM {vmm_id} has no known IP address", file=sys.stderr)
        return 1

    cmd = args.cmd or []
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    ssh_argv = ["ssh"]
    if args.key:
        ssh_argv += ["-i", args.key]
    ssh_argv += ["-l", args.user or "root", vm["ip_addr"]]
    ssh_argv += cmd

    try:
        os.execvp("ssh", ssh_argv)
    except FileNotFoundError:
        print("ssh binary not found on PATH", file=sys.stderr)
        return 1


def cmd_api(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    try:
        vmm_id = resolve_vm_id(vms, args.id)
    except VmIdError as e:
        print(str(e), file=sys.stderr)
        return e.code

    socket_path = os.path.join(data_path, vmm_id, "firecracker.socket")
    if not os.path.exists(socket_path):
        print(f"No socket file at {socket_path}", file=sys.stderr)
        return 1

    body = None
    if args.data:
        try:
            body = json.loads(args.data)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for -d: {e}", file=sys.stderr)
            return 1

    import requests

    from firecracker.api import Api

    api = Api(socket_path, timeout=5)
    try:
        kwargs = {} if body is None else {"json": body}
        res = api.session.request(args.method, api.endpoint + args.path, timeout=api.get_timeout(), **kwargs)
        print(f"{res.status_code} {res.reason}")
        try:
            print(json.dumps(res.json(), indent=2))
        except ValueError:
            if res.text:
                print(res.text)
        return 0 if res.ok else 1
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return 1
    finally:
        api.close()


def _print_net(data: dict) -> None:
    if not data["nftables_available"]:
        print("nftables: not available")

    for item in data["interfaces"]:
        status = "up" if item["tap_exists"] else "missing"
        print(f"{item['id']}  {item['tap']}  {status}")
        for rule in item["rules"]:
            print(f"    {rule['chain']}  handle={rule['handle']}  iface={rule['interface']}")

    if data["masquerade_handle"] is not None:
        print(f"\nMasquerade rule handle: {data['masquerade_handle']}")


def cmd_net(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)

    if args.id:
        try:
            vmm_id = resolve_vm_id(vms, args.id)
        except VmIdError as e:
            print(str(e), file=sys.stderr)
            return e.code
        target_ids = [vmm_id]
    else:
        target_ids = list(vms.keys())

    nm = _try_network_manager()
    if nm is None:
        print("NetworkManager unavailable on this host", file=sys.stderr)
        return 1

    try:
        nft_available = nm.is_nftables_available()
        all_filter_rules = nm.get_filter_rules() if nft_available else []

        report = []
        for vid in target_ids:
            tap_name = f"tap_{vid}"
            exists = nm.check_tap_device(tap_name)
            rules = nm.find_tap_interface_rules(all_filter_rules, tap_name) if all_filter_rules else []
            report.append({"id": vid, "tap": tap_name, "tap_exists": exists, "rules": rules})

        masquerade_handle = nm.get_masquerade_handle() if nft_available else None

        data = {
            "nftables_available": nft_available,
            "interfaces": report,
            "masquerade_handle": masquerade_handle,
        }
        print_or_json(data, args.json, lambda: _print_net(data))
        return 0
    finally:
        nm.close()


def _check_root() -> dict:
    ok = os.geteuid() == 0
    return {
        "status": "ok" if ok else "warn",
        "label": "Running as root",
        "detail": "",
        "fix": "" if ok else "Run fcpy with sudo for full functionality",
    }


def _check_binary() -> dict:
    config = MicroVMConfig()
    if not os.path.exists(config.binary_path):
        return {
            "status": "fail",
            "label": "Firecracker binary",
            "detail": f"{config.binary_path} not found",
            "fix": "Install Firecracker",
        }
    if not os.access(config.binary_path, os.X_OK):
        return {
            "status": "fail",
            "label": "Firecracker binary",
            "detail": f"{config.binary_path} not executable",
            "fix": f"chmod +x {config.binary_path}",
        }

    version = ""
    try:
        result = subprocess.run(
            [config.binary_path, "--version"], capture_output=True, text=True, timeout=2
        )
        if result.stdout:
            version = result.stdout.strip().splitlines()[0]
    except Exception:
        pass

    detail = f"{config.binary_path} ({version})" if version else config.binary_path
    return {"status": "ok", "label": "Firecracker binary", "detail": detail, "fix": ""}


def _check_kvm() -> dict:
    if not os.path.exists("/dev/kvm"):
        return {
            "status": "fail",
            "label": "KVM",
            "detail": "/dev/kvm not found",
            "fix": "Enable KVM (modprobe kvm_intel or kvm_amd)",
        }
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        return {
            "status": "fail",
            "label": "KVM",
            "detail": "/dev/kvm not read/write accessible",
            "fix": "sudo usermod -aG kvm $USER",
        }
    return {"status": "ok", "label": "KVM", "detail": "/dev/kvm read/write", "fix": ""}


def _check_ip_forward() -> dict:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            value = f.read().strip()
    except OSError:
        return {
            "status": "warn",
            "label": "IP forwarding",
            "detail": "could not read /proc/sys/net/ipv4/ip_forward",
            "fix": "",
        }
    if value != "1":
        return {
            "status": "fail",
            "label": "IP forwarding",
            "detail": f"net.ipv4.ip_forward = {value}",
            "fix": "sudo sysctl -w net.ipv4.ip_forward=1",
        }
    return {"status": "ok", "label": "IP forwarding", "detail": "net.ipv4.ip_forward = 1", "fix": ""}


def _check_nftables(nm) -> dict:
    if nm is None or not nm.is_nftables_available():
        return {
            "status": "warn",
            "label": "nftables module",
            "detail": "not available",
            "fix": "Install python3-nftables",
        }
    return {"status": "ok", "label": "nftables module", "detail": "available", "fix": ""}


def _check_data_dir() -> dict:
    config = MicroVMConfig()
    if os.path.isdir(config.data_path):
        return {"status": "ok", "label": "Data directory", "detail": config.data_path, "fix": ""}
    return {
        "status": "warn",
        "label": "Data directory",
        "detail": f"{config.data_path} does not exist",
        "fix": f"mkdir -p {config.data_path}",
    }


def _check_docker() -> dict:
    try:
        import docker

        docker.from_env(timeout=2).ping()
        return {"status": "ok", "label": "Docker", "detail": "reachable", "fix": ""}
    except Exception as e:
        return {
            "status": "warn",
            "label": "Docker",
            "detail": f"not reachable ({e})",
            "fix": "Start the Docker daemon",
        }


def _check_dead_vms(vms: dict) -> dict:
    stale = [vid for vid, v in vms.items() if v["state"] in ("dead", "broken")]
    if not stale:
        return {"status": "ok", "label": "Dead VM dirs", "detail": "0", "fix": ""}
    return {
        "status": "warn",
        "label": "Dead VM dirs",
        "detail": f"{len(stale)} ({', '.join(stale)})",
        "fix": "fcpy prune",
    }


def _find_orphan_taps(nm, vms: dict) -> list:
    if nm is None:
        return []
    try:
        links = nm.get_links()
    except Exception:
        return []

    known_ids = set(vms.keys())
    orphans = []
    for link in links:
        ifname = link.get("ifname", "")
        if ifname.startswith("tap_") and ifname[4:] not in known_ids:
            orphans.append(ifname)
    return orphans


def _check_orphan_taps(nm, vms: dict) -> dict:
    orphans = _find_orphan_taps(nm, vms)
    if not orphans:
        return {"status": "ok", "label": "Orphan TAP devices", "detail": "0", "fix": ""}
    return {
        "status": "warn",
        "label": "Orphan TAP devices",
        "detail": f"{len(orphans)} ({', '.join(orphans)})",
        "fix": "fcpy prune",
    }


def _print_doctor(checks: list) -> None:
    labels = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
    for c in checks:
        print(f"{labels[c['status']]}  {c['label']:<22} {c['detail']}")
        if c["status"] != "ok" and c.get("fix"):
            print(f"          Fix: {c['fix']}")

    fails = sum(1 for c in checks if c["status"] == "fail")
    warns = sum(1 for c in checks if c["status"] == "warn")
    parts = []
    if fails:
        parts.append(f"{fails} failure{'s' if fails != 1 else ''}")
    if warns:
        parts.append(f"{warns} warning{'s' if warns != 1 else ''}")
    summary = ", ".join(parts) if parts else "All checks passed"
    hint = " Run 'fcpy prune' to clean up." if (fails or warns) else ""
    print(f"\n{summary}.{hint}")


def cmd_doctor(args) -> int:
    data_path = args.data_path or _default_data_path()
    checks = [_check_root(), _check_binary(), _check_kvm(), _check_ip_forward()]

    nm = _try_network_manager()
    try:
        checks.append(_check_nftables(nm))
        checks.append(_check_data_dir())
        checks.append(_check_docker())

        vms = scan_vms(data_path)
        checks.append(_check_dead_vms(vms))
        checks.append(_check_orphan_taps(nm, vms))
    finally:
        if nm is not None:
            nm.close()

    print_or_json(checks, args.json, lambda: _print_doctor(checks))

    fails = sum(1 for c in checks if c["status"] == "fail")
    return 1 if fails else 0


def cmd_prune(args) -> int:
    data_path = args.data_path or _default_data_path()
    vms = scan_vms(data_path)
    stale_ids = [vid for vid, v in vms.items() if v["state"] in ("dead", "broken")]

    nm = _try_network_manager()
    try:
        orphan_taps = _find_orphan_taps(nm, vms)

        if not stale_ids and not orphan_taps:
            print("Nothing to prune.")
            return 0

        if not args.yes:
            print(f"Will delete {len(stale_ids)} VM dir(s): {', '.join(stale_ids) or '-'}")
            print(f"Will delete {len(orphan_taps)} orphan TAP(s): {', '.join(orphan_taps) or '-'}")
            answer = input("Proceed? [y/N] ").strip().lower()
            if answer != "y":
                print("Aborted.")
                return 1

        for vid in stale_ids:
            _delete_vm_dir(data_path, vid, vms[vid], network_manager=nm)

        for tap in orphan_taps:
            try:
                if nm is not None:
                    nm.delete_tap(tap)
            except Exception:
                pass

        print(f"Pruned {len(stale_ids)} VM(s), {len(orphan_taps)} TAP(s).")
        return 0
    finally:
        if nm is not None:
            nm.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fcpy", description="Debug CLI for Firecracker microVMs")
    parser.add_argument(
        "--data-path", dest="data_path", default=None, help="Override the firecracker data directory"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser(
        "list", help="List every VM directory (running, paused, dead, or broken)"
    )
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")
    list_parser.set_defaults(func=cmd_list)

    inspect_parser = subparsers.add_parser("inspect", help="Show detailed info for one VM")
    inspect_parser.add_argument("id", help="Full ID, name, or unique ID prefix")
    inspect_parser.add_argument("--json", action="store_true", help="Output as JSON")
    inspect_parser.set_defaults(func=cmd_inspect)

    logs_parser = subparsers.add_parser("logs", help="Tail the VMM log or guest console log")
    logs_parser.add_argument("id", help="Full ID, name, or unique ID prefix")
    logs_parser.add_argument(
        "--console", action="store_true", help="Show the guest serial console instead of the VMM log"
    )
    logs_parser.add_argument(
        "-n", dest="lines", type=int, default=10, help="Number of lines to show (default: 10)"
    )
    logs_parser.add_argument("-f", "--follow", action="store_true", help="Follow the log as it grows")
    logs_parser.set_defaults(func=cmd_logs)

    ssh_parser = subparsers.add_parser("ssh", help="Exec the system ssh binary against the VM's IP")
    ssh_parser.add_argument("id", help="Full ID, name, or unique ID prefix")
    ssh_parser.add_argument("-i", dest="key", default=None, help="Path to SSH private key")
    ssh_parser.add_argument("-u", dest="user", default=None, help="SSH username (default: root)")
    ssh_parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        default=[],
        help="Command to run instead of an interactive shell (prefix with --)",
    )
    ssh_parser.set_defaults(func=cmd_ssh)

    api_parser = subparsers.add_parser("api", help="Send a raw request to the VM's API socket")
    api_parser.add_argument("id", help="Full ID, name, or unique ID prefix")
    api_parser.add_argument("path", help="API path, e.g. /vm/config")
    api_parser.add_argument("-X", dest="method", default="GET", help="HTTP method (default: GET)")
    api_parser.add_argument("-d", dest="data", default=None, help="JSON request body")
    api_parser.set_defaults(func=cmd_api)

    net_parser = subparsers.add_parser("net", help="Show TAP device and nftables rule state")
    net_parser.add_argument("id", nargs="?", default=None, help="Limit to one VM (default: all known VMs)")
    net_parser.add_argument("--json", action="store_true", help="Output as JSON")
    net_parser.set_defaults(func=cmd_net)

    doctor_parser = subparsers.add_parser("doctor", help="Check the host for common setup problems")
    doctor_parser.add_argument("--json", action="store_true", help="Output as JSON")
    doctor_parser.set_defaults(func=cmd_doctor)

    events_parser = subparsers.add_parser("events", help="Show or watch VM lifecycle events")
    events_parser.add_argument("id", nargs="?", default=None, help="Filter to one VM ID (prefix match)")
    events_parser.add_argument(
        "--since", default=None, help="Only show events after this time (e.g. 2h, 1d, 2026-10-01)"
    )
    events_parser.add_argument("--json", action="store_true", help="Output as JSON")
    events_parser.add_argument(
        "--watch", "-f", action="store_true", help="Poll for new events and print them live"
    )
    events_parser.add_argument(
        "--interval", type=int, default=2, help="Polling interval in seconds for --watch (default: 2)"
    )
    events_parser.set_defaults(func=cmd_events)

    delete_parser = subparsers.add_parser(
        "delete", help="Delete a VM (including dead/broken ones) and record the event"
    )
    delete_parser.add_argument("id", help="Full ID, name, or unique ID prefix")
    delete_parser.set_defaults(func=cmd_delete)

    prune_parser = subparsers.add_parser(
        "prune", help="Remove all dead/broken VM directories and orphan TAP devices"
    )
    prune_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    prune_parser.set_defaults(func=cmd_prune)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
