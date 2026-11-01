# Cleanup

`delete()` stops a microVM and removes the resources it created on the host. This page explains what it removes, what it leaves, and how to clean up after a failed `create()`.

## What `delete()` removes

For a VM with the ID `abcd1234`, `delete()` removes:

| Resource | Example |
|---|---|
| Firecracker process | the Firecracker process of the VM |
| TAP device | `tap_abcd1234` |
| nftables rules for the TAP device | rules in the `ip nat` and `ip filter` tables that name `tap_abcd1234` exactly. Rules that other programs added for this TAP device are removed too. |
| Port forwards | rules with the comment `machine_id=abcd1234 ...` |
| Masquerade rule | the shared `microVM outbound NAT` rule. See [Known issues](#known-issues). |
| VM directory | `/var/lib/firecracker/abcd1234/`, including the rootfs copy and the logs |

The TAP device name always uses the random VM ID, not the VM `name`.

`delete()` removes the resources in this order:

1. The Firecracker process.
2. The VM directory. This is the largest item, so it goes early.
3. The network resources.

Each step runs even if an earlier step fails. Failures are logged together at the end:

```
Cleanup errors for abcd1234: Network cleanup failed: ...
```

## What `delete()` does not remove

- **Snapshots.** Files in `/var/lib/firecracker/snapshots/` stay. Delete them yourself.
- **The base rootfs.** `base_rootfs` is never changed or deleted. Only the copy in the VM directory is deleted.
- **Overlay files** that you passed as `overlayfs_file` outside the VM directory.

## Delete one VM or all VMs

```python
from firecracker import MicroVM

# The VM this object created
vm.delete()

# Any VM, by ID
MicroVM().delete(id="abcd1234")

# Every VM, plus orphaned TAP devices
MicroVM().delete(all=True)
```

`delete()` returns a message string:

| Return value | Meaning |
|---|---|
| `"VMM abcd1234 is deleted"` | The VM was deleted. |
| `"All VMMs and orphaned resources are deleted"` | `all=True` finished. |
| `"VMM with ID abcd1234 not found"` | No running VM has this ID. |
| `"No VMMs available to delete"` | No VM runs. Nothing was cleaned, also with `all=True`. |

## Delete a VM whose process is dead

Use `force=True` to clean up a VM after its Firecracker process crashed:

```python
MicroVM().delete(id="abcd1234", force=True)
```

Without `force`, `delete()` only finds VMs whose process runs. For a dead VM, it returns `"VMM with ID abcd1234 not found"` and removes nothing.

With `force=True`, `delete()` does these things:

- It runs every cleanup step, whatever the state of the process.
- It counts a resource that is already gone as removed. You can run it again safely.
- It raises `VMMError` if a step fails. It does not return an error string.
- It keeps the shared `microVM outbound NAT` rule, so other VMs keep their outbound traffic.
- It returns `"VMM abcd1234 is deleted"` also for an ID that has nothing left to clean up.
- It raises `VMMError` if the ID is not 8 letters or digits.

`force=True` works on one VM only. It raises `ValueError` together with `all=True`.

Before the library stops a process, it checks the process command line for `--id abcd1234`. Linux reuses process IDs. So the PID file of a VM that died long ago can name an unrelated process. The library never stops that process.

## Orphaned resources

A `create()` that fails can leave a TAP device and nftables rules behind. These resources are orphaned: no `config.json` exists for them, so `MicroVM.list()` does not show them.

`create()` cleans up by itself when Firecracker fails to start. A failure after that point, for example while it configures the boot source or the drives, can leave the TAP device and rules behind.

### How `delete(all=True)` finds orphans

1. It lists the running VMs with `MicroVM.list()`.
2. It lists the network devices whose name starts with `tap_`.
3. It deletes every `tap_<id>` device whose `<id>` is not a running VM, with its rules.

`delete(all=True)` runs this step only when at least one VM is running. When no VM runs, it returns `"No VMMs available to delete"` first.

### Clean up when no VM runs

Use one of the cleanup tools below, or delete the resources by hand:

```bash
# List TAP devices
ip link show | grep tap_

# Delete one
sudo ip link delete tap_abcd1234

# Look for the rules
sudo nft list table ip nat
sudo nft list table ip filter
```

## Cleanup tools

The repository has two scripts for development hosts. **Both remove more than the library creates.** Do not run them on a host where other software uses nftables, such as Docker or a firewall.

| Tool | What it does |
|---|---|
| `make cleanup-firecracker` (runs `scripts/cleanup_resources.py`) | Kills every `firecracker` process, deletes every `tap_*` device, **flushes** the `ip nat PREROUTING`, `ip nat POSTROUTING` and `ip filter FORWARD` chains, and deletes every VM directory and **every snapshot**. |
| `python cleanup_firecracker.py` | Kills every `firecracker` process, deletes every `tap_*` device, and flushes the same chains. Add `--clean-dirs` to also delete the directories in `/var/lib/firecracker`. Add `--dry-run` to see what it would do. |

> **Warning:** `make test` runs `make cleanup-firecracker` first. Running the tests deletes all VMs and snapshots on the host.

Run either tool as root.

## Known issues

- **Deleting one VM removes the shared masquerade rule.** `delete()` removes the `microVM outbound NAT` rule even when other VMs still run. Those VMs lose internet access until the next `create()` adds the rule again.
- **`delete(all=True)` skips orphan cleanup when no VM runs.** See [Clean up when no VM runs](#clean-up-when-no-vm-runs).

## Troubleshooting

### TAP devices remain after delete

Run the delete with debug logging, and read which step failed:

```python
from firecracker import MicroVM

MicroVM(verbose=True, level="DEBUG").delete(all=True)
```

### Permission errors

The library needs root to change network devices and nftables rules. Run Python as root.

### A VM is not in `MicroVM.list()`

`list()` shows a VM only when its `config.json` exists and its Firecracker process runs. A VM whose process died is not listed, so `delete(id=...)` returns `"VMM with ID ... not found"`. Delete its TAP device and directory by hand:

```bash
sudo ip link delete tap_abcd1234
sudo rm -rf /var/lib/firecracker/abcd1234
```

## Delete many VMs and continue on errors

```python
from firecracker import MicroVM
from firecracker.exceptions import VMMError

manager = MicroVM()
for vm_id in ["abcd1234", "efgh5678"]:
    try:
        print(manager.delete(id=vm_id))
    except VMMError as e:
        print(f"Error deleting {vm_id}: {e}")
```

## Tests

`tests/test_cleanup.py` covers this behavior:

```bash
uv run pytest tests/test_cleanup.py -v
```

## Related documentation

- [Getting Started](getting-started.md)
- [API Reference](api-reference.md)
- [Network](network.md)
- [Snapshots](snapshots.md)
