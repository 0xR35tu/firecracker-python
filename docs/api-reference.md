# API Reference

This page describes the public API of firecracker-python. The main entry point is the `MicroVM` class.

```python
from firecracker import MicroVM
```

## MicroVM

`MicroVM` describes one microVM. Use it to build a rootfs, create the VM, and manage it after it starts.

You can also use a `MicroVM` object to manage VMs that already exist. Pass their ID to methods such as `delete(id=...)` or `connect(id=...)`. For these calls, `MicroVM()` without arguments is enough.

### Constructor

```python
MicroVM(
    name=None,
    kernel_file=None,
    kernel_url=None,
    initrd_file=None,
    init_file=None,
    image=None,
    base_rootfs=None,
    rootfs_size=None,
    rootfs_format=None,
    overlayfs=False,
    overlayfs_file=None,
    vcpu=None,
    memory=None,
    ip_addr=None,
    mmds_enabled=None,
    mmds_ip=None,
    user_data=None,
    user_data_file=None,
    labels=None,
    expose_ports=False,
    host_port=None,
    dest_port=None,
    vsock_enabled=False,
    vsock_guest_cid=None,
    verbose=False,
    level="INFO",
)
```

The constructor always generates a random 8-character ID. You cannot choose the ID. Use `name` to give the VM a readable name.

The constructor connects to the local Docker daemon, so Docker must be running.

#### Kernel and boot

| Parameter | Type | Default | Description |
|---|---|---|---|
| `kernel_file` | str | `None` | Path to the guest kernel. **Required by `create()`.** |
| `kernel_url` | str | `None` | URL to download the kernel from. The file is saved to `kernel_file`, so you must pass both. The download is skipped if `kernel_file` already exists. |
| `initrd_file` | str | `None` | Path to an initrd. The file must exist when you create the object. When set, the rootfs drive is not marked as the root device. |
| `init_file` | str | `"/sbin/init"` | Path of the init program inside the guest. It is passed to the kernel only when `mmds_enabled` or `overlayfs` is set. |

#### Root filesystem

| Parameter | Type | Default | Description |
|---|---|---|---|
| `base_rootfs` | str | `None` | Path to the rootfs image. **Required by `create()`.** `create()` copies it into the VM directory, so the original stays unchanged. |
| `image` | str | `None` | Docker image to build the rootfs from with `build()`. Requires `base_rootfs`. The constructor checks that the image exists and pulls it if it is not local. |
| `rootfs_size` | str | `"5G"` | Size of the image that `build()` creates. Any size that `fallocate -l` accepts. |
| `rootfs_format` | str | `"ext4"` | File system that `build()` creates: `"ext3"`, `"ext4"` or `"xfs"`. Other values raise `ValueError`. |
| `overlayfs` | bool | `False` | Attach `base_rootfs` read-only and a second writable drive for an overlay. See [Overlayfs](advanced.md#overlayfs). |
| `overlayfs_file` | str | `None` | Path to the writable overlay drive. Defaults to `/var/lib/firecracker/<id>/rootfs/overlayfs.<rootfs_format>`. The library does not create this file. |

#### Resources

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | str | random | Name of the VM. Also used as the guest hostname. |
| `vcpu` | int | `1` | Number of vCPUs. Must be a positive integer. A float raises `ValueError`. |
| `memory` | int or str | `512` | Memory in MiB. Accepts a number (`1024`), or a string with `M` or `G` (`"512M"`, `"2G"`). Values below 128 MiB are raised to 128 MiB. |
| `labels` | dict | `{}` | Key-value labels. Stored in the VM's `config.json`. Use them with `find()`. |

#### Network

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ip_addr` | str | `"172.16.0.2"` | IPv4 address of the guest. The host side of the TAP device gets the `.1` address of the same `/24`. See [Network](network.md). |
| `expose_ports` | bool | `False` | Forward host ports to the guest when `create()` runs. Requires `host_port` and `dest_port`. |
| `host_port` | int, list or str | `None` | Host port or ports. A string can hold comma-separated ports, for example `"8080,8443"`. |
| `dest_port` | int, list or str | `None` | Guest port or ports. Must have the same number of entries as `host_port`. |

#### Metadata and vsock

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mmds_enabled` | bool | `False` | Enable the MicroVM Metadata Service (MMDS), version 2. See [MMDS](advanced.md#mmds-and-user-data). |
| `mmds_ip` | str | `"169.254.169.254"` | IPv4 address of MMDS inside the guest. |
| `user_data` | str | `None` | Text stored in MMDS at `latest/user-data`. The library does not run it. |
| `user_data_file` | str | `None` | Path to a file to read `user_data` from. You cannot pass both `user_data` and `user_data_file`. |
| `vsock_enabled` | bool | `False` | Attach a vsock device. See [Vsock](advanced.md#vsock). |
| `vsock_guest_cid` | int | `3` | Context ID (CID) of the guest on the vsock device. |

#### Logging

| Parameter | Type | Default | Description |
|---|---|---|---|
| `verbose` | bool | `False` | Print progress messages. |
| `level` | str | `"INFO"` | Log level, for example `"DEBUG"`. |

### Errors

Most methods wrap failures in `firecracker.exceptions.VMMError`. Some methods return a message string instead of raising an error, for example when a VM ID does not exist. The table under each method shows the return value.

## Static methods

### `MicroVM.list()`

Lists the VMs that have a `config.json` file and a running Firecracker process.

**Returns:** `list[dict]`. Each entry has these keys:

| Key | Description |
|---|---|
| `id` | VM ID |
| `name` | VM name |
| `pid` | Process ID of Firecracker |
| `ip_addr` | Guest IP address |
| `state` | `"Running"` or `"Paused"` |
| `created_at` | Creation time |
| `ports` | Forwarded ports, for example `{"22/tcp": [{"HostPort": 10222, "DestPort": 22}]}` |
| `labels` | Labels |

```python
for info in MicroVM.list():
    print(info["id"], info["ip_addr"], info["state"])
```

## Instance methods

In the methods below, `id` defaults to the ID of the current object.

### `build()`

Builds the rootfs image at `base_rootfs` from the Docker image in `image`. See [Build a rootfs from a Docker image](rootfs.md) for the full guide.

**Returns:** `str`. `"Rootfs built at <base_rootfs>"`, or `"No Docker image specified for building rootfs"` if `image` is not set.

**Raises:** `VMMError` if the build fails.

```python
vm = MicroVM(
    image="my-rootfs:latest",
    base_rootfs="/var/lib/firecracker/rootfs.img",
    kernel_file="./firecracker-files/vmlinux",
)
vm.build()
vm.create()
```

Call `build()` before `create()`. `create()` does not build the image for you.

### `create(snapshot=False, memory_path=None, snapshot_path=None, rootfs_path=None)`

Starts Firecracker, configures the VM and boots it.

| Parameter | Description |
|---|---|
| `snapshot` | If `True`, load the VM from a snapshot instead of booting it. |
| `memory_path` | Path to the snapshot memory file. Required when `snapshot=True`. |
| `snapshot_path` | Path to the snapshot state file. Required when `snapshot=True`. |
| `rootfs_path` | Rootfs to use when loading a snapshot. Overrides the path saved in the snapshot. |

`kernel_file` and `base_rootfs` must point to existing files, also when you load a snapshot.

**Returns:** `str`. One of:

- `"VMM <id> created"`
- `"VMM <id> failed to create"`
- `"VMM with ID <id> already exists"`
- `"IP address <ip> is already in use"`

**Raises:** `VMMError` if a step fails.

```python
vm = MicroVM(
    kernel_file="./firecracker-files/vmlinux",
    base_rootfs="./firecracker-files/rootfs.img",
)
vm.create()
```

See [Snapshots](snapshots.md) for the snapshot flow.

### `snapshot(id=None, action=None, memory_path=None, snapshot_path=None, rootfs_path=None)`

Creates or loads a snapshot.

| `action` | Behavior |
|---|---|
| `"create"` | Pauses the VM, writes the snapshot, and resumes the VM. |
| `"load"` | Loads a snapshot into a new Firecracker process. Use `create(snapshot=True, ...)` instead of calling this directly. |

`memory_path` and `snapshot_path` default to `/var/lib/firecracker/snapshots/<id>/memory` and `/var/lib/firecracker/snapshots/<id>/snapshot`.

**Raises:** `VMMError`. Any other `action` value also raises `VMMError`.

```python
vm.snapshot(action="create")
```

### `find(state=None, labels=None)`

Finds VMs with a given state and labels.

| Parameter | Description |
|---|---|
| `state` | `"Running"` or `"Paused"`. The value is case-sensitive. |
| `labels` | Dict of labels. A VM matches only if it has all of them. |

**Returns:** `list[dict]` with the keys `id`, `name`, `state` and `created_at`. Returns `"No state provided"` if `state` is empty.

```python
vm = MicroVM()
vm.find(state="Running", labels={"env": "prod"})
```

### `config(id=None)`

Returns the live VM configuration from the Firecracker API (`GET /vm/config`).

**Returns:** `dict`.

### `inspect(id=None)`

Returns the contents of `/var/lib/firecracker/<id>/config.json`.

**Returns:** `dict`, or `"VMM ID not exist"` if the file does not exist.

### `status(id=None)`

**Returns:** `str`. `"VMM <id> is running"` or `"VMM <id> is paused"`.

### `pause(id=None)` and `resume(id=None)`

Pauses or resumes the VM through the Firecracker API.

**Returns:** `str`. `"VMM <id> paused successfully"` or `"VMM <id> resumed successfully"`.

### `delete(id=None, all=False, force=False)`

Stops the VM and removes its TAP device, nftables rules, port forwards and directory.

| Parameter | Description |
|---|---|
| `id` | ID of the VM to delete. |
| `all` | If `True`, delete every VM and clean up orphaned TAP devices. |
| `force` | If `True`, clean up the VM even when its process is dead. Raises `VMMError` if a step fails. Cannot be used with `all`. See [Delete a VM whose process is dead](cleanup.md#delete-a-vm-whose-process-is-dead). |

**Returns:** `str`. One of:

- `"VMM <id> is deleted"`
- `"All VMMs and orphaned resources are deleted"`
- `"VMM with ID <id> not found"`
- `"No VMMs available to delete"`. In this case nothing is cleaned, also with `all=True`. See [Cleanup](cleanup.md).

```python
MicroVM().delete(id="abcd1234")
MicroVM().delete(all=True)
MicroVM().delete(id="abcd1234", force=True)
```

### `close()`

Releases the API session and the Docker client that the object holds. A long-running program that makes a new `MicroVM` for each task must close each one.

A `MicroVM` is also a context manager. It closes itself at the end of the `with` block:

```python
with MicroVM() as vm:
    vm.delete(id="abcd1234", force=True)
```

`MicroVM.list()` closes its own resources. Call it on the class, not on a new object.

### `connect(id=None, username=None, key_path=None)`

Opens an interactive SSH session to the guest. The call returns when the session ends.

| Parameter | Description |
|---|---|
| `username` | SSH user. Defaults to `root`. |
| `key_path` | Path to the SSH private key. **Required.** |

The library makes up to 3 connection attempts, 2 seconds apart.

**Returns:** `None` when the session closes. Returns a message string if `key_path` is missing or the VM does not exist.

```python
vm.connect(key_path="./ssh_keys/ubuntu-22.04")
```

### `port_forward(id=None, host_port=None, dest_port=None, remove=False)`

Adds or removes TCP port forwards from the host to the guest.

| Parameter | Description |
|---|---|
| `host_port` | Host port, or a list of ports. |
| `dest_port` | Guest port, or a list of ports. Must have the same length as `host_port`. |
| `remove` | If `True`, remove the forwards instead of adding them. |

**Returns:** `str`. `"Port forwarding added successfully for VMM <id>"` or `"Port forwarding removed successfully for VMM <id>"`.

```python
vm.port_forward(host_port=8080, dest_port=80)
vm.port_forward(host_port=8080, dest_port=80, remove=True)
```

## Exceptions

All exceptions are in `firecracker.exceptions` and inherit from `FirecrackerError`.

| Exception | Raised for |
|---|---|
| `FirecrackerError` | Base class |
| `VMMError` | VM operations. Most `MicroVM` methods raise this. |
| `ConfigurationError` | Invalid configuration, or a failed Firecracker configuration call |
| `NetworkError` | TAP device, nftables or IP address errors |
| `APIError` | Errors from the Firecracker HTTP API |
| `ProcessError` | Errors when starting or stopping the Firecracker process |

`MicroVM` wraps most errors in `VMMError`. Catch `VMMError` first.

```python
from firecracker.exceptions import VMMError

try:
    vm.create()
except VMMError as e:
    print(f"Create failed: {e}")
```

## Other classes

These classes are exported but mostly used inside the library.

| Class | Import | Purpose |
|---|---|---|
| `Api` | `from firecracker import Api` | HTTP client for the Firecracker API socket. `Api(socket_file, timeout=5)`. |
| `Logger` | `from firecracker import Logger` | Logger used by the library. `Logger(level="INFO", verbose=False)`. |
| `NetworkManager` | `from firecracker.network import NetworkManager` | TAP devices, nftables rules and port forwards. See [Network](network.md). |
| `VMMManager` | `from firecracker.vmm import VMMManager` | VM directories, `config.json` and cleanup. |
| `ProcessManager` | `from firecracker.process import ProcessManager` | Starts and stops the Firecracker process. |

## Command-line tools

| Command | Purpose |
|---|---|
| `firecracker-check` | Checks that the Firecracker binary exists at `/usr/local/bin/firecracker` and is executable. |
