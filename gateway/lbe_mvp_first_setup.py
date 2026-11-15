"""Explicit OFFLINE, first-install-only private Exec state provisioning.

Never called by WorkspaceService startup, REST or MCP.  The operator must
confirm this is a genuinely new installation with no prior Exec history
AND that every Gateway using this private root is stopped.  There is no
reset, recovery, repair, overwrite, rollback, replay or positive Exec grant.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .private_fs import PrivateFileError, open_pinned_directory


def initialize_fresh_v2_exec_state(
    config_dir: str | Path, *,
    operator_confirmed_first_install: bool = False,
    operator_confirmed_gateway_stopped: bool = False,
) -> dict[str, str | bool]:
    """Create a missing empty exec-state/owner.lock exactly once, offline.

    This primitive does not and cannot prove the operator's historical claim.
    It requires explicit confirmation and uses atomic no-clobber directory
    and lock creation.  A partially completed setup is left in place for
    manual inspection, NOT deleted/reset to silently force a green state.
    """
    if (operator_confirmed_first_install is not True
            or operator_confirmed_gateway_stopped is not True):
        raise PrivateFileError(
            "First installation and stopped Gateway must both be confirmed.")
    pin = open_pinned_directory(config_dir, private_leaf=True)
    child_fd = -1
    lock_fd = -1
    try:
        parent = os.fstat(pin.fd)
        if (parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise PrivateFileError(
                "Private control-plane directory must be operator-owned 0700.")
        # Reject an existing state root of ANY type, including a symlink or
        # abandoned partial setup.  No automatic quarantine reset or repair.
        try:
            os.stat("exec-state", dir_fd=pin.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            raise PrivateFileError(
                "Could not verify the private Exec state is absent.") from None
        else:
            raise PrivateFileError(
                "Exec state already exists; preserving prior identity/history.")

        try:
            os.mkdir("exec-state", mode=0o700, dir_fd=pin.fd)
            child_fd = os.open(
                "exec-state",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=pin.fd,
            )
            child = os.fstat(child_fd)
            if (child.st_uid != os.geteuid()
                    or stat.S_IMODE(child.st_mode) != 0o700):
                raise PrivateFileError("New Exec state root is not private.")
            lock_fd = os.open(
                "owner.lock",
                os.O_CREAT | os.O_EXCL | os.O_WRONLY
                | os.O_NOFOLLOW | os.O_CLOEXEC,
                mode=0o600, dir_fd=child_fd,
            )
            os.fchmod(lock_fd, 0o600)
            os.fsync(lock_fd)
            os.fsync(child_fd)
            os.fsync(pin.fd)
        except FileExistsError:
            raise PrivateFileError(
                "Exec state already exists; never overwrite it.") from None
        except OSError:
            raise PrivateFileError(
                "First-install provisioning failed; inspect state offline."
            ) from None
        return {
            "status": "first_install_provisioned",
            "state": "exec-state",
            "owner_lock": "owner.lock",
            "exec_enabled": False,
            "native_command_executed": False,
        }
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if child_fd >= 0:
            os.close(child_fd)
        pin.close()
