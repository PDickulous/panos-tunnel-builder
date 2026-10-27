"""Private, atomic storage for routing configuration and migration evidence."""

import os
from contextlib import suppress
from pathlib import Path


def create_artifact_directory(path: Path) -> None:
    """Create each missing directory privately; leave existing directories alone."""
    try:
        path.mkdir(mode=0o700)
    except FileNotFoundError:
        create_artifact_directory(path.parent)
        create_artifact_directory(path)
    except FileExistsError:
        if not path.is_dir():
            raise


def write_private_artifact(
    path: Path,
    content: str,
    *,
    overwrite: bool = False,
    retain_staging_on_error: bool = False,
) -> None:
    """Publish a complete UTF-8 file with mode 0600 on POSIX.

    Exclusive staging prevents following an existing symlink or truncating a
    previous staging file. Linking publishes without a check/overwrite race;
    explicit overwrite replaces the directory entry, not a symlink's target.
    """
    create_artifact_directory(path.parent)
    staging = path.with_name(path.name + ".tmp")
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if os.name == "posix":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            staging.replace(path)
        else:
            os.link(staging, path)
            staging.unlink()
    except (Exception, KeyboardInterrupt, SystemExit):
        if not retain_staging_on_error:
            with suppress(OSError):
                staging.unlink()
        raise
