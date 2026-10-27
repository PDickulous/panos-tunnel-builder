import os
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest

from panos_tunnel_builder import artifacts


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_private_from_creation_even_with_permissive_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o755)
    output = tmp_path / "new" / "nested" / "routes.json"
    real_fsync = os.fsync

    def inspect_before_publication(descriptor: int) -> None:
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
        assert not output.exists()
        assert stat.S_IMODE(output.with_suffix(".json.tmp").stat().st_mode) == 0o600
        real_fsync(descriptor)

    monkeypatch.setattr(artifacts.os, "fsync", inspect_before_publication)
    previous_umask = os.umask(0)
    try:
        artifacts.write_private_artifact(output, "routing authentication evidence")
    finally:
        os.umask(previous_umask)

    assert output.read_text() == "routing authentication evidence"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(output.parent.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o755
    assert not output.with_suffix(".json.tmp").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_explicit_overwrite_restricts_previously_public_file(tmp_path: Path) -> None:
    output = tmp_path / "routes.json"
    output.write_text("old evidence")
    output.chmod(0o666)
    artifacts.write_private_artifact(output, "new evidence", overwrite=True)
    assert output.read_text() == "new evidence"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("retain", [False, True])
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_failed_write_preserves_original_and_controls_private_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retain: bool,
    failure: type[BaseException],
) -> None:
    output = tmp_path / "routes.json"
    output.write_text("previous evidence")
    monkeypatch.setattr(
        artifacts.os, "fsync", Mock(side_effect=failure("interrupted write"))
    )
    with pytest.raises(failure):
        artifacts.write_private_artifact(
            output,
            "new evidence",
            overwrite=True,
            retain_staging_on_error=retain,
        )
    assert output.read_text() == "previous evidence"
    staging = output.with_suffix(".json.tmp")
    assert staging.exists() is retain
    if retain and os.name == "posix":
        assert stat.S_IMODE(staging.stat().st_mode) == 0o600


def test_no_overwrite_publication_handles_destination_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "routes.json"
    real_link = os.link

    def competing_writer(source: Path, destination: Path) -> None:
        destination.write_text("another capture")
        real_link(source, destination)

    monkeypatch.setattr(artifacts.os, "link", competing_writer)
    with pytest.raises(FileExistsError):
        artifacts.write_private_artifact(output, "this capture")
    assert output.read_text() == "another capture"
    assert not output.with_suffix(".json.tmp").exists()


@pytest.mark.parametrize("overwrite", [False, True])
def test_destination_symlink_does_not_modify_its_target(
    tmp_path: Path,
    overwrite: bool,
) -> None:
    target = tmp_path / "unrelated.txt"
    target.write_text("untouched")
    output = tmp_path / "routes.json"
    output.symlink_to(target)
    if overwrite:
        artifacts.write_private_artifact(output, "capture", overwrite=True)
        assert not output.is_symlink()
        assert output.read_text() == "capture"
    else:
        with pytest.raises(FileExistsError):
            artifacts.write_private_artifact(output, "capture")
        assert output.is_symlink()
    assert target.read_text() == "untouched"


def test_existing_staging_symlink_is_not_followed_or_deleted(tmp_path: Path) -> None:
    output = tmp_path / "routes.json"
    target = tmp_path / "unrelated.txt"
    target.write_text("untouched")
    staging = output.with_suffix(".json.tmp")
    staging.symlink_to(target)
    with pytest.raises(FileExistsError):
        artifacts.write_private_artifact(output, "capture")
    assert target.read_text() == "untouched"
    assert staging.is_symlink()
    assert not output.exists()
