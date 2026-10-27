import xml.etree.ElementTree as ET
from unittest.mock import Mock

import pytest
from panos.panorama import Panorama

from panos_tunnel_builder import candidate
from panos_tunnel_builder.lsvpn import LsvpnConfigurationError


def _config(value: str = "original", metadata: str = "") -> ET.Element:
    return ET.fromstring(
        f'<response status="success"><result><config {metadata}>'
        f"<shared><description>{value}</description></shared>"
        "</config></result></response>"
    )


@pytest.fixture
def source() -> tuple[Panorama, Mock]:
    panorama = Panorama("panorama.example.test", api_key="dummy")
    xapi = Mock()
    xapi.get.return_value = _config()
    xapi.show.return_value = _config()

    def op(command: bytes, *args: object, **kwargs: object) -> ET.Element:
        if b"effective-running" in command:
            return _config()
        return ET.fromstring('<response status="success"><result /></response>')

    xapi.op.side_effect = op
    panorama._xapi_private = xapi
    return panorama, xapi


def test_fingerprints_include_candidate_running_and_effective_config(
    source: tuple[Panorama, Mock],
) -> None:
    panorama, xapi = source
    captured = candidate.capture_source_configuration(panorama, "001122")
    xapi.get.assert_called_once_with("/config", extra_qs={"target": "001122"})
    xapi.show.assert_called_once_with("/config", extra_qs={"target": "001122"})
    assert xapi.op.call_args.args[3] == {"target": "001122"}
    assert captured.serial == "001122"
    assert captured.effective_running == captured.running == captured.candidate
    assert "original" not in repr(captured)
    assert len(captured.candidate) == 64


def test_formatting_and_panorama_metadata_do_not_invalidate_source(
    source: tuple[Panorama, Mock],
) -> None:
    panorama, xapi = source
    baseline = candidate.capture_source_configuration(panorama)
    xapi.get.return_value = _config(metadata='dirtyId="12" admin="user" time="now"')
    config = xapi.get.return_value.find("./result/config")
    assert config is not None
    config.text = "\n  "
    candidate.assert_source_configuration_unchanged(panorama, (baseline,))


@pytest.mark.parametrize(
    "scope,change",
    [
        (scope, change)
        for scope in ("panorama", "spoke", "hub", "shared-spoke")
        for change in ("candidate", "running", "effective", "committed")
        if (scope, change) != ("panorama", "effective")
    ],
)
def test_source_drift_blocks_before_snapshot_writes_or_rollback(
    source: tuple[Panorama, Mock],
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    change: str,
) -> None:
    panorama, xapi = source
    serials = {"panorama": None, "spoke": "001", "hub": "002", "shared-spoke": "003"}
    expected = tuple(
        candidate.capture_source_configuration(panorama, serial)
        for serial in serials.values()
    )
    changed_serial = serials[scope]

    def read(method: str, xpath: str, **kwargs: object) -> ET.Element:
        assert panorama.config_locked and panorama.commit_locked
        target = kwargs.get("extra_qs", {})
        serial = target.get("target") if isinstance(target, dict) else None
        changed = serial == changed_serial and change in (method, "committed")
        return _config("changed" if changed else "original")

    xapi.get.side_effect = lambda xpath, **kwargs: read("candidate", xpath, **kwargs)
    xapi.show.side_effect = lambda xpath, **kwargs: read("running", xpath, **kwargs)
    previous_op = xapi.op.side_effect

    def op(command: bytes, *args: object, **kwargs: object) -> ET.Element:
        if b"effective-running" in command and args[2] == {"target": changed_serial}:
            if change in ("effective", "committed"):
                return _config("changed")
        if change == "committed" and b"<jobs>" in command:
            candidate.assert_clean_candidate_configuration(panorama)
        return previous_op(command, *args, **kwargs)

    xapi.op.side_effect = op
    transaction = Mock()
    rollback = Mock()
    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", transaction)
    monkeypatch.setattr(candidate, "rollback_candidate_configuration", rollback)
    # In the committed case both views changed identically: cleanliness alone passes.
    with pytest.raises(
        LsvpnConfigurationError, match="rebuild and review a fresh plan"
    ):
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            allow_dirty_candidate=True,
            source_configuration=expected,
        )
    transaction.assert_not_called()
    rollback.assert_not_called()
    xapi.set.assert_not_called()
    xapi.edit.assert_not_called()
    xapi.delete.assert_not_called()
    assert not panorama.config_locked and not panorama.commit_locked
    assert not any(b"<save" in call.args[0] for call in xapi.op.call_args_list)


def test_unchanged_sources_are_checked_under_locks_before_transaction(
    source: tuple[Panorama, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = source
    expected = (
        candidate.capture_source_configuration(panorama),
        candidate.capture_source_configuration(panorama, "001"),
    )
    xapi.reset_mock()
    result = candidate.CandidateLoadResult("saved.xml", 1, 1)

    def transaction(*args: object, **kwargs: object) -> candidate.CandidateLoadResult:
        assert panorama.config_locked and panorama.commit_locked
        assert xapi.get.call_count == xapi.show.call_count == 2
        return result

    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", transaction)
    assert (
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=expected,
        )
        == result
    )


@pytest.mark.parametrize("method", ["get", "show", "effective"])
@pytest.mark.parametrize(
    "response",
    [
        '<response status="error"><result><config><shared />'
        "</config></result></response>",
        '<response status="success"><result /></response>',
        "<unexpected><result><config><shared /></config></result></unexpected>",
        '<response status="success"><result><config /></result></response>',
        '<response status="success"><result><entry><config><shared />'
        "</config></entry></result></response>",
        None,
    ],
)
def test_missing_partial_or_failed_configuration_is_rejected(
    source: tuple[Panorama, Mock],
    method: str,
    response: str | None,
) -> None:
    panorama, xapi = source
    value = ET.fromstring(response) if response else None
    if method == "effective":
        xapi.op.side_effect = None
        xapi.op.return_value = value
    else:
        getattr(xapi, method).return_value = value
    with pytest.raises(LsvpnConfigurationError, match="Cannot verify"):
        candidate.capture_source_configuration(panorama, "001")


@pytest.mark.parametrize("failure", [TimeoutError, KeyboardInterrupt, SystemExit])
def test_interrupted_or_failed_recheck_releases_locks_without_mutation(
    source: tuple[Panorama, Mock],
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
) -> None:
    panorama, xapi = source
    expected = (candidate.capture_source_configuration(panorama),)
    xapi.show.side_effect = failure("source read failed")
    transaction = Mock()
    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", transaction)
    with pytest.raises(failure, match="source read failed"):
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=expected,
        )
    transaction.assert_not_called()
    assert not panorama.config_locked and not panorama.commit_locked


def test_missing_panorama_baseline_cannot_bypass_source_check(
    source: tuple[Panorama, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, _ = source
    transaction = Mock()
    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", transaction)
    with pytest.raises(LsvpnConfigurationError, match="pre-discovery Panorama"):
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=(),
        )
    transaction.assert_not_called()


def test_drift_and_lock_cleanup_failure_preserve_both_errors(
    source: tuple[Panorama, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, xapi = source
    expected = (candidate.capture_source_configuration(panorama),)
    xapi.get.return_value = _config("changed")
    config_release = Mock(side_effect=RuntimeError("configuration unlock failed"))
    monkeypatch.setattr(panorama, "remove_config_lock", config_release)
    transaction = Mock()
    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", transaction)
    with pytest.raises(
        candidate.CandidateLoadError, match="Source configuration changed"
    ) as raised:
        candidate.load_candidate_configuration(
            panorama,
            "branch",
            (),
            (),
            (),
            source_configuration=expected,
        )
    assert "configuration unlock failed" in str(raised.value.lock_cleanup_error)
    assert not panorama.commit_locked
    transaction.assert_not_called()
