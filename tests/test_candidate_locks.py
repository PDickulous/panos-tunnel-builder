import xml.etree.ElementTree as ET
from unittest.mock import Mock

import pytest
from panos.panorama import Panorama

from panos_tunnel_builder import candidate


@pytest.fixture(autouse=True)
def verified_source(monkeypatch: pytest.MonkeyPatch) -> None:
    # These transaction tests isolate source validation, exercised separately in
    # test_source_configuration.py with real XML and lock sequencing.
    monkeypatch.setattr(candidate, "assert_source_configuration_unchanged", Mock())


@pytest.fixture
def protection(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Panorama, Mock, Mock, Mock]:
    panorama = Panorama("panorama.example.test", api_key="dummy")
    xapi = Mock()
    xapi.op.return_value = ET.fromstring(
        '<response status="success"><result /></response>'
    )
    panorama._xapi_private = xapi
    migration = Mock(return_value=candidate.CandidateLoadResult("snapshot.xml", 1, 1))
    restore = Mock(
        return_value=candidate.CandidateRestoreResult("saved.xml", "checkpoint.xml")
    )
    monkeypatch.setattr(candidate, "_load_candidate_configuration_locked", migration)
    monkeypatch.setattr(candidate, "_restore_candidate_locked", restore)
    return panorama, xapi, migration, restore


def _invoke(
    panorama: Panorama, operation: str
) -> candidate.CandidateLoadResult | candidate.CandidateRestoreResult:
    if operation == "restore":
        return candidate.restore_candidate_configuration(panorama, "saved.xml")
    return candidate.load_candidate_configuration(
        panorama,
        "branch",
        (),
        (),
        (),
        source_configuration=(),
    )


@pytest.mark.parametrize("operation", ["migration", "restore"])
def test_both_shared_locks_and_job_check_precede_mutation(
    protection: tuple[Panorama, Mock, Mock, Mock],
    operation: str,
) -> None:
    panorama, xapi, migration, restore = protection
    transaction = restore if operation == "restore" else migration
    result = transaction.return_value

    def mutate(*args: object, **kwargs: object) -> object:
        assert panorama.config_locked and panorama.commit_locked
        commands = [ET.fromstring(call.args[0]) for call in xapi.op.call_args_list]
        assert len(commands) == 3
        assert commands[0].find("config-lock/add") is not None
        assert commands[1].find("commit-lock/add") is not None
        assert commands[2].find("jobs/all") is not None
        return result

    transaction.side_effect = mutate
    assert _invoke(panorama, operation) == result
    commands = [ET.fromstring(call.args[0]) for call in xapi.op.call_args_list]
    assert commands[3].find("config-lock/remove") is not None
    assert commands[4].find("commit-lock/remove") is not None
    for index in (0, 1, 3, 4):
        call = xapi.op.call_args_list[index]
        assert call.kwargs["vsys"] == "shared"
        assert call.kwargs["retry_on_peer"] is False
        assert commands[index].find(".//admin") is None
    assert not panorama.config_locked and not panorama.commit_locked
    assert not xapi.commit.called


@pytest.mark.parametrize("operation", ["migration", "restore"])
@pytest.mark.parametrize("phase", ["config", "commit"])
@pytest.mark.parametrize(
    "failure", [False, RuntimeError, KeyboardInterrupt, SystemExit]
)
def test_acquisition_failure_never_mutates_or_removes_unconfirmed_locks(
    protection: tuple[Panorama, Mock, Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    phase: str,
    failure: bool | type[BaseException],
) -> None:
    panorama, _, migration, restore = protection
    acquire = Mock(return_value=False)
    if failure is not False:
        assert isinstance(failure, type)
        acquire.side_effect = failure("lock unavailable or response lost")
    monkeypatch.setattr(panorama, f"add_{phase}_lock", acquire)
    config_release, commit_release = Mock(), Mock()
    monkeypatch.setattr(panorama, "remove_config_lock", config_release)
    monkeypatch.setattr(panorama, "remove_commit_lock", commit_release)
    with pytest.raises(
        (candidate.CandidateLoadError, candidate.CandidateRestoreError)
    ) as raised:
        _invoke(panorama, operation)
    assert "not attempted" in str(raised.value)
    assert config_release.call_count == int(phase == "commit")
    commit_release.assert_not_called()
    migration.assert_not_called()
    restore.assert_not_called()
    if failure in (KeyboardInterrupt, SystemExit):
        assert isinstance(raised.value, candidate.CandidateLoadInterrupted) or (
            isinstance(raised.value, candidate.CandidateRestoreError)
            and raised.value.interrupted
        )


@pytest.mark.parametrize("operation", ["migration", "restore"])
@pytest.mark.parametrize(
    "kind,status",
    [
        ("Commit", "ACT"),
        ("CommitAll", "QUEUED"),
        ("AutoCom", "PEND"),
        ("Commit", "UNKNOWN"),
        ("Content", "ACT"),
        ("FutureJobType", "PEND"),
    ],
)
def test_unfinished_jobs_block_before_checkpoint_or_candidate_changes(
    protection: tuple[Panorama, Mock, Mock, Mock],
    operation: str,
    kind: str,
    status: str,
) -> None:
    panorama, xapi, migration, restore = protection
    # Result=OK is deliberately not treated as completion while status is active.
    xapi.op.return_value = ET.fromstring(
        f'<response status="success"><result><job><id>42</id><type>{kind}</type>'
        f"<status>{status}</status><result>OK</result></job></result></response>"
    )
    with pytest.raises(
        (candidate.CandidateLoadError, candidate.CandidateRestoreError),
        match=f"42 \\({kind}, {status}\\)",
    ):
        _invoke(panorama, operation)
    migration.assert_not_called()
    restore.assert_not_called()
    assert not panorama.config_locked and not panorama.commit_locked


@pytest.mark.parametrize(
    "response",
    [
        '<response status="error"><result /></response>',
        '<response status="success" />',
        '<response status="success"><result><unexpected /></result></response>',
        '<response status="success"><result>not a job listing</result></response>',
        '<response status="success"><result><job><id>42</id>'
        "<type>Commit</type></job></result></response>",
    ],
)
def test_unverifiable_job_responses_fail_closed(
    protection: tuple[Panorama, Mock, Mock, Mock],
    response: str,
) -> None:
    panorama, xapi, migration, _ = protection
    xapi.op.return_value = ET.fromstring(response)
    with pytest.raises(candidate.CandidateLoadError, match="not attempted"):
        _invoke(panorama, "migration")
    migration.assert_not_called()
    assert not panorama.config_locked and not panorama.commit_locked


@pytest.mark.parametrize("operation", ["migration", "restore"])
def test_failed_job_query_releases_both_locks_without_mutating(
    protection: tuple[Panorama, Mock, Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    panorama, _, migration, restore = protection
    monkeypatch.setattr(
        panorama, "op", Mock(side_effect=TimeoutError("job query timed out"))
    )
    with pytest.raises(
        (candidate.CandidateLoadError, candidate.CandidateRestoreError),
        match="job query timed out",
    ):
        _invoke(panorama, operation)
    migration.assert_not_called()
    restore.assert_not_called()
    assert not panorama.config_locked and not panorama.commit_locked


def test_finished_job_history_does_not_block(
    protection: tuple[Panorama, Mock, Mock, Mock],
) -> None:
    panorama, xapi, migration, _ = protection
    xapi.op.return_value = ET.fromstring(
        '<response status="success"><result><job><id>42</id><type>Commit</type>'
        "<status>FIN</status><result>FAIL</result></job></result></response>"
    )
    _invoke(panorama, "migration")
    migration.assert_called_once()


@pytest.mark.parametrize("operation", ["migration", "restore"])
@pytest.mark.parametrize("transaction_failed", [False, True])
@pytest.mark.parametrize(
    "cleanup_failure", [RuntimeError, KeyboardInterrupt, SystemExit]
)
def test_both_cleanup_failures_are_reported_without_masking_transaction(
    protection: tuple[Panorama, Mock, Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    transaction_failed: bool,
    cleanup_failure: type[BaseException],
) -> None:
    panorama, _, migration, restore = protection
    transaction = restore if operation == "restore" else migration
    primary = (
        candidate.CandidateRestoreError("restore failed; checkpoint recovery failed")
        if operation == "restore"
        else candidate.CandidateLoadError("write failed; rollback failed")
    )
    if transaction_failed:
        transaction.side_effect = primary
    config_release = Mock(side_effect=cleanup_failure("config release failed"))
    commit_release = Mock(side_effect=RuntimeError("commit release failed"))
    monkeypatch.setattr(panorama, "remove_config_lock", config_release)
    monkeypatch.setattr(panorama, "remove_commit_lock", commit_release)
    if transaction_failed:
        with pytest.raises(type(primary)) as raised:
            _invoke(panorama, operation)
        assert raised.value is primary
        message = primary.lock_cleanup_error
    else:
        outcome = _invoke(panorama, operation)
        message = outcome.lock_cleanup_error
        if isinstance(outcome, candidate.CandidateLoadResult):
            assert outcome.panorama_snapshot_name == "snapshot.xml"
        else:
            assert outcome.checkpoint_name == "checkpoint.xml"
    assert message is not None
    assert "configuration lock:" in message and "config release failed" in message
    assert "commit lock:" in message and "commit release failed" in message
    config_release.assert_called_once()
    commit_release.assert_called_once()


@pytest.mark.parametrize("operation", ["migration", "restore"])
def test_commit_acquisition_and_config_cleanup_failures_both_survive(
    protection: tuple[Panorama, Mock, Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    panorama, _, migration, restore = protection
    monkeypatch.setattr(
        panorama, "add_commit_lock", Mock(side_effect=RuntimeError("commit busy"))
    )
    config_release = Mock(return_value=False)
    commit_release = Mock()
    monkeypatch.setattr(panorama, "remove_config_lock", config_release)
    monkeypatch.setattr(panorama, "remove_commit_lock", commit_release)
    with pytest.raises(
        (candidate.CandidateLoadError, candidate.CandidateRestoreError),
        match="commit busy",
    ) as raised:
        _invoke(panorama, operation)
    assert raised.value.lock_cleanup_error is not None
    assert "configuration lock:" in raised.value.lock_cleanup_error
    assert "release was not confirmed" in raised.value.lock_cleanup_error
    commit_release.assert_not_called()
    migration.assert_not_called()
    restore.assert_not_called()
