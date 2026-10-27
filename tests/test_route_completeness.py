import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from panos_tunnel_builder import cli
from panos_tunnel_builder import route_validation as rv
from panos_tunnel_builder.lsvpn import RoutingInstanceConfig


def _xml(body: str, status: str = "success") -> ET.Element:
    return ET.fromstring(
        f'<response status="{status}"><result>{body}</result></response>'
    )


def _advanced(data: object) -> ET.Element:
    element = ET.Element("response", {"status": "success"})
    result = ET.SubElement(element, "result")
    ET.SubElement(result, "json").text = json.dumps(data)
    return element


def _candidate() -> dict[str, object]:
    return {
        "prefix": "10.0.0.0/8",
        "protocol": "bgp",
        "vrfName": "default",
        "distance": 20,
        "metric": 10,
        "selected": True,
        "installed": True,
        "nexthops": [{"ip": "192.0.2.1", "interfaceName": "tunnel.1", "active": True}],
    }


@pytest.mark.parametrize(
    "body",
    [
        "<flags>flags: A:active, B:bgp</flags>",
        "<count>0</count>",
        "<total-count>0</total-count>",
    ],
)
def test_legacy_accepts_explicit_empty_tables(body: str) -> None:
    assert rv._parse_legacy_routes(_xml(body), "default") == ()


def test_legacy_accepts_supported_entries_and_flag_legend() -> None:
    result = rv._parse_legacy_routes(
        _xml(
            "<flags>flags: A:active, B:bgp</flags>"
            "<entry><virtual-router>default</virtual-router><destinatio"
            "n>10.0.0.0/8</destination>"
            "<flags>A B</flags><interface>tunnel.1</interface></entry><"
            "total-count>1</total-count>"
        ),
        "default",
    )
    assert len(result) == 1 and result[0].prefix == "10.0.0.0/8"


@pytest.mark.parametrize(
    "response",
    [
        '<response status="error"><result><count>0</count></result></response>',
        '<response status="success"/>',
        '<response status="success"><result /></response>',
        '<response status="success"><result>command failed</result></response>',
        '<response status="success"><result><flags /></result></response>',
        '<response status="success"><result><routes><entry><destina'
        "tion>10.0.0.0/8</destination></entry></routes></result></r"
        "esponse>",
        '<response status="success"><result><entry><destination>10.'
        "0.0.0/8</destination><flags>A B</flags></entry><entry><fla"
        "gs>A B</flags></entry></result></response>",
        '<response status="success"><result><entry><destination>bad'
        "</destination><flags>A B</flags></entry></result></respons"
        "e>",
        '<response status="success"><result><entry><destination>10.'
        "0.0.0/8</destination></entry></result></response>",
        '<response status="success"><result><entry><virtual-router>'
        "other</virtual-router><destination>10.0.0.0/8</destination"
        "><flags>A B</flags></entry></result></response>",
        '<response status="success"><result><entry><destination>10.'
        "0.0.0/8</destination><flags>A B</flags><metric>bad</metric"
        "></entry></result></response>",
        '<response status="success"><result><entry><destination>10.'
        "0.0.0/8</destination><flags>A B</flags></entry><total-coun"
        "t>2</total-count></result></response>",
    ],
)
def test_legacy_rejects_incomplete_or_unrecognized_tables(response: str) -> None:
    with pytest.raises(rv.RouteValidationError):
        rv._parse_legacy_routes(ET.fromstring(response), "default")


def test_advanced_accepts_explicit_empty_router() -> None:
    assert rv._parse_advanced_routes(_advanced({"MainLR": {}}), "MainLR") == ()


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"different-router": {}},
        {"MainLR": []},
        {"MainLR": {"not-a-prefix": []}},
        {"MainLR": {"10.0.0.0/8": None}},
        {"MainLR": {"10.0.0.0/8": []}},
        {"MainLR": {"10.0.0.0/8": [_candidate(), "bad"]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "prefix": "10.1.0.0/16"}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "protocol": None}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "vrfName": ""}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "nexthops": None}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "nexthops": ["bad"]}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "nexthops": [{}]}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "metric": "bad"}]}},
        {"MainLR": {"10.0.0.0/8": [{**_candidate(), "selected": "unknown"}]}},
    ],
)
def test_advanced_rejects_partial_tables_and_records(data: object) -> None:
    with pytest.raises(rv.RouteValidationError):
        rv._parse_advanced_routes(_advanced(data), "MainLR")


@pytest.mark.parametrize(
    "body",
    [
        "<routes><entry><destination>10.0.0.0/8</destination></entry></routes>",
        "<json />",
        "<json>not json</json>",
        '<json>{"MainLR": {}, "MainLR": {}}</json>',
        '<json>{"MainLR": {}}</json><other />',
    ],
)
def test_advanced_rejects_unknown_envelope_or_duplicate_keys(body: str) -> None:
    with pytest.raises(rv.RouteValidationError):
        rv._parse_advanced_routes(_xml(body), "MainLR")


@pytest.fixture
def capture_context(monkeypatch: pytest.MonkeyPatch) -> tuple[Mock, Mock]:
    panorama, firewall = Mock(), Mock()
    monkeypatch.setattr(rv, "Firewall", Mock(return_value=firewall))
    effective = ET.fromstring(
        '<response status="success"><result><config><devices><entry><network>'
        '<virtual-router><entry name="default" /></virtual-router>'
        "</network></entry></devices></config></result></response>"
    )
    monkeypatch.setattr(
        rv, "_read_effective_running_config", Mock(return_value=effective)
    )
    monkeypatch.setattr(cli, "load_settings", Mock())
    monkeypatch.setattr(cli, "create_panorama", Mock(return_value=panorama))
    return panorama, firewall


def test_capture_records_every_instance_and_aborts_if_any_query_fails(
    capture_context: tuple[Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panorama, firewall = capture_context
    instances = (
        RoutingInstanceConfig("virtual-router", "default"),
        RoutingInstanceConfig("logical-router", "MainLR", "default"),
        RoutingInstanceConfig("logical-router", "MainLR", "blue"),
    )
    monkeypatch.setattr(rv, "discover_routing_instances", Mock(return_value=instances))
    firewall.op.side_effect = [_xml("<count>0</count>"), _advanced({"MainLR": {}})]
    snapshot = rv.capture_route_snapshot(panorama, "branch", "001")
    assert snapshot.captured_routing_instances == instances
    assert rv.RouteSnapshot.from_json(snapshot.to_json()) == snapshot
    assert firewall.op.call_count == 2
    firewall.op.side_effect = [_xml("<count>0</count>"), _xml("<unexpected />")]
    with pytest.raises(rv.RouteValidationError):
        rv.capture_route_snapshot(panorama, "branch", "001")


def test_snapshot_cli_rejects_unrecognized_nonempty_response_without_artifact(
    capture_context: tuple[Mock, Mock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, firewall = capture_context
    firewall.op.return_value = _xml(
        "<routes><entry><destination>10.0.0.0/8</destination></entry></routes>"
    )
    monkeypatch.setattr(
        cli,
        "discover_managed_firewall",
        Mock(return_value=Mock(name="branch", serial="001")),
    )
    destination = tmp_path / "routes.json"
    result = CliRunner().invoke(
        cli.app, ["routes", "snapshot", "branch", str(destination)]
    )
    assert result.exit_code != 0
    assert "unrecognized route table" in result.output
    assert not destination.exists()


def test_verify_cli_rejects_unknown_postchange_table(
    capture_context: tuple[Mock, Mock],
    tmp_path: Path,
) -> None:
    panorama, firewall = capture_context
    firewall.op.return_value = _xml("<count>0</count>")
    before = rv.capture_route_snapshot(panorama, "branch", "001")
    (tmp_path / "before.json").write_text(before.to_json())
    endpoint = rv.MigrationEndpointValidation(
        "spoke", "branch", "001", "vsys1", "before.json", {}, (), ()
    )
    manifest = rv.MigrationValidationManifest(1, "today", "saved.xml", (endpoint,))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.to_json())
    firewall.op.return_value = _xml(
        "<routes><entry><destination>10.0.0.0/8</destination></entry></routes>"
    )
    result = CliRunner().invoke(
        cli.app, ["routes", "verify-migration", str(manifest_path)]
    )
    assert result.exit_code == 1
    assert "unrecognized route table" in result.output
    assert "Migration route verification passed" not in result.output
    assert not tuple(tmp_path.glob("LSVPN_POST_MIGRATION_*"))


def test_older_snapshot_and_missing_coverage_cannot_be_verified(
    capture_context: tuple[Mock, Mock],
    tmp_path: Path,
) -> None:
    panorama, firewall = capture_context
    firewall.op.return_value = _xml("<count>0</count>")
    snapshot = rv.capture_route_snapshot(panorama, "branch", "001")
    old = json.loads(snapshot.to_json())
    old["schema_version"] = 1
    old.pop("captured_routing_instances")
    with pytest.raises(
        rv.RouteValidationError, match="does not prove route capture completeness"
    ):
        rv.RouteSnapshot.from_json(json.dumps(old))
    with pytest.raises(rv.RouteValidationError, match="capture evidence"):
        rv.compare_route_snapshots(
            replace(snapshot, captured_routing_instances=()), snapshot
        )
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(old))
    after.write_text(snapshot.to_json())
    result = CliRunner().invoke(cli.app, ["routes", "compare", str(before), str(after)])
    assert result.exit_code == 1
    assert "verify the original baseline manually" in result.output


def test_comparison_requires_same_captured_instance_scope(
    capture_context: tuple[Mock, Mock],
) -> None:
    panorama, firewall = capture_context
    firewall.op.return_value = _xml("<count>0</count>")
    snapshot = rv.capture_route_snapshot(panorama, "branch", "001")
    other = replace(
        snapshot,
        captured_routing_instances=(RoutingInstanceConfig("virtual-router", "other"),),
    )
    with pytest.raises(rv.RouteValidationError, match="routing instances differ"):
        rv.compare_route_snapshots(snapshot, other)


def test_legacy_rejects_unknown_protocol_and_duplicate_fields() -> None:
    for body in (
        "<entry><destination>10.0.0.0/8</destination><flags>A Z</flags></entry>",
        "<entry><destination>10.0.0.0/8</destination>"
        "<destination>192.0.2.0/24</destination><flags>A B</flags></entry>",
    ):
        with pytest.raises(rv.RouteValidationError):
            rv._parse_legacy_routes(_xml(body), "default")


def test_snapshot_rejects_missing_or_inconsistent_capture_evidence(
    capture_context: tuple[Mock, Mock],
) -> None:
    panorama, firewall = capture_context
    firewall.op.return_value = _xml("<count>0</count>")
    snapshot = rv.capture_route_snapshot(panorama, "branch", "001")
    data = json.loads(snapshot.to_json())
    data.pop("captured_routing_instances")
    with pytest.raises(rv.RouteValidationError, match="capture.*evidence"):
        rv.RouteSnapshot.from_json(json.dumps(data))
    data = json.loads(snapshot.to_json())
    data["routes"] = [
        {
            "routing_kind": "virtual-router",
            "routing_instance": "other",
            "vrf": None,
            "prefix": "10.0.0.0/8",
            "protocol": "bgp",
            "paths": [],
        }
    ]
    with pytest.raises(rv.RouteValidationError, match="no capture evidence"):
        rv.RouteSnapshot.from_json(json.dumps(data))


def test_verifier_rejects_legacy_baseline_before_capturing_post_routes(
    capture_context: tuple[Mock, Mock],
    tmp_path: Path,
) -> None:
    panorama, firewall = capture_context
    firewall.op.return_value = _xml("<count>0</count>")
    snapshot = rv.capture_route_snapshot(panorama, "branch", "001")
    legacy = json.loads(snapshot.to_json())
    legacy["schema_version"] = 1
    legacy.pop("captured_routing_instances")
    (tmp_path / "before.json").write_text(json.dumps(legacy))
    endpoint = rv.MigrationEndpointValidation(
        "spoke", "branch", "001", "vsys1", "before.json", {}, (), ()
    )
    manifest = rv.MigrationValidationManifest(1, "today", "saved.xml", (endpoint,))
    path = tmp_path / "manifest.json"
    path.write_text(manifest.to_json())
    firewall.op.reset_mock()
    result = CliRunner().invoke(cli.app, ["routes", "verify-migration", str(path)])
    assert result.exit_code == 1
    assert "verify the original baseline manually" in result.output
    assert "Migration route verification passed" not in result.output
    firewall.op.assert_not_called()


def test_legacy_rejects_route_data_hidden_in_metadata() -> None:
    body = (
        "<flags>flags: A:active<entry><destination>10.0.0.0/8</destination>"
        "</entry></flags>"
    )
    with pytest.raises(rv.RouteValidationError, match="invalid route metadata"):
        rv._parse_legacy_routes(_xml(body), "default")
