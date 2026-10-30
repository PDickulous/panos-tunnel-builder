import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import replace
from unittest.mock import Mock

import pytest
from panos.panorama import Panorama

from panos_tunnel_builder import management_profiles as profiles
from panos_tunnel_builder.inventory import FirewallTemplateInventory, TemplateCandidate
from panos_tunnel_builder.lsvpn import LsvpnConfigurationError


def _required(root: ET.Element, path: str) -> ET.Element:
    result = root.find(path)
    assert result is not None, path
    return result


def _inventory() -> FirewallTemplateInventory:
    return FirewallTemplateInventory(
        "branch",
        "001",
        "branches",
        (TemplateCandidate("branch", ("tunnel.2",)), TemplateCandidate("base", ())),
    )


def _config(profile: str = "") -> ET.Element:
    return ET.fromstring(
        """<config><devices><entry name="localhost.localdomain">
      <template>
        <entry name="base"><config><devices><entry name="localhost.localdomain">
          <network><profiles><interface-management-profile>"""
        + profile
        + """
          </interface-management-profile></profiles></network>
        </entry></devices></config></entry>
        <entry name="branch"><config><devices><entry name="localhost.localdomain">
          <network><interface><tunnel><units><entry name="tunnel.2">
            <interface-management-profile>Old Ping</interface-management-profile>
          </entry></units></tunnel><ethernet><entry name="ethernet1/1"><layer3>
            <interface-management-profile>Old Ping</interface-management-profile>
          </layer3></entry></ethernet></interface></network>
        </entry></devices></config></entry>
        <entry name="hub"><config><devices><entry name="localhost.localdomain">
          <network><profiles><interface-management-profile>
            <entry name="Old Ping"><ping>yes</ping></entry>
          </interface-management-profile></profiles><interface><tunnel><units>
            <entry name="tunnel.10">
              <interface-management-profile>Old Ping</interface-management-profile>
            </entry>
          </units></tunnel></interface></network>
        </entry></devices></config></entry>
      </template>
      <template-stack>
        <entry name="branches"><templates><member>branch</member><member>base</member>
          </templates><devices><entry name="001"/></devices></entry>
        <entry name="hubs"><templates><member>hub</member></templates>
          <devices><entry name="999"/></devices></entry>
      </template-stack>
    </entry></devices></config>"""
    )


class MemoryConfig:
    def __init__(self, root: ET.Element, native_references: bool = False):
        self.root = root
        self.native_references = native_references
        self.local_candidate = ET.fromstring(
            "<config><devices><entry><network/></entry></devices></config>"
        )
        self.local_running = deepcopy(self.local_candidate)
        self.panorama = Panorama("panorama.test", api_key="dummy")
        self.xapi = Mock()
        self.panorama._xapi_private = self.xapi
        self.xapi.get.side_effect = self.get
        self.xapi.show.side_effect = self.show
        self.xapi.rename.side_effect = self.rename
        self.xapi.set.side_effect = self.set
        self.xapi.edit.side_effect = self.edit

    def response(self, root: ET.Element) -> ET.Element:
        response = ET.Element("response", status="success")
        ET.SubElement(response, "result").append(deepcopy(root))
        return response

    def get(self, path: str, **kwargs: object) -> ET.Element:
        assert path == "/config"
        return self.response(self.local_candidate if kwargs else self.root)

    def show(self, path: str, **kwargs: object) -> ET.Element:
        assert path == "/config"
        assert kwargs == {"extra_qs": {"target": "001"}} or kwargs == {
            "extra_qs": {"target": "002"}
        }
        return self.response(self.local_running)

    def find(self, path: str) -> ET.Element:
        return _required(self.root, "." + path.removeprefix("/config"))

    def rename(self, path: str, name: str) -> None:
        node = self.find(path)
        old_name = node.get("name")
        node.set("name", name)
        if self.native_references:
            owner = next(
                entry
                for entry in self.root.findall(".//template/entry")
                if node in entry.iter()
            )
            for reference in owner.iter("interface-management-profile"):
                if not len(reference) and reference.text == old_name:
                    reference.text = name

    def set(self, path: str, xml: str) -> None:
        device_path, _ = path.split("/network/profiles/", 1)
        parent = self.find(device_path)
        for tag in ("network", "profiles", "interface-management-profile"):
            existing = parent.find(f"./{tag}")
            parent = ET.SubElement(parent, tag) if existing is None else existing
        parent.append(ET.fromstring(xml))

    def edit(self, path: str, xml: str) -> None:
        node = self.find(path)
        new = ET.fromstring(xml)
        node.text = new.text
        node[:] = list(new)


def _prepare(memory: MemoryConfig) -> profiles.PingOnlyProfilePlan:
    return profiles.prepare_ping_only_profiles(
        memory.panorama, (_inventory(),), "branch"
    )


@pytest.mark.parametrize(
    "fields,expected",
    [
        ("<ping>yes</ping>", True),
        ("<ping>yes</ping><ssh>no</ssh><https>no</https>", True),
        ("<ping>yes</ping><permitted-ip/>", True),
        ("<ping>yes</ping><ssh>yes</ssh>", False),
        ("<ping>yes</ping><http-ocsp>yes</http-ocsp>", False),
        ("<ping>yes</ping><response-pages>yes</response-pages>", False),
        ("<ping>yes</ping><userid-service>yes</userid-service>", False),
        ("<ping>yes</ping><future-service>yes</future-service>", False),
        ("<ping>no</ping>", False),
        ("<ssh>no</ssh>", False),
        (
            '<ping>yes</ping><permitted-ip><entry name="10.0.0.0/8"/></permitted-ip>',
            False,
        ),
        (
            '<ping>yes</ping><permitted-ip><entry name="0.0.0.0/0"/></permitted-ip>',
            False,
        ),
        (
            '<ping>yes</ping><permitted-ip><entry name="0.0.0.0/0"/>'
            '<entry name="::/0"/></permitted-ip>',
            True,
        ),
        (
            '<ping>yes</ping><permitted-ip><entry name="0.0.0.0/1"/>'
            '<entry name="128.0.0.0/1"/><entry name="::/0"/></permitted-ip>',
            True,
        ),
        ('<ping>yes</ping><permitted-ip><entry name="invalid"/></permitted-ip>', False),
    ],
)
def test_recognizes_only_unrestricted_ping(fields: str, expected: bool) -> None:
    assert (
        profiles.is_unrestricted_ping_only(
            ET.fromstring(f'<entry name="test">{fields}</entry>')
        )
        is expected
    )


def test_created_profile_explicitly_disables_all_other_services() -> None:
    profile = profiles.ping_only_profile()
    assert profile.get("name") == "ping-only"
    assert profiles.is_unrestricted_ping_only(profile)
    assert profile.find("./permitted-ip") is None
    assert {node.tag for node in profile if node.text == "yes"} == {"ping"}
    assert all(node.text == "no" for node in profile if node.tag != "ping")


@pytest.mark.parametrize("native_references", [False, True])
def test_renames_existing_profile_and_preserves_hub_and_other_profile_permissions(
    native_references: bool,
) -> None:
    root = _config(
        '<entry name="Old Ping"><ping>yes</ping></entry>'
        '<entry name="Admin"><ping>yes</ping><ssh>yes</ssh></entry>'
    )
    hub = ET.tostring(_required(root, ".//template/entry[@name='hub']"))
    memory = MemoryConfig(root, native_references)
    plan = _prepare(memory)
    assert plan.source_names == ("Old Ping",)
    assert not plan.creations
    assert not memory.xapi.rename.called  # Planning is read-only.
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert memory.xapi.rename.call_count == 1
    assert not memory.xapi.set.called
    assert (
        _required(
            root,
            ".//template/entry[@name='base']//interface-management-profile/entry[@name='ping-only']/ping",
        ).text
        == "yes"
    )
    for reference in root.findall(
        ".//template/entry[@name='branch']//interface-management-profile"
    ):
        assert reference.text == "ping-only"
    assert (
        _required(
            root, ".//template/entry[@name='base']//entry[@name='Admin']/ssh"
        ).text
        == "yes"
    )
    assert ET.tostring(_required(root, ".//template/entry[@name='hub']")) == hub
    assert not memory.xapi.commit.called


def test_creates_profile_when_only_restricted_or_extra_service_profiles_exist() -> None:
    memory = MemoryConfig(
        _config('<entry name="Admin"><ping>yes</ping><ssh>yes</ssh></entry>')
    )
    plan = _prepare(memory)
    assert not plan.renames and len(plan.creations) == 1
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert not memory.xapi.rename.called
    assert memory.xapi.set.call_count == 1
    profile = _required(
        memory.root,
        ".//template/entry[@name='branch']//profiles/interface-management-profile/entry[@name='ping-only']",
    )
    assert profiles.is_unrestricted_ping_only(profile)
    # Existing interface assignments are preserved when creating a new profile.
    assert (
        _required(
            memory.root,
            ".//template/entry[@name='branch']//units/entry/interface-management-profile",
        ).text
        == "Old Ping"
    )


def test_reuses_existing_canonical_profile_without_changing_permissions() -> None:
    memory = MemoryConfig(_config('<entry name="ping-only"><ping>yes</ping></entry>'))
    plan = _prepare(memory)
    assert not plan.renames and not plan.creations
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert (
        not memory.xapi.rename.called
        and not memory.xapi.set.called
        and not memory.xapi.edit.called
    )


@pytest.mark.parametrize(
    "fields",
    [
        "<ping>yes</ping><ssh>yes</ssh>",
        '<ping>yes</ping><permitted-ip><entry name="10.0.0.0/8"/></permitted-ip>',
    ],
)
def test_conflicting_canonical_name_blocks_before_writes(fields: str) -> None:
    memory = MemoryConfig(
        _config(
            f'<entry name="ping-only">{fields}</entry>'
            '<entry name="Old Ping"><ping>yes</ping></entry>'
        )
    )
    with pytest.raises(LsvpnConfigurationError, match="different permissions"):
        _prepare(memory)
    assert not memory.xapi.rename.called and not memory.xapi.set.called


def test_profile_inheritance_observes_stack_priority() -> None:
    root = _config('<entry name="Old Ping"><ping>yes</ping><ssh>yes</ssh></entry>')
    device = _required(root, ".//template/entry[@name='branch']/config/devices/entry")
    network = _required(device, "./network")
    definitions = ET.SubElement(
        ET.SubElement(network, "profiles"), "interface-management-profile"
    )
    definitions.append(ET.fromstring('<entry name="Old Ping"><ssh>no</ssh></entry>'))
    memory = MemoryConfig(root)
    plan = _prepare(memory)
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert memory.xapi.rename.call_count == 2
    profiles.verify_ping_only_profiles(memory.panorama, plan)


@pytest.mark.parametrize("outsider", ["002", "999"])
def test_shared_template_outside_spoke_group_blocks_rename(outsider: str) -> None:
    root = _config('<entry name="Old Ping"><ping>yes</ping></entry>')
    if outsider == "002":
        ET.SubElement(
            _required(root, ".//template-stack/entry[@name='branches']/devices"),
            "entry",
            name=outsider,
        )
    else:
        ET.SubElement(
            _required(root, ".//template-stack/entry[@name='hubs']/templates"), "member"
        ).text = "base"
    memory = MemoryConfig(root)
    with pytest.raises(
        LsvpnConfigurationError, match="outside the spoke migration scope"
    ):
        _prepare(memory)
    assert not memory.xapi.rename.called


def test_shared_spokes_rename_profile_once_and_update_all_references() -> None:
    root = _config('<entry name="Old Ping"><ping>yes</ping></entry>')
    ET.SubElement(
        _required(root, ".//template-stack/entry[@name='branches']/devices"),
        "entry",
        name="002",
    )
    memory = MemoryConfig(root)
    plan = profiles.prepare_ping_only_profiles(
        memory.panorama, (_inventory(), replace(_inventory(), serial="002")), "branch"
    )
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert memory.xapi.rename.call_count == 1


@pytest.mark.parametrize("running", [False, True])
def test_local_old_profile_reference_blocks_rename(running: bool) -> None:
    memory = MemoryConfig(_config('<entry name="Old Ping"><ping>yes</ping></entry>'))
    local = memory.local_running if running else memory.local_candidate
    interface = ET.SubElement(_required(local, "./devices/entry/network"), "interface")
    ET.SubElement(interface, "interface-management-profile").text = "Old Ping"
    with pytest.raises(LsvpnConfigurationError, match="local references or settings"):
        _prepare(memory)
    assert not memory.xapi.rename.called


def test_unexpected_candidate_drift_fails_profile_verification() -> None:
    memory = MemoryConfig(_config())
    plan = _prepare(memory)
    original_set = memory.xapi.set.side_effect

    def set_profile(path: str, xml: str) -> None:
        original_set(path, xml)
        _required(memory.root, ".//template/entry[@name='hub']").set(
            "unexpected", "change"
        )

    memory.xapi.set.side_effect = set_profile
    with pytest.raises(LsvpnConfigurationError, match="unexpected candidate changes"):
        profiles.apply_ping_only_profiles(memory.panorama, plan)


def test_prefers_a_safe_matching_profile_when_another_match_is_shared_with_hub() -> (
    None
):
    root = _config('<entry name="A-Shared"><ping>yes</ping></entry>')
    ET.SubElement(
        _required(root, ".//template-stack/entry[@name='hubs']/templates"), "member"
    ).text = "base"
    network = _required(
        root, ".//template/entry[@name='branch']/config/devices/entry/network"
    )
    definitions = ET.SubElement(
        ET.SubElement(network, "profiles"), "interface-management-profile"
    )
    definitions.append(
        ET.fromstring('<entry name="B-Isolated"><ping>yes</ping></entry>')
    )
    memory = MemoryConfig(root)
    plan = _prepare(memory)
    assert plan.source_names == ("B-Isolated",)
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert (
        _required(
            root, ".//template/entry[@name='base']//entry[@name='A-Shared']/ping"
        ).text
        == "yes"
    )


def test_stack_override_cannot_hide_restricted_canonical_permissions() -> None:
    root = _config('<entry name="ping-only"><ping>yes</ping></entry>')
    stack = _required(root, ".//template-stack/entry[@name='branches']")
    override = ET.SubElement(stack, "config")
    device = ET.SubElement(
        ET.SubElement(override, "devices"), "entry", name="localhost.localdomain"
    )
    definitions = ET.SubElement(
        ET.SubElement(ET.SubElement(device, "network"), "profiles"),
        "interface-management-profile",
    )
    definitions.append(
        ET.fromstring('<entry name="ping-only"><https>yes</https></entry>')
    )
    memory = MemoryConfig(root)
    with pytest.raises(LsvpnConfigurationError, match="different permissions"):
        _prepare(memory)
    assert not memory.xapi.rename.called and not memory.xapi.set.called


def test_native_same_template_reference_updates_need_no_extra_edits() -> None:
    root = _config()
    network = _required(
        root, ".//template/entry[@name='branch']/config/devices/entry/network"
    )
    definitions = ET.SubElement(
        ET.SubElement(network, "profiles"), "interface-management-profile"
    )
    definitions.append(ET.fromstring('<entry name="Old Ping"><ping>yes</ping></entry>'))
    memory = MemoryConfig(root, native_references=True)
    plan = _prepare(memory)
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert memory.xapi.rename.call_count == 1
    assert not memory.xapi.edit.called


@pytest.mark.parametrize("running", [False, True])
def test_conflicting_local_canonical_profile_blocks_creation(running: bool) -> None:
    memory = MemoryConfig(_config())
    local = memory.local_running if running else memory.local_candidate
    network = _required(local, "./devices/entry/network")
    definitions = ET.SubElement(
        ET.SubElement(network, "profiles"), "interface-management-profile"
    )
    definitions.append(
        ET.fromstring('<entry name="ping-only"><ping>yes</ping><ssh>yes</ssh></entry>')
    )
    with pytest.raises(LsvpnConfigurationError, match="conflicting local ping-only"):
        _prepare(memory)
    assert not memory.xapi.set.called


def test_normalization_keeps_stack_override_profile_fragments_together() -> None:
    root = _config('<entry name="Old Ping"><ping>yes</ping><ssh>yes</ssh></entry>')
    stack = _required(root, ".//template-stack/entry[@name='branches']")
    config = ET.SubElement(stack, "config")
    device = ET.SubElement(
        ET.SubElement(config, "devices"), "entry", name="localhost.localdomain"
    )
    definitions = ET.SubElement(
        ET.SubElement(ET.SubElement(device, "network"), "profiles"),
        "interface-management-profile",
    )
    definitions.append(ET.fromstring('<entry name="Old Ping"><ssh>no</ssh></entry>'))
    memory = MemoryConfig(root)
    plan = _prepare(memory)
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert memory.xapi.rename.call_count == 2
    profiles.verify_ping_only_profiles(memory.panorama, plan)


def test_upper_source_restriction_cannot_be_masked_by_lower_allow_all_list() -> None:
    root = _config(
        '<entry name="Old Ping"><ping>yes</ping><permitted-ip>'
        '<entry name="0.0.0.0/0"/><entry name="::/0"/></permitted-ip></entry>'
    )
    network = _required(
        root, ".//template/entry[@name='branch']/config/devices/entry/network"
    )
    definitions = ET.SubElement(
        ET.SubElement(network, "profiles"), "interface-management-profile"
    )
    definitions.append(
        ET.fromstring(
            '<entry name="Old Ping"><permitted-ip>'
            '<entry name="10.0.0.0/8"/></permitted-ip></entry>'
        )
    )
    memory = MemoryConfig(root)
    plan = _prepare(memory)
    assert not plan.renames and len(plan.creations) == 1
    profiles.apply_ping_only_profiles(memory.panorama, plan)
    assert not memory.xapi.rename.called
