"""Normalize the ping-only interface-management profile for migrating spokes."""

import ipaddress
import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import dataclass

from panos.panorama import Panorama

from .inventory import FirewallTemplateInventory
from .lsvpn import LsvpnConfigurationError
from .router_rename import _canonical, _config, _literal, _segment, _walk

PING_ONLY = "ping-only"
_PROFILE_PATH = "./network/profiles/interface-management-profile"
_SERVICES = (
    "ping",
    "telnet",
    "ssh",
    "http",
    "http-ocsp",
    "https",
    "snmp",
    "response-pages",
    "userid-service",
    "userid-syslog-listener-ssl",
    "userid-syslog-listener-udp",
)
_REFERENCE_TAGS = {"interface-management-profile", "management-profile"}


def is_unrestricted_ping_only(profile: ET.Element) -> bool:
    """Recognize only ping, with no source restrictions for either IP family."""
    if (profile.findtext("./ping") or "").strip() != "yes":
        return False
    seen: set[str] = set()
    for field in profile:
        if field.tag in seen:
            return False
        seen.add(field.tag)
        if field.tag in {"permitted-ip", "description"}:
            continue
        if len(field) or (field.text or "").strip() != (
            "yes" if field.tag == "ping" else "no"
        ):
            return False
    permitted = profile.find("./permitted-ip")
    if permitted is None or not len(permitted):
        return permitted is None or not (permitted.text or "").strip()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for node in permitted:
        if node.tag != "entry" or len(node):
            return False
        try:
            networks.append(ipaddress.ip_network(node.get("name", ""), strict=False))
        except ValueError:
            return False
    ipv4 = ipaddress.collapse_addresses(
        [item for item in networks if isinstance(item, ipaddress.IPv4Network)]
    )
    ipv6 = ipaddress.collapse_addresses(
        [item for item in networks if isinstance(item, ipaddress.IPv6Network)]
    )
    return any(item.prefixlen == 0 for item in ipv4) and any(
        item.prefixlen == 0 for item in ipv6
    )


def ping_only_profile() -> ET.Element:
    profile = ET.Element("entry", name=PING_ONLY)
    for service in _SERVICES:
        ET.SubElement(profile, service).text = "yes" if service == "ping" else "no"
    return profile


@dataclass(frozen=True)
class ProfileScopeRename:
    xpath: str
    old_name: str


@dataclass(frozen=True)
class PingOnlyProfilePlan:
    renames: tuple[ProfileScopeRename, ...]
    creations: tuple[str, ...]
    stacks: tuple[str, ...]

    @property
    def source_names(self) -> tuple[str, ...]:
        return tuple(sorted({scope.old_name for scope in self.renames}))


def _device(root: ET.Element) -> tuple[str, ET.Element]:
    devices = root.findall("./devices/entry")
    if len(devices) != 1:
        raise LsvpnConfigurationError(
            "Cannot resolve Panorama profile configuration uniquely."
        )
    return f"/config/devices/{_segment(devices[0])}", devices[0]


def _scopes(root: ET.Element, stack_name: str) -> list[tuple[str, ET.Element]]:
    path, device = _device(root)
    stack = device.find(f"./template-stack/entry[@name={_literal(stack_name)}]")
    if stack is None:
        raise LsvpnConfigurationError(
            f'Cannot find spoke template stack "{stack_name}".'
        )
    scopes: list[tuple[str, ET.Element]] = []
    override = stack.find("./config")
    if override is not None:
        scopes.append((f"{path}/template-stack/{_segment(stack)}/config", override))
    for member in stack.findall("./templates/member"):
        name = (member.text or "").strip()
        template = device.find(f"./template/entry[@name={_literal(name)}]")
        if template is None:
            raise LsvpnConfigurationError(f'Cannot find template "{name}".')
        config = template.find("./config")
        if config is not None:
            scopes.append((f"{path}/template/{_segment(template)}/config", config))
    return scopes


def _profiles(scopes: list[tuple[str, ET.Element]]) -> dict[str, ET.Element]:
    """Resolve profile fields by priority without assuming IP-list union semantics."""
    result: dict[str, ET.Element] = {}
    for _, scope in reversed(scopes):
        for device in scope.findall("./devices/entry"):
            for profile in device.findall(f"{_PROFILE_PATH}/entry"):
                name = profile.get("name", "")
                merged = result.setdefault(name, ET.Element("entry", name=name))
                for field in profile:
                    previous = merged.find(f"./{field.tag}")
                    # An empty higher layer cannot prove that inherited IP
                    # restrictions disappear. Nonempty higher lists take priority;
                    # never infer unrestricted access by unioning multiple layers.
                    if (
                        field.tag == "permitted-ip"
                        and previous is not None
                        and not len(field)
                        and not (field.text or "").strip()
                    ):
                        continue
                    if previous is not None:
                        merged.remove(previous)
                    merged.append(deepcopy(field))
    return result


def _uses(scope: ET.Element, name: str) -> bool:
    return any(
        entry.get("name") == name
        for entry in scope.findall(
            ".//network/profiles/interface-management-profile/entry"
        )
    ) or any(
        node.tag in _REFERENCE_TAGS
        and not len(node)
        and (node.text or "").strip() == name
        for node in scope.iter()
    )


def _exclusive(root: ET.Element, path: str, serials: set[str]) -> None:
    _, device = _device(root)
    for stack in device.findall("./template-stack/entry"):
        device_path = f"/config/devices/{_segment(device)}"
        stack_path = f"{device_path}/template-stack/{_segment(stack)}/config"
        uses = path == stack_path
        for member in stack.findall("./templates/member"):
            template_name = _literal((member.text or "").strip())
            template_path = (
                f"{device_path}/template/entry[@name={template_name}]/config"
            )
            uses |= path == template_path
        if uses:
            outsiders = {
                node.get("name", "") for node in stack.findall("./devices/entry")
            } - serials
            if outsiders:
                raise LsvpnConfigurationError(
                    "Management-profile changes would affect firewalls outside the "
                    "spoke migration scope: "
                    + ", ".join(sorted(outsiders))
                    + ". Isolate their templates before normalizing the profile."
                )


def _relative(path: str) -> str:
    return "." + path.removeprefix("/config")


def _simulate(root: ET.Element, plan: PingOnlyProfilePlan) -> None:
    for rename in plan.renames:
        scope = root.find(_relative(rename.xpath))
        if scope is None:
            raise LsvpnConfigurationError("Management-profile scope disappeared.")
        for parent in scope.findall(".//network/profiles/interface-management-profile"):
            source = next(
                (entry for entry in parent if entry.get("name") == rename.old_name),
                None,
            )
            if source is not None:
                if any(entry.get("name") == PING_ONLY for entry in parent):
                    raise LsvpnConfigurationError(
                        "Cannot merge existing management profiles named ping-only."
                    )
                source.set("name", PING_ONLY)
        for node in scope.iter():
            if (
                node.tag in _REFERENCE_TAGS
                and not len(node)
                and (node.text or "").strip() == rename.old_name
            ):
                node.text = PING_ONLY
    for path in plan.creations:
        # The device entry exists; the profile containers may be new.
        device_path, _ = path.split("/network/profiles/", 1)
        device = root.find(_relative(device_path))
        if device is None:
            raise LsvpnConfigurationError(
                "Management-profile creation template disappeared."
            )
        parent = device
        for tag in ("network", "profiles", "interface-management-profile"):
            existing = parent.find(f"./{tag}")
            parent = existing if existing is not None else ET.SubElement(parent, tag)
        if any(entry.get("name") == PING_ONLY for entry in parent):
            raise LsvpnConfigurationError(
                "The ping-only management-profile name is already in use."
            )
        parent.append(ping_only_profile())


def _verify(root: ET.Element, stacks: tuple[str, ...]) -> None:
    for stack in stacks:
        profile = _profiles(_scopes(root, stack)).get(PING_ONLY)
        if profile is None or not is_unrestricted_ping_only(profile):
            raise LsvpnConfigurationError(
                f'Stack "{stack}" does not resolve an unrestricted ping-only profile.'
            )


def _rename_candidate(
    root: ET.Element,
    scopes: list[tuple[str, ET.Element]],
    stacks: tuple[str, ...],
    old: str,
    selected: set[str],
    spokes: tuple[FirewallTemplateInventory, ...],
    local_configs: dict[str, list[ET.Element]],
    existing: dict[str, ProfileScopeRename],
) -> tuple[ProfileScopeRename, ...]:
    changed = {path for path, scope in scopes if _uses(scope, old)}
    # Follow sharing between selected stacks so inherited definitions and all
    # existing interface references move together without changing permissions.
    while True:
        expanded = set(changed)
        for other in stacks:
            other_scopes = _scopes(root, other)
            if not any(path in changed for path, _ in other_scopes):
                continue
            source = _profiles(other_scopes).get(old)
            if source is None or not is_unrestricted_ping_only(source):
                raise LsvpnConfigurationError(
                    "Shared management-profile inheritance "
                    "has incompatible permissions."
                )
            expanded.update(path for path, scope in other_scopes if _uses(scope, old))
        if expanded == changed:
            break
        changed = expanded
    for path in sorted(changed):
        _exclusive(root, path, selected)
        previous = existing.get(path)
        if previous is not None and previous.old_name != old:
            raise LsvpnConfigurationError("Shared management-profile names conflict.")
    for spoke in spokes:
        paths = {path for path, _ in _scopes(root, spoke.stack_name)}
        if not paths.intersection(changed):
            continue
        if any(
            _uses(device, old)
            for config in local_configs[spoke.serial]
            for device in config.findall("./devices/entry")
        ):
            raise LsvpnConfigurationError(
                f'Firewall "{spoke.serial}" has local references or settings '
                f'for profile "{old}". Move them into Panorama '
                "templates before renaming."
            )
    candidate = tuple(ProfileScopeRename(path, old) for path in sorted(changed))
    expected = deepcopy(root)
    _simulate(expected, PingOnlyProfilePlan(candidate, (), ()))
    affected = tuple(
        stack
        for stack in stacks
        if any(path in changed for path, _ in _scopes(root, stack))
    )
    _verify(expected, affected)
    return candidate


def prepare_ping_only_profiles(
    panorama: Panorama,
    spokes: tuple[FirewallTemplateInventory, ...],
    creation_template: str,
) -> PingOnlyProfilePlan:
    root = _config(panorama, purpose="management-profile normalization")
    selected = {spoke.serial for spoke in spokes}
    stacks = tuple(dict.fromkeys(spoke.stack_name for spoke in spokes))
    local_configs: dict[str, list[ET.Element]] = {spoke.serial: [] for spoke in spokes}
    for spoke in spokes:
        _, device = _device(root)
        stack = device.find(
            f"./template-stack/entry[@name={_literal(spoke.stack_name)}]"
        )
        if stack is None or spoke.serial not in {
            node.get("name") for node in stack.findall("./devices/entry")
        }:
            raise LsvpnConfigurationError(
                "Spoke stack device assignment could not be verified."
            )
        assigned = tuple(
            (member.text or "").strip()
            for member in stack.findall("./templates/member")
        )
        if (
            assigned != tuple(item.name for item in spoke.templates)
            or creation_template not in assigned
        ):
            raise LsvpnConfigurationError(
                "Spoke template assignment changed; rebuild the migration."
            )
        for running in (False, True):
            local = _config(
                panorama,
                spoke.serial,
                running=running,
                purpose="management-profile normalization",
            )
            local_configs[spoke.serial].append(local)
            for profile in local.findall(
                "./devices/entry/network/profiles/interface-management-profile/entry"
            ):
                if profile.get("name") == PING_ONLY and not is_unrestricted_ping_only(
                    profile
                ):
                    raise LsvpnConfigurationError(
                        f'Firewall "{spoke.serial}" has a conflicting '
                        "local ping-only profile."
                    )
    # Check every original stack before simulating any rename or creation. A new
    # higher-priority definition must never mask a conflicting existing target.
    for stack_name in stacks:
        target = _profiles(_scopes(root, stack_name)).get(PING_ONLY)
        if target is not None and not is_unrestricted_ping_only(target):
            raise LsvpnConfigurationError(
                f'Stack "{stack_name}" already has a ping-only '
                "profile with different permissions."
            )
    renames: dict[str, ProfileScopeRename] = {}
    creations: list[str] = []
    for stack_name in stacks:
        scopes = _scopes(root, stack_name)
        profiles = _profiles(scopes)
        target = profiles.get(PING_ONLY)
        if target is not None:
            if not is_unrestricted_ping_only(target):
                raise LsvpnConfigurationError(
                    f'Stack "{stack_name}" already has a ping-only '
                    "profile with different permissions."
                )
            continue
        matches = sorted(
            name
            for name, profile in profiles.items()
            if is_unrestricted_ping_only(profile)
        )
        if not matches:
            path, device = _device(root)
            template = device.find(
                f"./template/entry[@name={_literal(creation_template)}]/config"
            )
            if template is None or len(template.findall("./devices/entry")) != 1:
                raise LsvpnConfigurationError(
                    "Cannot resolve the spoke management-profile creation template."
                )
            config_path = (
                f"{path}/template/entry[@name={_literal(creation_template)}]/config"
            )
            _exclusive(root, config_path, selected)
            owner = template.findall("./devices/entry")[0]
            creation = (
                f"{config_path}/devices/{_segment(owner)}"
                "/network/profiles/interface-management-profile"
            )
            partial = PingOnlyProfilePlan((), (creation,), ())
            _simulate(root, partial)
            creations.append(creation)
            continue
        errors: list[str] = []
        for old in matches:
            try:
                candidate = _rename_candidate(
                    root, scopes, stacks, old, selected, spokes, local_configs, renames
                )
            except LsvpnConfigurationError as exc:
                errors.append(str(exc))
                continue
            _simulate(root, PingOnlyProfilePlan(candidate, (), ()))
            renames.update((item.xpath, item) for item in candidate)
            break
        else:
            raise LsvpnConfigurationError(
                "No matching profile can be renamed safely: " + errors[-1]
            )
    result = PingOnlyProfilePlan(tuple(renames.values()), tuple(creations), stacks)
    _verify(root, stacks)
    return result


def apply_ping_only_profiles(panorama: Panorama, plan: PingOnlyProfilePlan) -> int:
    if not plan.renames and not plan.creations:
        verify_ping_only_profiles(panorama, plan)
        return 0
    before = _config(panorama, purpose="management-profile normalization")
    expected = deepcopy(before)
    _simulate(expected, plan)
    _verify(expected, plan.stacks)
    definitions: list[str] = []
    references: list[str] = []
    for rename in plan.renames:
        scope = before.find(_relative(rename.xpath))
        if scope is None:
            raise LsvpnConfigurationError("Management-profile scope disappeared.")
        parents = set(scope.findall(".//network/profiles/interface-management-profile"))
        for node, path in _walk(scope, rename.xpath):
            if node in parents:
                definitions.extend(
                    f"{path}/{_segment(entry)}"
                    for entry in node
                    if entry.get("name") == rename.old_name
                )
            if (
                node.tag in _REFERENCE_TAGS
                and not len(node)
                and (node.text or "").strip() == rename.old_name
            ):
                references.append(path)
    for path in definitions:
        panorama.xapi.rename(path, PING_ONLY)
    for path in plan.creations:
        panorama.xapi.set(path, ET.tostring(ping_only_profile(), encoding="unicode"))
    after_native = _config(panorama, purpose="management-profile normalization")
    for path in references:
        wanted = expected.find(_relative(path))
        actual = after_native.find(_relative(path))
        if wanted is None or actual is None:
            raise LsvpnConfigurationError("Management-profile reference disappeared.")
        if (actual.text or "").strip() != PING_ONLY:
            panorama.xapi.edit(path, ET.tostring(wanted, encoding="unicode"))
    actual_config = _config(panorama, purpose="management-profile normalization")
    if _canonical(actual_config) != _canonical(expected):
        raise LsvpnConfigurationError(
            "Management-profile verification failed: unexpected candidate changes."
        )
    _verify(actual_config, plan.stacks)
    return len(definitions) + len(plan.creations) + len(references)


def verify_ping_only_profiles(panorama: Panorama, plan: PingOnlyProfilePlan) -> None:
    _verify(_config(panorama, purpose="management-profile verification"), plan.stacks)
