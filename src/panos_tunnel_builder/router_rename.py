"""Plan and verify spoke virtual-router renames inside a migration transaction."""

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass

from panos.panorama import Panorama

from .inventory import FirewallTemplateInventory
from .lsvpn import LsvpnConfigurationError, StandardIpsecClonePlan

_METADATA = {"admin", "dirtyId", "time"}


def validate_router_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9 _-]{1,31}", value) or value != value.strip():
        raise LsvpnConfigurationError(
            "Spoke virtual router name must contain 1 to 31 letters, numbers, "
            "spaces, hyphens, or underscores, without leading or trailing spaces."
        )
    return value


def _literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    return "concat(" + ', "\'", '.join(f"'{part}'" for part in value.split("'")) + ")"


def _segment(node: ET.Element) -> str:
    if "name" in node.attrib:
        return f"{node.tag}[@name={_literal(node.attrib['name'])}]"
    if node.tag == "member":
        return f"member[.={_literal((node.text or '').strip())}]"
    return node.tag


def _walk(root: ET.Element, path: str) -> Iterator[tuple[ET.Element, str]]:
    yield root, path
    for child in root:
        yield from _walk(child, f"{path}/{_segment(child)}")


def _config(
    panorama: Panorama,
    serial: str | None = None,
    *,
    running: bool = False,
) -> ET.Element:
    operation = panorama.xapi.show if running else panorama.xapi.get
    options = {"extra_qs": {"target": serial}} if serial else {}
    response = operation("/config", **options)
    if not isinstance(response, ET.Element) or (
        response.tag == "response" and response.get("status") != "success"
    ):
        raise LsvpnConfigurationError(
            "Cannot verify full candidate configuration for router rename."
        )
    root = response if response.tag == "config" else response.find("./result/config")
    if root is None or not len(root):
        raise LsvpnConfigurationError(
            "Full candidate configuration is required for router rename."
        )
    return deepcopy(root)


def _canonical(root: ET.Element) -> str:
    copied = deepcopy(root)
    for node in copied.iter():
        for attribute in _METADATA:
            node.attrib.pop(attribute, None)
    # Router and import order have no policy-order semantics. Native rename can
    # move these entries; retain ordering everywhere else, including rulebases.
    for parent in copied.findall(".//network/virtual-router"):
        if all(child.tag in {"entry", "member"} for child in parent):
            parent[:] = sorted(
                parent, key=lambda child: (child.get("name", ""), child.text or "")
            )
    return ET.canonicalize(ET.tostring(copied, encoding="unicode"), strip_text=True)


def map_router_references(root: ET.Element, mapping: dict[str, str]) -> None:
    """Map schema-defined scalar references and vsys router-import members."""
    for node in root.iter():
        if node.tag in {"next-vr", "virtual-router"} and not len(node):
            value = (node.text or "").strip()
            if value in mapping:
                node.text = mapping[value]
    for node in root.findall(".//import/network/virtual-router/member"):
        value = (node.text or "").strip()
        if value in mapping:
            node.text = mapping[value]


@dataclass(frozen=True)
class RouterRenameScope:
    xpath: str
    old_name: str


@dataclass(frozen=True)
class SpokeRouterRename:
    new_name: str
    routers_by_serial: tuple[tuple[str, str], ...]
    scopes: tuple[RouterRenameScope, ...]

    def mapping(self, serial: str) -> dict[str, str]:
        return {
            old: self.new_name
            for device, old in self.routers_by_serial
            if device == serial and old != self.new_name
        }


def _scope_changes(root: ET.Element, old: str, new: str) -> bool:
    changed = deepcopy(root)
    _transform(changed, old, new)
    return _canonical(root) != _canonical(changed)


def _transform(root: ET.Element, old: str, new: str) -> None:
    for entry in root.findall(".//network/virtual-router/entry"):
        if entry.get("name") == old:
            entry.set("name", new)
    for container in root.findall(".//import/network/virtual-router"):
        members = {(node.text or "").strip() for node in container.findall("./member")}
        if old in members and new in members and old != new:
            raise LsvpnConfigurationError(
                "Router rename target is already imported into a virtual system."
            )
    map_router_references(root, {old: new})


def prepare_spoke_router_rename(
    panorama: Panorama,
    spokes: tuple[FirewallTemplateInventory, ...],
    plans: tuple[StandardIpsecClonePlan, ...],
    new_name: str,
) -> SpokeRouterRename | None:
    """Resolve all contributing templates and stack overrides before any writes."""
    validate_router_name(new_name)
    names: dict[str, set[str]] = {spoke.serial: set() for spoke in spokes}
    for plan in plans:
        source = plan.spoke_tunnel_source
        if source is None or plan.spoke_identity not in names:
            raise LsvpnConfigurationError(
                "Spoke router rename requires a complete migration scope."
            )
        memberships = source.routing_instances
        if memberships:
            if len(memberships) != 1 or memberships[0].kind != "virtual-router":
                raise LsvpnConfigurationError(
                    "Spoke router rename supports legacy virtual routers only."
                )
            old = memberships[0].name
        elif len(source.virtual_routers) == 1:
            old = source.virtual_routers[0]
        else:
            raise LsvpnConfigurationError(
                "Spoke source interface must belong to one virtual router."
            )
        names[plan.spoke_identity].add(old)
    if any(len(values) != 1 for values in names.values()):
        raise LsvpnConfigurationError(
            "Cannot merge multiple spoke virtual routers into one name."
        )
    by_serial = tuple((serial, next(iter(values))) for serial, values in names.items())
    if all(old == new_name for _, old in by_serial):
        return None

    root = _config(panorama)
    devices = root.findall("./devices/entry")
    if len(devices) != 1:
        raise LsvpnConfigurationError(
            "Cannot resolve Panorama template configuration uniquely."
        )
    device = devices[0]
    device_path = f"/config/devices/{_segment(device)}"
    templates = {node.get("name"): node for node in device.findall("./template/entry")}
    stacks = {
        node.get("name"): node for node in device.findall("./template-stack/entry")
    }
    selected = set(names)
    scopes: dict[str, RouterRenameScope] = {}
    for spoke in spokes:
        old = dict(by_serial)[spoke.serial]
        if old != new_name:
            for running in (False, True):
                local = _config(panorama, spoke.serial, running=running)
                for device_config in local.findall("./devices/entry"):
                    if any(
                        entry.get("name") == new_name
                        for entry in device_config.findall(
                            "./network/virtual-router/entry"
                        )
                    ):
                        raise LsvpnConfigurationError(
                            f'Spoke virtual router "{new_name}" already exists '
                            f'on firewall "{spoke.serial}".'
                        )
                    if _scope_changes(device_config, old, new_name):
                        raise LsvpnConfigurationError(
                            f'Firewall "{spoke.serial}" has local router configuration '
                            "or references that would retain the old router name. "
                            "Move those settings into Panorama templates "
                            "before renaming."
                        )
        stack = stacks.get(spoke.stack_name)
        if stack is None:
            raise LsvpnConfigurationError(
                f'Cannot find spoke template stack "{spoke.stack_name}".'
            )
        if spoke.serial not in {
            node.get("name") for node in stack.findall("./devices/entry")
        }:
            raise LsvpnConfigurationError(
                "Spoke stack device assignment could not be verified."
            )
        assigned = tuple(
            (member.text or "").strip()
            for member in stack.findall("./templates/member")
        )
        if assigned != tuple(template.name for template in spoke.templates):
            raise LsvpnConfigurationError(
                "Spoke template assignment changed; rebuild the migration."
            )
        entries: list[tuple[str, ET.Element]] = []
        for name in assigned:
            template = templates.get(name)
            if template is None:
                raise LsvpnConfigurationError(f'Cannot find spoke template "{name}".')
            entries.append((f"{device_path}/template/{_segment(template)}", template))
        entries.append((f"{device_path}/template-stack/{_segment(stack)}", stack))
        found = False
        for path, entry in entries:
            config = entry.find("./config")
            if config is None:
                continue
            routers = config.findall(".//network/virtual-router/entry")
            found |= any(node.get("name") == old for node in routers)
            if old != new_name and any(
                node.get("name") == new_name for node in routers
            ):
                raise LsvpnConfigurationError(
                    f'Spoke virtual router "{new_name}" already exists in '
                    f'stack "{spoke.stack_name}".'
                )
            if old == new_name or not _scope_changes(config, old, new_name):
                continue
            # Every consumer of a modified template/override must participate.
            consumers = (
                [entry]
                if "/template-stack/" in path
                else [
                    item
                    for item in stacks.values()
                    if entry.get("name")
                    in {
                        (member.text or "").strip()
                        for member in item.findall("./templates/member")
                    }
                ]
            )
            for consumer in consumers:
                outsiders = {
                    node.get("name", "") for node in consumer.findall("./devices/entry")
                } - selected
                if outsiders:
                    raise LsvpnConfigurationError(
                        "Spoke router rename would affect firewalls "
                        "outside the migration scope: "
                        + ", ".join(sorted(outsiders))
                        + ". Isolate their templates before renaming."
                    )
            scope = RouterRenameScope(f"{path}/config", old)
            if scope.xpath in scopes and scopes[scope.xpath] != scope:
                raise LsvpnConfigurationError(
                    "Shared template router names conflict; "
                    "cannot merge routing scopes."
                )
            scopes[scope.xpath] = scope
        if not found:
            raise LsvpnConfigurationError(
                f'Spoke router "{old}" is not owned by its Panorama templates.'
            )
    return SpokeRouterRename(new_name, by_serial, tuple(scopes.values()))


def apply_spoke_router_rename(panorama: Panorama, rename: SpokeRouterRename) -> int:
    """Rename full router objects, repair cross-template references, reread all config.

    The caller owns the migration locks, recovery snapshot, and rollback boundary.
    """
    validate_router_name(rename.new_name)
    before = _config(panorama)
    expected = deepcopy(before)
    definitions: list[tuple[str, str]] = []
    references: list[tuple[str, str, ET.Element]] = []
    for scope in rename.scopes:
        relative = "." + scope.xpath.removeprefix("/config")
        original = before.find(relative)
        destination = expected.find(relative)
        if original is None or destination is None:
            raise LsvpnConfigurationError(
                "Router rename scope disappeared during migration."
            )
        if any(
            node.get("name") == rename.new_name
            for node in original.findall(".//network/virtual-router/entry")
        ):
            raise LsvpnConfigurationError(
                "Router rename target already exists; refusing to merge routers."
            )
        router_sections = set(original.findall(".//network/virtual-router"))
        for node, path in _walk(original, scope.xpath):
            if node in router_sections:
                for entry in node.findall("./entry"):
                    if entry.get("name") == scope.old_name:
                        definitions.append(
                            (f"{path}/{_segment(entry)}", rename.new_name)
                        )
        _transform(destination, scope.old_name, rename.new_name)
        # Keep reference values old while moving definitions to their new paths.
        renamed = deepcopy(original)
        for entry in renamed.findall(".//network/virtual-router/entry"):
            if entry.get("name") == scope.old_name:
                entry.set("name", rename.new_name)
        for node, path in _walk(renamed, scope.xpath):
            if not len(node) and (node.text or "").strip() == scope.old_name:
                if node.tag in {"next-vr", "virtual-router"} or (
                    node.tag == "member" and "/import/network/virtual-router/" in path
                ):
                    new = deepcopy(node)
                    new.text = rename.new_name
                    new_path = path
                    if node.tag == "member":
                        new_path = path.rsplit("/", 1)[0] + "/" + _segment(new)
                    references.append((path, new_path, new))
    if not definitions:
        raise LsvpnConfigurationError(
            "Source virtual router disappeared during migration."
        )
    for path, new_name in definitions:
        panorama.xapi.rename(path, new_name)
    after_native = _config(panorama)
    for old_path, new_path, node in references:
        relative = "." + new_path.removeprefix("/config")
        existing = after_native.find(relative)
        if existing is not None and _canonical(existing) == _canonical(node):
            continue
        old_relative = "." + old_path.removeprefix("/config")
        if after_native.find(old_relative) is None:
            raise LsvpnConfigurationError("Router reference disappeared during rename.")
        panorama.xapi.edit(old_path, ET.tostring(node, encoding="unicode"))
    actual = _config(panorama)
    if _canonical(actual) != _canonical(expected):
        raise LsvpnConfigurationError(
            "Router rename verification failed: candidate configuration differs "
            "from the approved router and reference changes."
        )
    return len(definitions) + len(references)
