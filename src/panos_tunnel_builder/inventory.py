from dataclasses import dataclass
from difflib import get_close_matches
from typing import Any

from panos.device import SystemSettings
from panos.firewall import Firewall
from panos.network import (
    AggregateInterface,
    EthernetInterface,
    LoopbackInterface,
    TunnelInterface,
    VlanInterface,
)
from panos.panorama import Panorama, Template, TemplateStack

INTERFACE_TYPES: tuple[type[Any], ...] = (
    EthernetInterface,
    AggregateInterface,
    VlanInterface,
    LoopbackInterface,
    TunnelInterface,
)


class DiscoveryError(RuntimeError):
    """Raised when Panorama inventory cannot produce an unambiguous selection."""


@dataclass(frozen=True)
class TemplateCandidate:
    name: str
    interface_names: tuple[str, ...]

    @property
    def eligible(self) -> bool:
        return bool(self.interface_names)


@dataclass(frozen=True)
class ManagedFirewall:
    name: str
    serial: str


@dataclass(frozen=True)
class FirewallTemplateInventory:
    firewall_name: str
    serial: str
    stack_name: str
    templates: tuple[TemplateCandidate, ...]

    @property
    def eligible_templates(self) -> tuple[TemplateCandidate, ...]:
        return tuple(template for template in self.templates if template.eligible)


@dataclass(frozen=True)
class SharedTemplateScope:
    """Every managed firewall that inherits a selected template."""

    template_name: str
    firewalls: tuple[FirewallTemplateInventory, ...]


def _as_names(value: str | list[str] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _firewall_hostname(firewall: Firewall) -> str | None:
    settings = firewall.findall(SystemSettings)
    if not settings:
        return None
    hostname = getattr(settings[0], "hostname", None)
    return str(hostname) if hostname else None


def _find_firewall(
    firewalls: list[Firewall],
    firewall_name: str,
) -> tuple[Firewall, str]:
    requested = firewall_name.strip()
    if not requested:
        raise DiscoveryError("Firewall name cannot be empty.")
    if not firewalls:
        raise DiscoveryError("Panorama returned no managed firewalls.")

    wanted = requested.casefold()
    matches: list[tuple[Firewall, str]] = []
    identities: dict[str, str] = {}

    for firewall in firewalls:
        hostname = _firewall_hostname(firewall)
        serial = str(firewall.serial or "")
        if hostname:
            identities[hostname.casefold()] = hostname
        if serial:
            identities[serial.casefold()] = serial
        if (hostname and hostname.casefold() == wanted) or serial.casefold() == wanted:
            matches.append((firewall, hostname or serial))

    if not matches and "." not in wanted:
        matches = [
            (firewall, hostname)
            for firewall in firewalls
            if (hostname := _firewall_hostname(firewall))
            and hostname.partition(".")[0].casefold() == wanted
        ]

    unique_matches: dict[str, tuple[Firewall, str]] = {}
    for firewall, hostname in matches:
        serial = str(firewall.serial or "")
        unique_matches[serial or hostname.casefold()] = (firewall, hostname)
    matches = list(unique_matches.values())

    if not matches:
        suggestions = get_close_matches(wanted, identities, n=3, cutoff=0.6)
        message = f'Firewall "{requested}" is not managed by this Panorama.'
        if suggestions:
            display_names = ", ".join(identities[name] for name in suggestions)
            message = f"{message} Did you mean: {display_names}?"
        raise DiscoveryError(message)
    if len(matches) > 1:
        serials = ", ".join(str(firewall.serial) for firewall, _ in matches)
        raise DiscoveryError(
            f'Firewall name "{requested}" is ambiguous; matching serials: {serials}.'
        )
    return matches[0]


def _find_template_stack(
    stacks: list[TemplateStack],
    serial: str,
) -> TemplateStack:
    matches = [stack for stack in stacks if serial in _as_names(stack.devices)]

    if not matches:
        raise DiscoveryError(
            f'Firewall serial "{serial}" is not assigned to a template stack.'
        )
    if len(matches) > 1:
        names = ", ".join(str(stack.name) for stack in matches)
        raise DiscoveryError(
            f'Firewall serial "{serial}" is assigned to multiple template stacks: '
            f"{names}."
        )
    return matches[0]


def _interface_names(template: Template) -> tuple[str, ...]:
    names: list[str] = []
    for interface_type in INTERFACE_TYPES:
        interfaces = interface_type.refreshall(template, add=False, name_only=True)
        names.extend(str(interface.name) for interface in interfaces)
    return tuple(dict.fromkeys(names))


def discover_firewall_templates(
    panorama: Panorama,
    firewall_name: str,
) -> FirewallTemplateInventory:
    """Discover the firewall's stack and templates containing interfaces."""
    managed_firewall = discover_managed_firewall(panorama, firewall_name)
    serial = managed_firewall.serial

    stacks = TemplateStack.refreshall(panorama, add=False)
    stack = _find_template_stack(stacks, serial)

    candidates: list[TemplateCandidate] = []
    for template_name in _as_names(stack.templates):
        template = Template(template_name)
        template.parent = panorama
        candidates.append(
            TemplateCandidate(
                name=template_name,
                interface_names=_interface_names(template),
            )
        )

    if not candidates:
        raise DiscoveryError(f'Template stack "{stack.name}" contains no templates.')

    return FirewallTemplateInventory(
        firewall_name=managed_firewall.name,
        serial=serial,
        stack_name=str(stack.name),
        templates=tuple(candidates),
    )


def discover_managed_firewall(
    panorama: Panorama,
    firewall_name: str,
) -> ManagedFirewall:
    """Resolve a managed firewall hostname or serial to its canonical identity."""
    firewalls = panorama.refresh_devices(
        expand_vsys=False,
        include_device_groups=False,
        add=False,
    )
    firewall, resolved_name = _find_firewall(firewalls, firewall_name)
    serial = str(firewall.serial or "")
    if not serial:
        raise DiscoveryError(
            f'Firewall "{resolved_name}" does not have a serial number in Panorama.'
        )
    return ManagedFirewall(name=resolved_name, serial=serial)


def discover_shared_template_scope(
    panorama: Panorama,
    template_name: str,
) -> SharedTemplateScope:
    """Return all managed firewalls whose stack includes ``template_name``.

    A template can be reused by more than one stack, so this intentionally scans
    every stack instead of limiting the result to the initially selected stack.
    """
    wanted = template_name.casefold()
    stacks = TemplateStack.refreshall(panorama, add=False)
    matching_stacks = [
        stack
        for stack in stacks
        if any(name.casefold() == wanted for name in _as_names(stack.templates))
    ]
    if not matching_stacks:
        raise DiscoveryError(
            f'Template "{template_name}" is not assigned through any template stack.'
        )

    managed = panorama.refresh_devices(
        expand_vsys=False,
        include_device_groups=False,
        add=False,
    )
    by_serial = {
        str(firewall.serial): (_firewall_hostname(firewall) or str(firewall.serial))
        for firewall in managed
        if firewall.serial
    }
    template_cache: dict[str, TemplateCandidate] = {}
    results: list[FirewallTemplateInventory] = []
    seen_serials: set[str] = set()
    for stack in matching_stacks:
        stack_name = str(stack.name)
        stack_templates = _as_names(stack.templates)
        candidates: list[TemplateCandidate] = []
        for name in stack_templates:
            candidate = template_cache.get(name)
            if candidate is None:
                template = Template(name)
                template.parent = panorama
                candidate = TemplateCandidate(name, _interface_names(template))
                template_cache[name] = candidate
            candidates.append(candidate)
        for serial in _as_names(stack.devices):
            if serial in seen_serials:
                raise DiscoveryError(
                    f'Firewall serial "{serial}" inherits template '
                    f'"{template_name}" through multiple template stacks.'
                )
            hostname = by_serial.get(serial)
            if hostname is None:
                raise DiscoveryError(
                    f'Template stack "{stack_name}" assigns serial "{serial}", '
                    "but Panorama did not return it as a managed firewall."
                )
            seen_serials.add(serial)
            results.append(
                FirewallTemplateInventory(
                    firewall_name=hostname,
                    serial=serial,
                    stack_name=stack_name,
                    templates=tuple(candidates),
                )
            )
    return SharedTemplateScope(
        template_name=template_name,
        firewalls=tuple(
            sorted(
                results, key=lambda item: (item.firewall_name.casefold(), item.serial)
            )
        ),
    )
