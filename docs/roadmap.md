# Scope and roadmap

[Documentation index](../README.md#documentation)

## Current scope

Version 0.1.0 targets migration of existing LSVPN deployments to standard IPsec
through Panorama. It supports shared spoke templates, legacy virtual routers,
logical-router VRFs, IPv4/IPv6 BGP, and IPv4 OSPFv2. Existing router names are
preserved. See [architecture](architecture.md) for supported routing topologies.

## Operator responsibilities

Panorama commits, commit-all operations, template-stack pushes, security policy
review, and post-commit firewall rollback remain operator-controlled. The tool
also leaves the timing of routing-convergence checks and application traffic
testing to the operator. These are boundaries of this version, not promises of
future automation.

## Not implemented

- Greenfield VPN creation when no LSVPN deployment exists. The proposed workflow
  would discover external/untrust/internet-zone interfaces and build redundant
  hub-and-spoke tunnels when multiple eligible interfaces exist.
- OSPFv3 cloning.
- Automatic commit validation or post-commit firewall rollback.
- Generating or reviewing security policy rules for the new VPN zones.
- Automatic gateway selection when neither runtime state nor serial criteria
  identifies a unique portal gateway.
- Waiting for dynamic-routing convergence before post-change verification.

These items are not scheduled release commitments. Ambiguous gateway selection
currently stops the workflow; absence of LSVPN does not trigger greenfield creation.

## Remaining validation

Latest destination-based tunnel naming has automated fixture coverage but has
not been exercised against live Panorama in the recorded September 30 review.
A lab candidate-load check and operator-controlled post-commit verification
remain before production use. Historical lab results and their limits are in
[validation records](validation.md#verification-records).
