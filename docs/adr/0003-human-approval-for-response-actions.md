# ADR-0003: Mandatory Human Approval for Destructive Response Actions

**Status:** Accepted  
**Date:** 2026-10-06  

## Context

Security automation platforms often propose automated containment actions (e.g., isolating a host, terminating network interfaces, blocking domain traffic, or revoking privileged accounts). However, unverified autonomous execution risks causing severe business disruption, operational downtime, or accidental Denial-of-Service if false positives occur on critical enterprise infrastructure (such as Domain Controllers or production databases).

SOC operational trust requires that containment actions are transparent, explainable, and guarded by explicit authorization protocols.

## Decision

All destructive response actions must be explicitly proposed in PostgreSQL (`response_actions` with `status = 'proposed'`) and require an authorized human analyst approval in `action_approvals` before execution:
1. No destructive containment action may ever be executed automatically by any service or model without recorded approval.
2. In Milestone 1, the `response-agent` is implemented strictly as a non-executing service scaffold stub.
3. Every proposed, approved, executed, or rejected action is permanently recorded in PostgreSQL with an append-only audit trail.

## Consequences

### Positive
- Prevents catastrophic self-inflicted outages on mission-critical assets.
- Provides complete forensic accountability and auditability for compliance.
- Builds analyst trust in the platform's reasoning before introducing automated containment in later milestones.

### Negative
- Response latency is bounded by analyst review availability rather than pure machine speed.
- Analysts must triage and act upon containment queues during active intrusions.
