# Changelog — tibet-cbom

## 0.2.0 — 2026-05-20

### Security

**Replaces substring-based admin gate with chain-walk discipline.**

The v0.1.x release contained a pre-write authority gate in `rewrap.py`
that used a Python substring check (`".admin" in actor_id`) to
determine whether the calling actor had admin authority. This check
was identified during the RS-2026-001 peer-review engagement as
bypassable: a malicious actor with an identifier such as
`evil.admin.attacker.aint` would satisfy the substring match and the
gate would pass.

Investigation revealed that authority verification belonged in the
chain-walking discipline already operative in `verify.py`, not as a
substring pre-check in `rewrap.py`. v0.2.0 removes the substring gate
entirely and adds a new `transition-authority` check to `verify.py`
that operationalises the cross-reference discipline articulated in
joint paper §6.5 (Richard Barron, Red Specter):

**Three authority categories per transition_type**, each verified
against the TIBET chain rather than against string patterns:

- **Self-issued** (`freeze`, `release`)
  Actor's identity must be consistent across the `parent_action_id`
  link in the audit chain. Inconsistency = authority break, REJECTED.

- **Delegated** (`handoff`, `takeover`, `supersede`)
  `parent_action_id` must resolve to an action by a different actor
  (= the delegating authority, or the sender in handoff case). Cross-
  chain reference satisfied per §6.5. Self-delegation = REJECTED.

- **Chain-anchored** (`reclaim`)
  Prior ownership token must exist in audit context for this actor.
  Absence of prior ownership = REJECTED.

Unknown transition types are REJECTED rather than silently accepted.

### Note on handoff semantics

Handoff is **delegated**, not self-issued. A handoff is structurally
a bilateral consent-bound transfer: sender's chain emits a Transfer-Out
Anchor (release event with receiver_aint declared), receiver's chain
emits a Transfer-In Anchor (accept-event referencing sender's release).
The two chains converge via cross-reference, not via shared sequencer.

This is consistent with:

- **TAT Rule 1** (Bilateral Consent, `draft-vandemeent-tibet-tat-00`):
  *"Transfer MUST be consent-bound, anchored, and sealed."*
- **IDDrop offer-first / request-first modes**
  (`draft-vandemeent-iddrop-00`): both modes require explicit
  receiver-side acceptance act.
- **CEP decision-plane separation**
  (`draft-vandemeent-continuity-envelope-00`): handoff is a transfer
  event with cross-reference, distinct from a decision-plane `fork`
  outcome.

The `verify.py` "delegated" branch enforces the cross-chain reference
requirement: `parent_actor != actor`. Self-handoff (sender == receiver)
is structurally rejected. Identified by Richard Barron during
RS-2026-001 review (21 May 2026); fixed before v0.2.0 PyPI publish.

### Bypass-attack testing

The new `tests/test_authority.py` suite includes proof-of-rejection
cases for both v0.1.x bypass patterns:

1. Malicious actor with `.admin` substring in identifier, no
   legitimate audit history — REJECTED (parent_not_resolved).
2. Malicious actor with `.admin` substring, audit contains only
   self-actions — REJECTED (self-delegation).

Plus legitimate-case pass tests for all three authority categories,
plus delegated-handoff acceptance + self-loop rejection.
Total: 9/9 tests passing.

### API changes

- `rewrap.build_rewrap_prerequisite_set()`: the `admin actor id`
  Prerequisite check is removed. The `authority_mode` parameter is
  preserved for backward compatibility but no longer triggers a
  substring check.

- `rewrap.validate_transition_inputs()`: the substring-based
  authority-mode validation is removed. Other validations (handoff
  target, freeze reason, status compatibility) unchanged.

- `verify.build_verify_report()`: returns an additional check named
  `transition-authority` in the `checks` list when an ownership
  transition is present.

### Future work

- Ed25519 signature verification against AINS-registered pubkey is
  planned for v0.3.0 once the transition payload format carries
  signature bytes alongside the existing fields.

- Chain-anchored verification currently checks for prior-actor
  presence in audit context; full backward walk through merged
  chains is scheduled for v0.3.0.

### Acknowledgements

Authority gap originally identified in RS-2026-001 peer-review
engagement (Red Specter Security Research, Richard Barron). The
v0.2.0 architectural reframing is documented in joint paper §6.5
(JIS-causality-flex extending) and §8.3 (AARM ownership-transition
primitive).

---

## 0.1.2 — 2026-05-15

- SAM-receipt integration
- Audit walker fix
- Verify command improvements

## 0.1.1 — initial release

- CBOM document model + State of Manifest emission
- Six ownership-transition event types (freeze / takeover / handoff /
  supersede / reclaim / release)
- Inspect, sniff, audit, manifest, verify, rewrap, render modules
