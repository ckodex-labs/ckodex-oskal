# OSCAL projection inputs and evidence limits

The projector emits OSCAL 1.2.3 JSON from supplied domain facts and explicit
`ProjectionContext`. It validates the resulting document against the embedded
schemas before returning bytes. It does not authenticate input facts, fetch
imports, verify evidence content, resolve a profile, or establish compliance.

`NewProjector()` remains source compatible, but has no document relationships or
system facts. Methods that need these inputs return `ProjectionInputError` with
the missing field and no document bytes. Supply facts through
`NewProjectorWithContext(ProjectionContext)`. The public SDK exposes the same
constructor and context types. Context JSON uses these fields:

| Field | Meaning |
| --- | --- |
| `assessment_plan_href` | Actual assessment-plan reference used by assessment results |
| `system_security_plan_href` | Actual SSP reference used by assessment plans |
| `control_source` | Actual catalog or profile reference used by component implementations |
| `control_namespace`, `control_version` | Exact source control identity; every selected control must match |
| `component.type`, `component.description`, `component.purpose` | Caller-supplied component facts; purpose is optional |
| `component.implementations` | Actual implementation narratives keyed by canonical control reference |
| `system.profile_href` | Actual profile reference for the SSP |
| `system.characteristics` | OSCAL `system-characteristics`, including actual information types, status, and authorization boundary |
| `system.implementation` | OSCAL `system-implementation`, including actual components and their status |
| `system.control_implementation_description`, `system.implementations` | SSP implementation description and actual per-control narratives |
| `finding_targets` | Explicit canonical-control to `{type,target_id}` mapping for an actual objective or statement |

A canonical key includes the namespace and, when present, version, for example
`nist-sp-800-53:AC-6@rev5`. It is not a catalog URL. No framework, catalog URL,
profile, objective ID, operational status, information type, or authorization
boundary is inferred from a control ID or system name. Imports must reference
external documents; this API does not supply back-matter for import fragments.

Assessment results select the exact evaluated controls, preserve each evaluation's
subject, epoch digest, assurance state, evidence references, and timestamps, and
use the latest `evaluatedAt` as the result end. `validUntil` is observation expiry,
not future execution. `UNKNOWN` remains a namespaced assurance-state property;
it never becomes an OSCAL satisfied or not-satisfied determination. No observation
or control is created when evaluations are absent. Findings need an explicit
objective/statement target and evidence shared with an evaluation of the exact
same subject and control; substring matches and unrelated-observation fallbacks
are rejected. Projection does not independently verify that evidence.

Component definitions require actual component facts. With no evaluations they
omit optional control implementations. When evaluations are supplied, actual
catalog references and implementation narratives are mandatory. An evaluation
alone does not establish how a control was implemented.

An SSP requires actual system facts and at least one control implementation.
Unknown operational status can be represented using OSCAL `other` with explanatory
`remarks`. Unknown authorization boundaries or information types have no substitute
in this API: supply the facts or projection fails. Assurance state is independent
of operational status. No default AC-6 requirement is emitted.

Assessment plans select only supplied controls. Empty contracts do not create
admission tasks. The subject URI is retained as a namespaced property; it does not
select all components in an imported SSP. Supplied tasks describe plans, not
completed verification.

POA&M projection treats its finding inputs as caller-selected remediation items.
The caller owns triage and approval; projection does not claim these occurred.
With no findings, projection returns an error. It does not manufacture a conformance
item or claim zero open risks means all controls are satisfied.

## Schema contract and verification boundary

The pinned 1.2.3 JSON schemas and current NIST 1.2.3 references require:

- An assessment result has a nonempty control selection. `include-controls` needs
  at least one control; `include-all` has different, broader semantics.
- SSP `system-characteristics` requires system information, status, and an
  authorization boundary. System and component status accept `other`; system
  status requires explanatory remarks for that value.
- SSP `control-implementation.implemented-requirements` and POA&M `poam-items`
  each require at least one item.
- Finding targets refer to an objective or statement. Their status is `satisfied`
  or `not-satisfied`; there is no `not-assessed` state to use for `UNKNOWN`.
- Component control implementations and assessment-plan tasks are optional and
  can be omitted rather than fabricated.

Primary references: [NIST SSP](https://pages.nist.gov/OSCAL-Reference/models/v1.2.3/system-security-plan/json-reference/),
[NIST assessment results](https://pages.nist.gov/OSCAL-Reference/models/v1.2.3/assessment-results/json-reference/),
[NIST component definition](https://pages.nist.gov/OSCAL-Reference/models/v1.2.3/component-definition/json-reference/),
[NIST assessment plan](https://pages.nist.gov/OSCAL-Reference/models/v1.2.3/assessment-plan/json-reference/),
and [NIST POA&M](https://pages.nist.gov/OSCAL-Reference/models/v1.2.3/plan-of-action-and-milestones/json-reference/).

Schema validity proves structural compatibility with those pinned schemas. It
proves neither complete Metaschema constraint conformance nor semantic completeness,
import resolution, verified provenance, operational readiness, or compliance.
The tests use explicit domain examples and real embedded schema validation; their
example system facts are not runtime or production evidence.
