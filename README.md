# RADAR TRACE

**Threat Reachability and Attack-path Context Enrichment**

RADAR TRACE turns flat CVE records into versioned, evidence-backed attack-path
profiles. It describes *how* vulnerable code is reached: the affected scope's
role, who initiates the relevant interaction, what triggers vulnerable behavior,
what the attacker controls, and which generic path capabilities are required.

The pipeline exists because CVSS `AV:N` means an exploit can traverse a network;
it does not prove an attacker can open an inbound connection to the vulnerable
component. RADAR TRACE preserves CVSS while adding the semantics analysts need
to reason about reachability.

RADAR TRACE produces generic CVE intelligence. It deliberately does **not**
declare a vulnerability reachable in a particular deployment. Its published
profiles can enrich any tool used to improve analyst triage workflows. A
consumer can combine a profile with configuration, network paths, and runtime
evidence to make an environment-specific decision.

This repository is the open, docs-and-data subset of RADAR TRACE: the
methodology, the JSON Schema contracts, and a point-in-time snapshot of the
published dataset. It does not include the pipeline implementation or
infrastructure.

## Current public snapshot

The current `data/` snapshot is intentionally limited to the 2,000-CVE 2026
backfill rerun produced under the v2 contract. It is not the complete private
registry.

## Architecture

![RADAR TRACE architecture](docs/architecture.svg)

The rendered diagram is generated from the editable
[draw.io source](docs/architecture.drawio).

The validation gate never guesses at model output. Invalid, oversized, truncated,
or unsupported output is quarantined; only structurally valid, evidence-linked
profiles reach publication. A semantic repair pass receives exact validator
errors. If that pass is token-truncated, one final source-only recovery request
runs without copying the prior candidate. Every substantive stage writes a
manifest and artifact fingerprint so a result can be traced to its inputs, model
request, and pipeline version.

Before constructing a Gemini request, the pipeline computes an `analysisKey`
from the CVE ID, evidence fingerprint, schema version, analyzer version, prompt
digest, and configured model. A registry lookup removes matching published
analyses from the pending cohort. Overlapping scans and scheduled cohorts
therefore do not incur repeat inference cost unless their evidence or analysis
contract changes, or the caller forces a re-run.

## Attack-path profile

Each profile contains a compact set of materially distinct paths rather than an
entire exploit graph. The portable
[attack-path profile JSON Schema](schemas/attack-path-profile-v2.schema.json)
is the current canonical `attack-path-profile/v2` contract. Version 1 remains
immutable and readable for historical records. Every discrete taxonomy value
has a title and definition in the schema; source IDs, locators, package
identities, version statements, and protocol versions remain extensible.

The v2 contract makes ownership explicit for attacker access, direct outcomes,
mitigation assessment, and narrative-only conditions while preserving the
inbound-versus-outbound path semantics. The published v2 envelope is defined by
[`published-attack-path-profile-v2.schema.json`](schemas/published-attack-path-profile-v2.schema.json).

An `attackPaths` entry describes one affected scope and one immediate vulnerable
boundary. Entries are alternatives. Within an entry, `attackerRequirements`,
`requiredPathCapabilities`, and `preconditions` are three CAPEC-compatible
prerequisite families and form an AND-set: every listed item is necessary.
`protocols` is a descriptive set; a strict
protocol requirement belongs in a typed precondition. Deployment
labels such as `internet-facing` or `cluster-internal` are intentionally absent;
they describe where software is deployed, not the generic CVE path. A consumer
resolves `remote-initiated-ingress`, for example, against its own routes, policy,
and runtime evidence.

The three prerequisite families align conceptually with CAPEC attack
prerequisites while retaining typed fields that a workload-aware consumer can
resolve. Optional `taxonomyMappings` associate a concrete CVE path with a CAPEC
pattern as `instance-of` or `related-to`; RADAR TRACE does not reproduce CAPEC's
full ordered execution-flow model. A CAPEC record or another source that states
the mapping must be supplied as evidence; the model does not derive CAPEC IDs
from CWE or CVSS alone.

`affectedScope.packages` preserves the CVE Record Format `collectionURL` and
`packageName` pair and may add a deterministically derived `purl`.
`affectedScope.versions` preserves `version`, range bounds, `versionType`, and
affected status so consumers can perform package and SBOM joins without parsing
a human-readable range.

| Field | Question answered |
| --- | --- |
| `affectedScope` | Which product, package, component, routine, behavior, or version range does this path describe? |
| `vulnerableRole` | Is that scope acting as a listener, client, peer, parser, local component, or unresolved role? |
| `interactionInitiator` | Who starts the interaction that reaches the vulnerable boundary? |
| `protocols` | Which normalized communication protocols and layers are evidenced? An empty list means no live protocol is required; strict requirements use a precondition. |
| `trigger` | Which operation and artifact activate the behavior, and how does that artifact cross the immediate boundary? |
| `attackerRequirements` | Which typed endpoint-control, network-position, input-control, or local-access prerequisites must the attacker satisfy? |
| `requiredPathCapabilities` | Which capabilities must all exist: remote-initiated ingress, vulnerable-component-initiated egress, on-path interception, peer networking, or local input transfer? |
| `preconditions` | Which typed version, configuration, feature, protocol, dependency, state, authentication, topology, or user-action conditions constrain the path? |
| `taxonomyMappings` | Which evidence-backed CAPEC patterns describe or relate to this concrete path? |
| `confidence` and `evidenceRefs` | How strongly is the path supported, and which exact claims support it? |
| `evidence` | Which collected source contains each claim, where it appears, which paths it bears on, and whether it is explicit, inferred, corroborating, or contradictory? |

This separates attacker control from topology. `remote-client`, for example,
says that the attacker controls the initiating endpoint; it does not claim the
endpoint is on the public internet. Likewise, `remote-endpoint` says the
vulnerable component contacts an attacker-controlled destination; it does not
claim that egress is permitted in a specific deployment.

Structurally valid profiles with `low` confidence, unresolved material fields,
or contradictory evidence remain publishable but carry
`reviewRecommended: true` in their validated and published envelopes. Invalid
or unsupported output stays in a separate review artifact. This preserves
uncertainty without silently turning it into a false classification.

## Example analyses

These examples show why CVSS AV:N alone is insufficient. Each describes generic
path requirements; a consumer still decides whether those requirements exist in
a particular environment.

| CVE | Attack pattern | Required path capabilities | What a consumer must determine |
| --- | --- | --- | --- |
| CVE-2023-44487 | A remote client reaches an HTTP/2 listener and sends rapid request/reset frames | `remote-initiated-ingress` | Is an affected HTTP/2 listener active, and can an untrusted client route to it? |
| CVE-2024-11053 | curl follows a redirect and leaks `.netrc` credentials to the redirect target | `vulnerable-component-initiated-egress` | Does the workload use affected curl behavior, redirects, and the required `.netrc` configuration? |
| CVE-2021-44228 | Attacker-controlled input reaches Log4j, which performs a JNDI lookup to a remote endpoint | `local-input-transfer` and `vulnerable-component-initiated-egress` | Can untrusted data reach Log4j, and can the process perform the callback? |

Primary references: [HTTP/2 Rapid Reset analysis](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack),
[curl CVE-2024-11053 advisory](https://curl.se/docs/CVE-2024-11053.html),
and [Apache Log4j security advisory](https://logging.apache.org/security.html#CVE-2021-44228).

### CVE-2023-44487 — inbound listener

```json
{
  "schemaVersion": "attack-path-profile/v1",
  "cveId": "CVE-2023-44487",
  "attackPaths": [
    {
      "pathId": "http2-rapid-reset-listener",
      "affectedScope": {
        "description": "Affected HTTP/2 server or proxy request handler",
        "component": "HTTP/2 request handler"
      },
      "vulnerableRole": "listener",
      "interactionInitiator": "attacker-controlled-component",
      "protocols": [
        {"id": "http", "layer": "application", "version": "2"},
        {"id": "tcp", "layer": "transport"}
      ],
      "trigger": {
        "phase": "protocol-message-processing",
        "artifact": "frame",
        "directionAtBoundary": "remote-to-vulnerable",
        "details": "Rapid request and RST_STREAM frame sequence"
      },
      "attackerRequirements": [
        {"kind": "endpoint-control", "value": "remote-client"}
      ],
      "requiredPathCapabilities": ["remote-initiated-ingress"],
      "preconditions": [
        {
          "id": "affected-http2-handler",
          "kind": "runtime-feature",
          "description": "An affected HTTP/2 handler is enabled.",
          "evidenceRefs": ["rapid-reset-analysis"]
        }
      ],
      "taxonomyMappings": [],
      "confidence": "high",
      "evidenceRefs": ["rapid-reset-analysis"]
    }
  ],
  "evidence": [
    {
      "evidenceId": "rapid-reset-analysis",
      "sourceId": "rapid-reset-analysis",
      "sourceType": "other",
      "claim": "A client can create and immediately reset HTTP/2 streams while the server continues processing work.",
      "locator": "How the attack works",
      "pathRefs": ["http2-rapid-reset-listener"],
      "strength": "explicit"
    }
  ],
  "notes": "Deployment reachability still requires an active affected HTTP/2 listener and an untrusted route."
}
```

### CVE-2024-11053 — outbound vulnerable client

```json
{
  "schemaVersion": "attack-path-profile/v1",
  "cveId": "CVE-2024-11053",
  "attackPaths": [
    {
      "pathId": "curl-netrc-redirect",
      "affectedScope": {
        "description": "Affected curl redirect and .netrc handling",
        "product": "curl"
      },
      "vulnerableRole": "client",
      "interactionInitiator": "vulnerable-component",
      "protocols": [
        {"id": "http", "layer": "application"},
        {"id": "tls", "layer": "security"},
        {"id": "tcp", "layer": "transport"}
      ],
      "trigger": {
        "phase": "remote-response-processing",
        "artifact": "redirect",
        "directionAtBoundary": "remote-to-vulnerable"
      },
      "attackerRequirements": [
        {"kind": "endpoint-control", "value": "redirect-target"}
      ],
      "requiredPathCapabilities": ["vulnerable-component-initiated-egress"],
      "preconditions": [
        {
          "id": "netrc-and-redirects",
          "kind": "configuration",
          "description": "curl uses .netrc credentials, follows redirects, and the target entry omits the password.",
          "evidenceRefs": ["curl-advisory-claim"]
        }
      ],
      "taxonomyMappings": [],
      "confidence": "high",
      "evidenceRefs": ["curl-advisory-claim"]
    }
  ],
  "evidence": [
    {
      "evidenceId": "curl-advisory-claim",
      "sourceId": "curl-advisory",
      "sourceType": "vendor-advisory",
      "claim": "Affected curl versions can reuse the first host's password after a redirect to a matching .netrc target entry.",
      "locator": "CVE-2024-11053 vulnerability description",
      "pathRefs": ["curl-netrc-redirect"],
      "strength": "explicit"
    }
  ],
  "notes": "The vulnerable component must first connect or follow a redirect to the attacker-controlled target."
}
```

### CVE-2021-44228 — local trigger with callback

```json
{
  "schemaVersion": "attack-path-profile/v1",
  "cveId": "CVE-2021-44228",
  "attackPaths": [
    {
      "pathId": "log4j-message-lookup",
      "affectedScope": {
        "description": "Affected Log4j message lookup behavior",
        "product": "Apache Log4j",
        "component": "log4j-core"
      },
      "vulnerableRole": "local-component",
      "interactionInitiator": "upstream-component",
      "protocols": [
        {"id": "ldap", "layer": "application"},
        {"id": "tcp", "layer": "transport"}
      ],
      "trigger": {
        "phase": "local-invocation",
        "artifact": "api-arguments",
        "directionAtBoundary": "local-to-vulnerable"
      },
      "attackerRequirements": [
        {"kind": "input-control", "value": "untrusted-input"},
        {"kind": "endpoint-control", "value": "remote-endpoint"}
      ],
      "requiredPathCapabilities": [
        "local-input-transfer",
        "vulnerable-component-initiated-egress"
      ],
      "preconditions": [
        {
          "id": "attacker-input-logged",
          "kind": "api-usage",
          "description": "Attacker-controlled data reaches a vulnerable log message or parameter.",
          "evidenceRefs": ["apache-log4j-claim"]
        },
        {
          "id": "jndi-callback-available",
          "kind": "runtime-feature",
          "description": "The affected JNDI lookup behavior can resolve an attacker-controlled remote endpoint.",
          "evidenceRefs": ["apache-log4j-claim"]
        }
      ],
      "taxonomyMappings": [],
      "confidence": "high",
      "evidenceRefs": ["apache-log4j-claim"]
    }
  ],
  "evidence": [
    {
      "evidenceId": "apache-log4j-claim",
      "sourceId": "apache-log4j-advisory",
      "sourceType": "vendor-advisory",
      "claim": "Attacker-controlled log messages or parameters can cause Log4j to resolve an attacker-controlled JNDI endpoint.",
      "locator": "CVE-2021-44228 advisory entry",
      "pathRefs": ["log4j-message-lookup"],
      "strength": "explicit"
    }
  ],
  "notes": "Local application behavior activates vulnerable code, which then initiates the network callback."
}
```

## Pipeline stages

| Stage | Responsibility | Execution |
| --- | --- | --- |
| `index-nuclei` | Build optional CVE-to-protocol observations from a Nuclei templates checkout | Local or preparatory job |
| `collect` | Gather and normalize CVE, advisory, patch, VEX, and scanner evidence | Batch job |
| `plan-analysis` | Split reusable cache hits from pending CVEs using the analysis identity | Batch job |
| `prepare-extract` | Produce deterministic structured-extraction requests | Batch job |
| model batch | Extract scoped attack paths and evidence references | Vertex AI Gemini batch |
| `validate` | Enforce the core contract and source-backed evidence links; separate invalid review items | Batch job |
| `prepare-repair` | Create one bounded, error-conditioned retry for model-validation failures only | Batch job |
| repair model batch | Re-extract failed profiles from the original evidence and exact validator errors | Vertex AI Gemini batch |
| `prepare-recovery` | Create one clean, source-only retry for a token-truncated repair | Batch job |
| recovery model batch | Regenerate only truncated repairs with a smaller output budget and low thinking level | Vertex AI Gemini batch |
| `reconcile` | Replace first-pass failures with repair outcomes without duplicating CVEs | Batch job |
| `publish` | Add immutable run metadata to validated profiles; attach deterministic CVSS metadata | Batch job |
| `registry-sync` | Merge immutable revisions into the registry and emit added or materially updated profiles | Batch job |
| `export-current` | Rebuild stable CVE-keyed JSON objects from the canonical current registry view | Batch job or operator command |
| consumer import | Join profiles to environment-specific evidence and analyst decisions | Any compatible triage or analysis tool |

The model returns only the reusable core profile. Validation wraps it in
`validated-attack-path-profile/v1` with provenance and review signals. The
stable CVE-keyed public projection emits
`published-attack-path-profile/v2`, which adds a `cvss` array containing every
CNA and ADP CVSS vector found in the mirrored CVE List V5 record (including
version, exact vector string, source, metric key, and available base score and
severity). This metadata is deterministic and does not participate in the
attack-path analysis/cache identity.

## Data snapshot

The `data/` directory in this repository is a point-in-time export of the
published dataset: one `published-attack-path-profile/v2` record per CVE,
sorted into a folder per CVE year (`data/2021/CVE-2021-44228.json`, etc.). As
of this snapshot (latest `publishedAt` 2026-08-13) it contains 15,020 profiles
spanning CVE years 2004–2026. It is the same stable, CVE-keyed projection the
live system serves at:

```text
https://radar-trace.thearmory.cloud/cves/CVE-2026-2530.json
```

A consumer should use `profile.cveId` as its join key and combine a profile
with its own finding, package, image, configuration, and runtime evidence to
make an environment-specific decision. RADAR TRACE deliberately does not
declare a vulnerability reachable in any particular deployment.
