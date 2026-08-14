# Schema versions

Two contracts are published here: the **core profile** (the reusable,
deployment-independent analysis) and the **envelopes** that wrap it for
validation and publication.

## Core profile

`attack-path-profile-v2.schema.json` is the current canonical
`attack-path-profile/v2` contract. Version 2 adds explicit ownership for
attacker access, direct outcomes, mitigation assessment, and narrative-only
conditions while preserving evidence links and inbound-versus-outbound path
semantics.

Each `mitigationAssessment.options` entry carries a required `controlKind`
stating what the option actually is: `configuration`, `access-restriction`,
`usage-change`, `operational-control`, or `version-upgrade`. Only independent
controls are published, so `version-upgrade` never appears in `data/`: moving to
a fixed release is already carried by `affectedScope.versions` and is not a
mitigation. The value remains in the enum because the contract names the kind it
excludes rather than leaving it implied.

`attack-path-profile-v1.schema.json` is the superseded
`attack-path-profile/v1` contract: the same generic core without attacker
access, direct outcomes, mitigation assessment, or structured condition atoms.
It remains immutable and readable so historical records stay interpretable, but
nothing in `data/` uses it.

## Envelopes

`validated-attack-path-profile-v2.schema.json` is the validation envelope for a
v2 core profile, carrying review signals and the provenance recorded when the
profile was validated. It is included so consumers can validate the complete
internal contract, although `data/` contains published envelopes rather than
validated ones.

`published-attack-path-profile-v2.schema.json` wraps the v2 core profile with a
`cvss` array containing every CNA/ADP CVSS vector found for the CVE (version,
exact vector string, source, metric key, and available base score and
severity). This metadata is deterministic and does not participate in the
attack-path analysis itself. **The records in `data/` use this v2 envelope.**

`provenance` and `publication` are optional in that envelope. The stable
per-CVE objects served to consumers omit the run audit trail — model version,
fingerprints, and run ID — which is retained on the internal publish artifact
and in the BigQuery revision history. A record that does carry those fields is
still checked against them.

`published-attack-path-profile-v1.schema.json` is the equivalent envelope for a
v1 core, kept for historical records. It requires the provenance and publication
blocks that the v2 public projection omits.
