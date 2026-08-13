# Schema versions

`attack-path-profile-v1.schema.json` is the canonical `attack-path-profile/v1`
contract: the reusable, generic core of an attack-path profile (affected
scope, vulnerable role, interaction initiator, trigger, attacker requirements,
required path capabilities, preconditions, evidence, and optional CAPEC
taxonomy mappings).

`attack-path-profile-v2.schema.json` is the current canonical
`attack-path-profile/v2` contract. Version 2 adds explicit ownership for
attacker access, direct outcomes, mitigation assessment, and narrative-only
conditions while preserving evidence links and inbound-versus-outbound path
semantics. Version 1 remains immutable and readable for historical data.

`published-attack-path-profile-v1.schema.json` wraps the core profile with
publication provenance (`reviewRecommended`, `reviewReasons`, `provenance`,
`publication`).

`validated-attack-path-profile-v2.schema.json` is the validation envelope for a
v2 core profile. It is included so consumers can validate the complete
contract, although public `data/` contains published envelopes.

`published-attack-path-profile-v2.schema.json` wraps the v2 core profile with a
`cvss` array containing every CNA/ADP CVSS vector found for the CVE (version,
exact vector string, source, metric key, and available base score and
severity). This metadata is deterministic and does not participate in the
attack-path analysis itself. **The records in `data/` use this v2 envelope.**
