# Schema versions

`attack-path-profile-v1.schema.json` is the canonical `attack-path-profile/v1`
contract: the reusable, generic core of an attack-path profile (affected
scope, vulnerable role, interaction initiator, trigger, attacker requirements,
required path capabilities, preconditions, evidence, and optional CAPEC
taxonomy mappings).

`published-attack-path-profile-v1.schema.json` wraps the core profile with
publication provenance (`reviewRecommended`, `reviewReasons`, `provenance`,
`publication`).

`published-attack-path-profile-v2.schema.json` extends the v1 envelope with a
`cvss` array containing every CNA/ADP CVSS vector found for the CVE (version,
exact vector string, source, metric key, and available base score and
severity). This metadata is deterministic and does not participate in the
attack-path analysis itself. **The records in `data/` use this v2 envelope.**
