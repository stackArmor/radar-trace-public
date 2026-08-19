# Validation

How RADAR TRACE profiles are validated, and what the current results show.
This exercise tests whether a profile is sound and defensible under
independent adversarial challenge; it is not presented as a statistical
estimate of field-level precision or recall, and cross-model agreement is not
independent ground truth.

## Method

RADAR TRACE profiles are validated through blind, cross-model adversarial
review:

1. **Independent re-derivation.** A sample of 250 published profiles is
   independently re-derived by a second, independently developed frontier
   model, working from byte-identical source records — verified by SHA-256
   source fingerprint — under the same field contract and semantics as the
   production pipeline. The reviewer never sees the production profile and may
   not consult material beyond the assigned source record.
2. **Fail-closed validation on both sides.** Production output and reviewer
   output must both pass the same closed-vocabulary, cross-field-invariant
   validation before any comparison. Invalid output is re-derived, never
   hand-corrected.
3. **Canonical comparison.** Both derivations are reduced to one projection —
   vulnerable role, interaction initiator, required path capabilities,
   trigger phase/artifact/direction, and protocols — and compared field by
   field.
4. **Decomposed scoring.** Differences are classified, not totaled:
   - **agreement** — identical committed values;
   - **abstention** — one derivation commits a value, the other reports
     `unknown` because the evidence does not establish it. Abstention is
     instructed behavior and is not scored as a contradiction;
   - **evidence-threshold** — one derivation records a protocol the other
     declines to infer from the same text;
   - **committed contradiction** — both derivations commit and the values
     differ. Only this class can indicate a defective profile, and every such
     case is routed to human adjudication against the cited source evidence.

## Results

Across the 250-profile sample:

| Measure | Result |
|---|---:|
| Field-level comparisons free of committed contradiction | **95.4%** |
| Profiles with no committed contradiction in any field | **90.4%** (226/250) |
| Profiles with byte-identical projections | 63% (158/250) |
| Committed contradictions routed to cited adjudication | 24 profiles |

## Expected disagreement

Residual disagreement between independent assessors is expected and is not by
itself a process flaw. Independent assessors already disagree about the most
standardized field in the vulnerability ecosystem: a stackArmor analysis of
1,000 randomly selected CVEs, comparing independent CVSS assessments of the
same CVE, found:

| Dimension | Rate | Meaning |
|---|---:|---|
| CVSS vector discrepancy | 42.4% | Over 4 in 10 CVEs carry at least one differing CVSS vector metric between assessors |
| Base score discrepancy | 41.5% | Different numeric base score for the same CVE |
| Severity tier discrepancy | 25.9% | More than 1 in 4 CVEs shift severity tiers (Medium ↔ High, High ↔ Critical) |
| Average score delta when diverging | ±1.78 pts | Nearly two full CVSS points apart when they differ; maximum observed exceeds 5.3 |

Semantic vulnerability analysis carries irreducible subjectivity. The
appropriate response is the one this project practices throughout: decomposed
per-field measurement, preserved abstention, evidence-linked claims, and human
adjudication of the contested residue — not a single aggregate accuracy
number.

## Artifacts

The comparison harness, fingerprint-bound inputs, and per-run comparison
artifacts are retained internally and support recomputation of the results
above from the recorded inputs and outputs.
