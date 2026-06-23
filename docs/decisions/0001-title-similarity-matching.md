---
title:
  "ADR-0001: Use title-similarity matching to map 12c controls to 19c controls"
description:
  "Decision to select the source 12c InSpec control for each 19c STIG control
  via SequenceMatcher title similarity with a 0.85 threshold"
status: accepted
tier: 2
last_updated: "2026-06-23"
nist_controls: ["CM-3", "SA-8", "SA-11", "SA-15"]
---

# ADR-0001: Use title-similarity matching to map 12c controls to 19c controls

- Status: draft -- wholly AI-generated at this point, requires review
- Date: 2026-06-23
- Deciders: Peter Burkholder

## Context and Problem Statement

The project migrates Oracle Database 12c InSpec controls (STIG v1) into the
smaller set of Oracle Database 19c controls (STIG v1). Per `PROJECT_PLAN.md`,
the approach is to iterate over each 19c STIG control and reuse the check logic
from the closest applicable 12c control.

There is no authoritative crosswalk that maps 12c group IDs (e.g. `V-61413`) to
19c group IDs (e.g. `V-270521`). The migration tool
(`12c_to_19c/migrate_controls.py`) must decide, for each 19c control, which 12c
control(s) are the "closest" source of reusable check logic, and do so
reproducibly and auditably.

## Decision Drivers

- Must be deterministic and reproducible (auditability — CM-3).
- Must run with no third-party dependencies (the tool uses only the Python
  standard library).
- Must surface ambiguity rather than silently guessing (no silent failures, per
  AGENTS.md §14.5).
- Must be simple to maintain by reviewers who are not the original author.

## Considered Options

1. **Title-similarity matching** using `difflib.SequenceMatcher` on the control
   titles, with a fixed acceptance threshold.
2. **Manual crosswalk table** hand-authored mapping each 19c ID to a 12c ID.
3. **Full-text / semantic similarity** over the entire control body
   (description + check + fix), e.g. embeddings or TF-IDF.

## Decision Outcome

Chosen option: **Option 1 — title-similarity matching**, because STIG control
titles are short, stable, and highly indicative of intent; the standard library
covers it with zero dependencies; and the score plus the full match list can be
recorded in each generated control for human audit.

Implementation specifics:

- Similarity is computed with
  `SequenceMatcher(None, a.lower(), b.lower()).ratio()`.
- A control is considered a match only at or above `MATCH_THRESHOLD = 0.85`.
- The highest-scoring match becomes the primary source for the Ruby check logic
  and carry-over tags.
- **All** matches at or above threshold are recorded in the `12c_matches` tag
  (primary first), and the threshold is recorded in `12c_match_threshold`, so a
  reviewer can see what was considered.
- When the 12c and 19c check text differ, a `NOTE` comment is emitted in the
  generated control flagging that the Ruby code may need manual updating.
- When no 12c control clears the threshold, a `skip` stub is emitted requiring
  manual implementation (fail-closed rather than guess).

### Consequences

- Good: deterministic, dependency-free, auditable, easy to re-run.
- Good: ambiguity is surfaced (multiple matches listed; sub-threshold cases
  become explicit manual-review stubs).
- Bad: title-only matching can miss controls whose titles were reworded between
  12c and 19c even though the underlying check is equivalent.
- Bad: the 0.85 threshold is a heuristic; it may need tuning as more controls
  are processed against the full STIG.

### Confirmation

- Unit tests in `12c_to_19c/test_migrate_controls.py` cover the similarity
  scoring, descending-sort ordering, threshold filtering, and the end-to-end
  match selection for `V-270521 -> V-61413`.
- Verify with the one-command script: `./12c_to_19c/verify.sh`.

## Pros and Cons of the Options

### Option 2 — Manual crosswalk table

- Good: maximally accurate where a human has reviewed each pairing.
- Bad: labor-intensive, error-prone, and must be maintained by hand as the STIG
  evolves; defeats the goal of an automated migration tool.

### Option 3 — Full-text / semantic similarity

- Good: can capture equivalence even when titles are reworded.
- Bad: introduces third-party dependencies (embeddings/TF-IDF libraries), is
  less deterministic/explainable, and adds supply-chain surface for a task whose
  titles already discriminate well.
