# Local modifications to the vendored MITRE profile

This directory is a **vendored, pinned copy** of
[`mitre/oracle-database-19c-stig-baseline`](https://github.com/mitre/oracle-database-19c-stig-baseline)
(Apache-2.0; see `LICENSE.md` / `NOTICE.md`), imported at HEAD-of-`main` on
2026-07-24 for the cloud.gov RDS Oracle 19c STIG overlay validation harness.

Per Apache-2.0 §4(b), the following **modifications from upstream** are recorded
here. All are also reported upstream in
[mitre/oracle-database-19c-stig-baseline#1](https://github.com/mitre/oracle-database-19c-stig-baseline/issues/1)
and tracked in this repo's issues #6 / #9.

## Modifications

1. **`inspec.yml`** — corrected `name`/`title`/`summary` from
   `oracle-database-12c-stig-baseline` → `19c` (upstream 12c copy-paste artifact).
   Added a `sqlcl_bin` input (upstream only declared `sqlplus_bin`) and a
   `max_idle_time` input (for the SV-270497 check below).

2. **`controls/SV-270580.rb`** — changed `desc 'fix', %q(...)` to `%q{...}`.
   Upstream's `%q(` delimiter collided with unbalanced parens in embedded SQL
   examples, causing a Ruby SyntaxError that prevented the **entire profile** from
   loading.

3. **12 controls filled from the analogous MITRE 12c profile** (empty stubs
   upstream), marked `# PORTED FROM 12c V-#####`:
   SV-270504, SV-270510, SV-270511, SV-270513, SV-270519, SV-270523, SV-270526,
   SV-270550, SV-270553, SV-270561, SV-270587.

4. **1 control authored from the DISA V1R5 check text** (no 12c analogue), marked
   `# OVERLAY-AUTHORED`: SV-270497 (`max_idle_time`).

5. **23 controls converted from empty stubs to explicit review blocks**, marked
   `# OVERLAY-ADDED`: 17 manual-review skips + 6 documented not-applicable-on-RDS
   (the latter also classified in `../../control-layers.yml`).

Net effect: upstream shipped 35 metadata-only stubs that silently pass at scan
time; this vendored copy has **zero**. See `../RESULTS.md` for the validated
per-control disposition and the accuracy caveats (#9) still to confirm vs. DISA V1R5.

> These edits are ours; MITRE does not endorse them. To re-sync with upstream,
> re-vendor at a pinned commit and re-apply these modifications (or consume the
> upstream fixes once mitre#1 is addressed).
