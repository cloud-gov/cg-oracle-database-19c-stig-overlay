# Vendored SQLcl distribution

This directory holds the **vendored Oracle SQLcl distribution** used by the
Java-buildpack packaging (`../README.md`). It is intentionally **git-ignored**
(`../.gitignore`) because the distribution is large and carries the Oracle **OTN
EULA**, whose redistribution terms we do not want to trip by committing it.

GSA Tech Law confirmed by email on November 2, 2026 that our internal SQLcl testing
use conforms to the OTN license. This confirmation does not cover redistributing the
distribution or other uses; keep the ZIP and extracted files out of the repository.

## Provenance & pinning

The Makefile pins the exact source and three checksums. MD5 and SHA1 are
Oracle-published; SHA256 was computed and confirmed locally from the archive,
not published by Oracle.

| Field | Value |
| --- | --- |
| SQLcl version | `26.3.0.260.1620` |
| Source | `https://download.oracle.com/otn_software/java/sqldeveloper/sqlcl-26.3.0.260.1620.zip` |
| Archive MD5 | `52fb8905e90a99caf23ac022b609e3f8` |
| Archive SHA1 | `c858adea26aca18496a8b638b953285839fecbce` |
| Archive SHA256 (locally verified, 2026-11-02) | `eb0dca2becc30e9aa1c700ae71e5df6efde8a33d098d7d23405b6558bbb81a81` |

## How to vendor

```bash
# Normal path: download from the pinned Oracle HTTPS URL, verify all three checksums,
# verify the embedded version, and atomically replace vendor/sqlcl/.
make vendor-sqlcl-cf

# Offline development only:
make vendor-sqlcl-cf SQLCL_CF_ARCHIVE_PATH="$PWD/sqlcl-26.3.0.260.1620.zip"
```

MD5 and SHA1 are retained because they are the checksums Oracle publishes for this
artifact; all three must match before extraction. The locally calculated SHA256
pins the reviewed archive but is not independent proof of Oracle provenance.

The buildpack supplies the JRE; do **not** vendor a JVM. `entrypoint.sh` points
`SQLCL_BIN` at `vendor/sqlcl/bin/sql`.
