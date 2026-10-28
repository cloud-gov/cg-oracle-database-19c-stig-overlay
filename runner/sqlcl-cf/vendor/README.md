# Vendored SQLcl distribution

This directory holds the **vendored Oracle SQLcl distribution** used by the
Java-buildpack packaging (`../README.md`). It is intentionally **git-ignored**
(`../.gitignore`) because the distribution is large and carries the Oracle **OTN
EULA**, whose redistribution terms we do not want to trip by committing it.

## Provenance & pinning

The Makefile pins the exact source and Oracle-published checksums:

| Field | Value |
| --- | --- |
| SQLcl version | `26.3.0.260.1620` |
| Source | `https://download.oracle.com/otn_software/java/sqldeveloper/sqlcl-26.3.0.260.1620.zip` |
| Archive MD5 | `52fb8905e90a99caf23ac022b609e3f8` |
| Archive SHA1 | `c858adea26aca18496a8b638b953285839fecbce` |

## How to vendor

```bash
# Normal path: download from the pinned Oracle HTTPS URL, verify both checksums,
# verify the embedded version, and atomically replace vendor/sqlcl/.
make vendor-sqlcl-cf

# Offline development only:
make vendor-sqlcl-cf SQLCL_CF_ARCHIVE_PATH="$PWD/sqlcl-26.3.0.260.1620.zip"
```

MD5 and SHA1 are retained because they are the checksums Oracle publishes for this
artifact; both must match before extraction.

The buildpack supplies the JRE; do **not** vendor a JVM. `entrypoint.sh` points
`SQLCL_BIN` at `vendor/sqlcl/bin/sql`.
