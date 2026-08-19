# Vendored SQLcl distribution

This directory holds the **vendored Oracle SQLcl distribution** used by the
Java-buildpack packaging (`../README.md`). It is intentionally **git-ignored**
(`../.gitignore`) because the distribution is large and carries the Oracle **OTN
EULA**, whose redistribution terms we do not want to trip by committing it.

## Provenance & pinning

Record the exact version and Oracle-published checksum you vendored, mirroring the
Docker path's pinned digest discipline:

| Field | Value |
| --- | --- |
| SQLcl version | `26.2.1.0` (match the Docker path's pinned base image) |
| Source | Oracle SQLcl download (OTN) |
| Archive SHA256 | `<paste the Oracle-published SHA256 you verified>` |
| Vendored on | `<YYYY-MM-DD>` |

## How to vendor

```bash
# 1. Download sqlcl-<version>.zip from Oracle.
# 2. Verify the checksum against Oracle's published value:
sha256sum sqlcl-*.zip           # compare to the table above
# 3. Unzip here (yields ./sqlcl/bin/sql):
unzip sqlcl-*.zip -d "$(dirname "$0")"
# 4. Confirm the launcher exists and is executable:
test -x ./sqlcl/bin/sql && echo OK
```

The buildpack supplies the JRE; do **not** vendor a JVM. `entrypoint.sh` points
`SQLCL_BIN` at `vendor/sqlcl/bin/sql`.
