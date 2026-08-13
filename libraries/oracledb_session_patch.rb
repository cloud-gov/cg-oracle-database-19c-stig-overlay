# Downstream stopgap for the upstream oracledb_session multi-column CSV bug.
#
# The vendored InSpec resource's `parse_csv_result` only supports single-column
# results: it globally substitutes commas before CSV.parse (destroying the
# delimiters) and then flattens each row into `[k,v]`, so `.column('<name>')`
# returns nil for every column of any multi-column SELECT. This is a silent
# wrong answer that can flip a control's pass/fail.
#
# Upstream fix: inspec/inspec#7997 (rewrites parse_csv_result to parse standard
# RFC 4180 CSV directly). CINC Auditor picks it up on its next rebuild. Until
# that release lands, this profile library prepends the corrected parser so our
# scans return real column values today.
#
# Tracking: cloud-gov/cg-oracle-database-19c-stig-overlay#32
# Revert (dependency-blocked on the upstream fix): #35
#
# This override is intentionally byte-for-byte equivalent to the upstream PR's
# parse_csv_result. Remove it once the runner image ships a CINC Auditor that
# includes inspec/inspec#7997 (see #35).

require "inspec/resources/oracledb_session"
require "csv"
require "hashie"

module OraqueryMultiColumnCsvFix
  # sqlplus (SET MARKUP CSV) and sqlcl (set sqlformat csv), and this repo's
  # oraquery client, all emit standard RFC 4180 CSV: a header row followed by
  # data rows, with embedded commas/quotes/newlines quoted per the spec. Parse
  # it directly so every column is addressable and commas inside quoted fields
  # are preserved.
  def parse_csv_result(stdout)
    output = stdout.split("oracle_query_string")[-1].to_s.sub(/\r/, "").strip
    return [] if output.empty?

    converter = ->(header) { header.downcase }
    ::CSV.parse(output, headers: true, header_converters: converter).filter_map do |row|
      hash = row.to_h
      # Drop only truly empty parsed rows (no columns); keep rows whose values
      # are nil/empty so callers can still index by row position.
      next if hash.empty?

      ::Hashie::Mash.new(hash)
    end
  end
end

::Inspec::Resources::OracledbSession.prepend(OraqueryMultiColumnCsvFix)
