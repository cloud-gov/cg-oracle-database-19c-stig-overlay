# frozen_string_literal: true

# Specs for the downstream oracledb_session multi-column CSV stopgap
# (libraries/oracledb_session_patch.rb). Runs in the CINC Auditor image; see
# `make test-ruby`. Two guarantees, matching the review asks on PR #33:
#   1. the patched parser addresses every column, keeps single-column
#      back-compat, preserves quoted commas, and returns [] for empty output;
#   2. a "remove me" guard fails loudly once inspec/inspec#7997 lands upstream,
#      signalling the revert tracked in #35 (which closes #32).

require "inspec/resources/oracledb_session"
require_relative "../libraries/oracledb_session_patch"

RSpec.describe "oracledb_session multi-column CSV stopgap" do
  # parse_csv_result is private and touches no instance state; allocate skips
  # initialize (which would demand auth) and prepends "oracle_query_string" —
  # the echo marker it splits on — just like real sqlplus/oraquery output.
  def parse(csv_body)
    ::Inspec::Resources::OracledbSession.allocate
      .send(:parse_csv_result, "oracle_query_string\n#{csv_body}")
  end

  MULTI = <<~CSV
    "PROFILE","LIMIT","COMMENTS"
    "DEFAULT","UNLIMITED","locked, until reset"
    "DEFAULT","365","set by DBA"
  CSV

  # column => expected values across rows. Covers multi-column addressing,
  # numeric-looking values, and a comma inside a quoted field (regression:
  # upstream's gsub-before-parse would split on it).
  {
    "profile"  => %w[DEFAULT DEFAULT],
    "limit"    => %w[UNLIMITED 365],
    "comments" => ["locked, until reset", "set by DBA"],
  }.each do |col, expected|
    it "addresses the #{col.inspect} column across all rows" do
      expect(parse(MULTI).map { |r| r[col] }).to eq(expected)
    end
  end

  it "keeps single-column back-compat and downcases the header" do
    # Callers index by the downcased key, as the resource's own examples do
    # (`.column('value')`).
    expect(parse(%{"VALUE"\n"ORCL"\n}).map { |r| r["value"] }).to eq(["ORCL"])
  end

  it "returns [] for empty output" do
    expect(parse("")).to eq([])
    expect(parse("\n")).to eq([])
  end

  it "wins over the vendored parser at runtime (prepend is in the ancestry)" do
    owner = ::Inspec::Resources::OracledbSession
      .instance_method(:parse_csv_result).owner
    expect(owner.name).to match(/OraqueryMultiColumnCsvFix/)
  end

  # "Remove me" guard: the stopgap exists only because the *vendored* resource
  # still has the buggy gsub-before-CSV.parse parser. When this fails,
  # inspec/inspec#7997 has shipped — do the revert tracked in #35 (delete
  # libraries/oracledb_session_patch.rb, this spec, and the Dockerfile
  # `COPY libraries` line), which closes #32.
  it "still needs the stopgap (vendored resource has the buggy parser)" do
    source = ::Inspec::Resources::OracledbSession
      .instance_method(:query).source_location.first
    expect(File.read(source)).to include('gsub(",", "comma_query_sub")'),
      "Vendored oracledb_session no longer uses the buggy comma-substitution " \
      "parser — inspec/inspec#7997 has landed. REMOVE the stopgap: see #35 (closes #32)."
  end
end
