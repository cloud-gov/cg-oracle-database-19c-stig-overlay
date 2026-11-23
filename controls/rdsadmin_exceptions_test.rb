# Run with: make test-rdsadmin (CINC Auditor image; no database).
# Unit checks use fake SQL; posture integration checks use the real CINC engine
# with a local fixture baseline/resource, without network or Oracle access.
require 'minitest/autorun'
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

class RdsadminExceptionsTest < Minitest::Test
  class Result
    def initialize(rows)
      @rows = rows
    end

    def column(_name)
      @rows
    end
  end

  class Session
    def initialize(rows)
      @rows = rows
    end

    def query(sql)
      resource = if sql.include?("'SESSIONS_PER_USER'")
                   'SESSIONS_PER_USER'
                 elsif sql.include?("'PASSWORD_LOCK_TIME'")
                   'PASSWORD_LOCK_TIME'
                 elsif sql.include?("'FAILED_LOGIN_ATTEMPTS'")
                   'FAILED_LOGIN_ATTEMPTS'
                 elsif sql.include?("'INACTIVE_ACCOUNT_TIME'")
                   'INACTIVE_ACCOUNT_TIME'
                 elsif sql.include?("'PASSWORD_VERIFY_FUNCTION'")
                   'PASSWORD_VERIFY_FUNCTION'
                 else
                   'PASSWORD_LIFE_TIME'
                 end
      Result.new(@rows.fetch(resource, []))
    end
  end

  class Context
    attr_reader :failures, :descriptions, :tags, :skipped, :controls, :queries

    def initialize(rows, skip_customer: false, approved: ['ORA12C_STIG_VERIFY_FUNCTION'])
      @rows = rows
      @skip_customer = skip_customer
      @approved = approved
      @skipped = []
      @controls = []
      @queries = 0
      @failures = []
      @descriptions = []
      @tags = []
    end

    def input(name)
      { 'skip_customer_responsibility_controls' => @skip_customer,
        'approved_password_verify_functions' => @approved,
        'failed_logon_attempts' => 3, 'account_inactivity_age' => 35 }[name]
    end

    def include_controls(_name, &block)
      instance_eval(&block)
    end

    def control(id, &block)
      @controls << id
      @id = id
      instance_eval(&block)
    end

    def skip_control(id)
      @skipped << id
    end

    def impact(*_args) ; end
    def title(*_args) ; end
    def desc(*_args) ; end
    def tag(value) ; @tags << value ; end

    def oracledb_session(**_options)
      @queries += 1
      Session.new(@rows)
    end

    def describe(text, &block)
      @descriptions << text
      instance_eval(&block)
    end

    def subject
      @subject = yield
    end

    def it(_text = nil, &block)
      instance_eval(&block) if block
    rescue Minitest::Assertion => e
      @failures << "#{@id}: #{e.message}"
    end

    def should_not(matcher)
      raise Minitest::Assertion, 'empty inventory' if matcher == :empty && @subject.empty?
    end

    def be_empty
      :empty
    end

    def expect(actual)
      Expectation.new(actual)
    end

    def eq(value)
      [:eq, value]
    end

    def match(pattern)
      [:match, pattern]
    end

    class Expectation
      def initialize(actual)
        @actual = actual
      end

      def to(matcher)
        kind, value = matcher
        good = kind == :eq ? @actual == value : !!(@actual =~ value)
        raise Minitest::Assertion, "#{@actual.inspect} did not satisfy #{matcher.inspect}" unless good
      end

      def not_to(matcher)
        raise Minitest::Assertion, 'empty value' if matcher == :empty && @actual.empty?
      end
    end
  end

  # Evaluate the seven exception controls; other controls are outside this harness.
  SOURCE = File.read(File.join(__dir__, 'overlay.rb')).split('  # --- PLATFORM disposition:').first + "\nend\n"
  CUSTOMER_IDS = %w[SV-270495 SV-270549 SV-270550 SV-270551 SV-270561 SV-270563 SV-270587].freeze

  def evaluate(rows, **options)
    context = Context.new(rows, **options)
    context.instance_eval(SOURCE, 'controls/overlay.rb')
    context
  end

  def compliant_rows
    { 'SESSIONS_PER_USER' => %w[RDSADMIN|UNLIMITED DEFAULT|550],
      'PASSWORD_LOCK_TIME' => %w[RDSADMIN|1 DEFAULT|UNLIMITED],
      'FAILED_LOGIN_ATTEMPTS' => %w[RDSADMIN|10 DEFAULT|3],
      'INACTIVE_ACCOUNT_TIME' => %w[RDSADMIN|UNLIMITED DEFAULT|35],
      'PASSWORD_LIFE_TIME' => %w[RDSADMIN|65 DEFAULT|42],
      'PASSWORD_VERIFY_FUNCTION' => %w[RDSADMIN|NULL DEFAULT|ORA12C_STIG_VERIFY_FUNCTION] }
  end

  def test_only_named_aws_rds_exceptions_pass
    result = evaluate(compliant_rows)
    assert_empty result.failures
    assert result.descriptions.any? { |text| text.include?('RDSADMIN') && text.include?('65') }
    assert result.tags.any? { |tag| tag[:rds_exception].to_s.include?('accepted AWS RDS') }
  end

  def test_customer_deviations_fail
    rows = compliant_rows
    rows['SESSIONS_PER_USER'] << 'SITE|UNLIMITED'
    rows['PASSWORD_LOCK_TIME'] << 'SITE|1'
    rows['FAILED_LOGIN_ATTEMPTS'] << 'SITE|10'
    rows['INACTIVE_ACCOUNT_TIME'] << 'SITE|UNLIMITED'
    rows['PASSWORD_LIFE_TIME'] << 'SITE|65'
    assert_equal 5, evaluate(rows).failures.length
  end

  def test_missing_values_and_unexpected_rdsadmin_values_fail
    rows = compliant_rows
    rows['PASSWORD_LOCK_TIME'] = ['RDSADMIN|2']
    rows['INACTIVE_ACCOUNT_TIME'] = ['DEFAULT|']
    rows['PASSWORD_LIFE_TIME'] = ['RDSADMIN|MISSING']
    assert_equal 3, evaluate(rows).failures.length
  end

  def test_missing_profile_limit_fails
    rows = compliant_rows
    rows['SESSIONS_PER_USER'] = ['SITE|MISSING']
    rows['FAILED_LOGIN_ATTEMPTS'] = ['SITE|MISSING']
    assert_equal 2, evaluate(rows).failures.length
  end

  def test_empty_inventories_fail
    rows = compliant_rows.transform_values { [] }
    assert_equal 7, evaluate(rows).failures.length
  end

  def test_null_or_unresolved_customer_functions_fail_both_controls
    ['', 'NULL', 'DEFAULT', 'MISSING', 'UNLIMITED'].each do |value|
      rows = compliant_rows
      rows['PASSWORD_VERIFY_FUNCTION'] << "SITE|#{value}"
      assert_equal 2, evaluate(rows).failures.length, value.inspect
    end
  end

  def test_missing_rdsadmin_function_is_not_the_literal_null_exception
    ['', 'MISSING', 'DEFAULT', 'UNLIMITED'].each do |value|
      rows = compliant_rows
      rows['PASSWORD_VERIFY_FUNCTION'] = ["RDSADMIN|#{value}"]
      assert_equal 2, evaluate(rows).failures.length, value.inspect
    end
  end

  def test_unapproved_function_fails_587_even_on_rdsadmin
    %w[SITE RDSADMIN].each do |profile|
      rows = compliant_rows
      rows['PASSWORD_VERIFY_FUNCTION'] = ["#{profile}|UNAPPROVED_FUNCTION"]
      failures = evaluate(rows).failures
      assert_equal 1, failures.length
      assert_match(/SV-270587/, failures.first)
    end
  end

  def test_resolved_inherited_function_and_reviewed_custom_function_pass
    rows = compliant_rows
    rows['PASSWORD_VERIFY_FUNCTION'] += %w[SITE|ORA12C_STIG_VERIFY_FUNCTION CUSTOM|SITE_VERIFY]
    assert_empty evaluate(rows, approved: %w[ORA12C_STIG_VERIFY_FUNCTION SITE_VERIFY]).failures
    assert_equal 1, evaluate(compliant_rows, approved: []).failures.length
  end

  def test_missing_profile_name_fails_both_password_controls
    rows = compliant_rows
    rows['PASSWORD_VERIFY_FUNCTION'] = ['|ORA12C_STIG_VERIFY_FUNCTION']
    assert_equal 2, evaluate(rows).failures.length
  end

  def test_platform_only_posture_does_not_execute_customer_assertions
    result = evaluate({}, skip_customer: true)
    assert_empty result.failures
    assert_empty result.descriptions
    assert_empty result.controls
    assert_equal CUSTOMER_IDS.sort, result.skipped.sort
    assert_equal 0, result.queries
  end

  # The old fake DSL treated skip_control as permanent, masking overrides that
  # re-selected the same IDs. Exercise actual include_controls/skip_control here.
  def test_cinc_platform_only_excludes_customer_checks_and_preserves_platform_check
    report, queries = run_cinc(skip_customer: true, rows: observed_rows)
    controls = executed_controls(report)
    customer = controls.select { |control| CUSTOMER_IDS.include?(control.fetch('id')) }
    assert customer.all? { |control| control.fetch('results').all? { |result| result['status'] == 'skipped' } }
    assert_equal 0, queries
    sentinel = controls.find { |control| control['id'] == 'platform-sentinel' }
    refute_nil sentinel
    assert_equal ['passed'], sentinel.fetch('results').map { |result| result.fetch('status') }
  end

  def test_cinc_full_posture_retains_all_seven_customer_findings
    report, queries = run_cinc(skip_customer: false, rows: observed_rows)
    controls = executed_controls(report)
    failed = controls.select { |control| control.fetch('results').any? { |result| result['status'] == 'failed' } }
    assert_equal CUSTOMER_IDS.sort, failed.map { |control| control.fetch('id') }.sort
    failures = failed.flat_map { |control| control.fetch('results').select { |result| result['status'] == 'failed' } }
    assert_equal 9, failures.length, JSON.pretty_generate(failures)
    assert_equal 7, queries
  end

  def test_cinc_full_posture_accepts_only_documented_rdsadmin_exceptions
    report, queries = run_cinc(skip_customer: false, rows: compliant_rows)
    controls = executed_controls(report)
    customer = controls.select { |control| CUSTOMER_IDS.include?(control.fetch('id')) }
    assert_equal CUSTOMER_IDS.sort, customer.map { |control| control.fetch('id') }.sort
    customer.each do |control|
      refute_empty control.fetch('results')
      assert control.fetch('results').all? { |result| result['status'] == 'passed' }, JSON.pretty_generate(control)
    end
    assert_equal 7, queries
  end

  def observed_rows
    { 'SESSIONS_PER_USER' => %w[DEFAULT|UNLIMITED ORA_STIG_PROFILE|DEFAULT RDSADMIN|UNLIMITED],
      'PASSWORD_LOCK_TIME' => %w[DEFAULT|1 RDSADMIN|1],
      'FAILED_LOGIN_ATTEMPTS' => %w[DEFAULT|UNLIMITED RDSADMIN|10],
      'INACTIVE_ACCOUNT_TIME' => %w[DEFAULT|UNLIMITED RDSADMIN|UNLIMITED],
      'PASSWORD_LIFE_TIME' => %w[DEFAULT|UNLIMITED ORA_STIG_PROFILE|65 RDSADMIN|UNLIMITED],
      'PASSWORD_VERIFY_FUNCTION' => %w[DEFAULT|NULL RDSADMIN|NULL] }
  end

  def executed_controls(report)
    # Inherited controls also appear as metadata-only entries with no results.
    # Select executions, not a particular profile or the first matching ID.
    controls = report.fetch('profiles').flat_map { |profile| profile.fetch('controls') }
                     .reject { |control| control.fetch('results').empty? }
    ids = controls.map { |control| control.fetch('id') }
    assert_equal ids.uniq.sort, ids.sort, 'A control executed in more than one profile'
    controls
  end

  def write_cinc_fixture(root)
    baseline = File.join(root, 'baseline')
    overlay = File.join(root, 'overlay')
    [baseline, overlay].each { |path| FileUtils.mkdir_p(File.join(path, 'controls')) }
    # include_controls evaluates overrides in the dependency's resource context.
    FileUtils.mkdir_p(File.join(baseline, 'libraries'))
    metadata = YAML.load_file(File.join(__dir__, '..', 'inspec.yml'))
    metadata['depends'] = [{ 'name' => 'oracle-database-19c-stig-baseline', 'path' => '../baseline' }]
    File.write(File.join(overlay, 'inspec.yml'), YAML.dump(metadata))
    File.write(File.join(baseline, 'inspec.yml'), YAML.dump(
      'name' => 'oracle-database-19c-stig-baseline', 'version' => '0.1.0',
      'inputs' => [{ 'name' => 'failed_logon_attempts', 'value' => 3 },
                   { 'name' => 'account_inactivity_age', 'value' => 35 }]
    ))
    baseline_controls = (CUSTOMER_IDS + ['platform-sentinel']).map do |id|
      "control '#{id}' do\n  describe('fixture baseline') { it { expect(true).to eq(true) } }\nend\n"
    end.join
    File.write(File.join(baseline, 'controls', 'fixture.rb'), baseline_controls)
    File.write(File.join(overlay, 'controls', 'overlay.rb'), SOURCE)
    File.write(File.join(baseline, 'libraries', 'oracledb_session.rb'), <<~'RUBY')
      require 'json'
      class FixtureOracleSession < Inspec.resource(1)
        name 'oracledb_session'
        def initialize(*_args); end
        def query(sql)
          File.open(ENV.fetch('FIXTURE_QUERY_LOG'), 'a') { |file| file.puts('query') }
          resource = sql[/\b(?:SESSIONS_PER_USER|PASSWORD_LOCK_TIME|FAILED_LOGIN_ATTEMPTS|INACTIVE_ACCOUNT_TIME|PASSWORD_VERIFY_FUNCTION)\b/]
          @rows = JSON.parse(File.read(ENV.fetch('FIXTURE_ROWS'))).fetch(resource || 'PASSWORD_LIFE_TIME')
          self
        end
        def column(_name)
          @rows
        end
      end
    RUBY
    overlay
  end

  def run_cinc(skip_customer:, rows:)
    candidates = ENV.fetch('PATH').split(File::PATH_SEPARATOR).map { |path| File.join(path, 'cinc-auditor') }
    auditor = (candidates + ['/opt/cinc-auditor/bin/cinc-auditor']).find { |path| File.executable?(path) }
    refute_nil auditor, 'CINC Auditor is required: run make test-rdsadmin'
    Dir.mktmpdir('rdsadmin-posture-') do |root|
      overlay = write_cinc_fixture(root)
      inputs = File.join(root, 'inputs.yml')
      # CLI inputs reach the dependency namespace too; overlay defaults do not.
      File.write(inputs, YAML.dump(
        'skip_customer_responsibility_controls' => skip_customer,
        'approved_password_verify_functions' => ['ORA12C_STIG_VERIFY_FUNCTION'],
        'failed_logon_attempts' => 3, 'account_inactivity_age' => 35
      ))
      rows_path = File.join(root, 'rows.json')
      File.write(rows_path, JSON.generate(rows))
      query_log = File.join(root, 'queries.log')
      report_path = File.join(root, 'report.json')
      stdout, stderr, status = Open3.capture3(
        { 'FIXTURE_ROWS' => rows_path, 'FIXTURE_QUERY_LOG' => query_log },
        auditor, 'exec', overlay, '--input-file', inputs, '--reporter', "json:#{report_path}"
      )
      assert_includes [0, 100, 101], status.exitstatus, "#{stdout}\n#{stderr}"
      assert File.file?(report_path), "CINC did not produce a report: #{stdout}\n#{stderr}"
      report = JSON.parse(File.read(report_path))
      report.fetch('profiles').each do |profile|
        refute_equal 'failed', profile['status'], profile['status_message']
      end
      [report, File.exist?(query_log) ? File.readlines(query_log).length : 0]
    end
  end
end
