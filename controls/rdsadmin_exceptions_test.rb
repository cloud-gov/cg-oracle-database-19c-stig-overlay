# Run with: ruby controls/rdsadmin_exceptions_test.rb (Ruby stdlib only).
# Exercises the scoped overlay DSL with a fake SQL result, without a database.
require 'minitest/autorun'

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
    attr_reader :failures, :descriptions, :tags

    def initialize(rows, skip_customer: false, approved: ['ORA12C_STIG_VERIFY_FUNCTION'])
      @rows = rows
      @skip_customer = skip_customer
      @approved = approved
      @skipped = []
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
      return if @skipped.include?(id)

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

  # Evaluate only the password-function exceptions; other controls are inherited.
  SOURCE = File.read(File.join(__dir__, 'overlay.rb')).split('  # --- PLATFORM disposition:').first + "\nend\n"

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
    assert result.descriptions.any? { |text| text.include?('RDSADMIN') && text.include?('NULL') }
    assert result.tags.any? { |tag| tag[:rds_exception].to_s.include?('accepted AWS RDS') }
  end

  def test_empty_inventories_fail
    rows = compliant_rows.transform_values { [] }
    assert_equal 2, evaluate(rows).failures.length
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
  end
end
