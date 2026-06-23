#!/usr/bin/env python3
"""Unit tests for migrate_controls.py.

Uses the Python standard-library ``unittest`` framework (no third-party
dependencies required). Run with::

    python3 -m unittest discover -s 12c_to_19c -p 'test_*.py' -v

or via the one-command verify script::

    ./12c_to_19c/verify.sh
"""

import json
import tempfile
import unittest
from pathlib import Path

import migrate_controls as mc


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures'
CONTROLS_12C = HERE / '12c_controls'


class SeverityToImpactTests(unittest.TestCase):
    def test_known_severities(self):
        self.assertEqual(mc.severity_to_impact('high'), 0.7)
        self.assertEqual(mc.severity_to_impact('medium'), 0.5)
        self.assertEqual(mc.severity_to_impact('low'), 0.3)

    def test_case_insensitive(self):
        self.assertEqual(mc.severity_to_impact('HIGH'), 0.7)
        self.assertEqual(mc.severity_to_impact('Medium'), 0.5)

    def test_unknown_and_empty_default_to_zero(self):
        self.assertEqual(mc.severity_to_impact('unknown'), 0.0)
        self.assertEqual(mc.severity_to_impact(''), 0.0)
        self.assertEqual(mc.severity_to_impact(None), 0.0)


class TitleExtractionTests(unittest.TestCase):
    def test_extract_double_quoted_title(self):
        rb = 'control \'V-1\' do\n  title "Some title."\nend\n'
        self.assertEqual(mc.extract_title_from_rb(rb), 'Some title.')

    def test_extract_single_quoted_title(self):
        rb = "control 'V-1' do\n  title 'Another title.'\nend\n"
        self.assertEqual(mc.extract_title_from_rb(rb), 'Another title.')

    def test_missing_title_returns_none(self):
        self.assertIsNone(mc.extract_title_from_rb('control \'V-1\' do\nend\n'))


class SimilarityAndMatchingTests(unittest.TestCase):
    def test_identical_titles_score_one(self):
        self.assertEqual(mc.similarity('abc def', 'ABC DEF'), 1.0)

    def test_find_all_matches_sorted_descending(self):
        files = sorted(CONTROLS_12C.glob('*.rb'))
        title = 'Oracle instance names must not contain Oracle version numbers.'
        matches = mc.find_all_matches(title, files)
        self.assertTrue(matches, 'expected at least one match')
        # Sorted by score, highest first.
        scores = [m['score'] for m in matches]
        self.assertEqual(scores, sorted(scores, reverse=True))
        # The identical-title 12c control is the top match.
        self.assertEqual(matches[0]['group_id'], 'V-61413')
        self.assertAlmostEqual(matches[0]['score'], 1.0)

    def test_threshold_filters_weak_matches(self):
        files = sorted(CONTROLS_12C.glob('*.rb'))
        title = 'Oracle instance names must not contain Oracle version numbers.'
        matches = mc.find_all_matches(title, files)
        good = [m for m in matches if m['score'] >= mc.MATCH_THRESHOLD]
        # Only the exact title clears the 0.85 threshold.
        self.assertEqual([m['group_id'] for m in good], ['V-61413'])


class TagCarryoverTests(unittest.TestCase):
    def setUp(self):
        self.content = (CONTROLS_12C / 'V-61413.rb').read_text()

    def test_carry_over_nist_tag(self):
        self.assertEqual(
            mc.extract_tag_value(self.content, 'nist'),
            "['CM-6 b', 'Rev_4']",
        )

    def test_carry_over_stig_id_tag(self):
        self.assertEqual(
            mc.extract_tag_value(self.content, 'stig_id'),
            "'O121-BP-021300'",
        )

    def test_carry_over_nil_tag(self):
        self.assertEqual(mc.extract_tag_value(self.content, 'mitigations'), 'nil')

    def test_missing_tag_returns_none(self):
        self.assertIsNone(mc.extract_tag_value(self.content, 'no_such_tag'))


class RubyCodeExtractionTests(unittest.TestCase):
    def test_extracts_sql_block(self):
        content = (CONTROLS_12C / 'V-61413.rb').read_text()
        code = mc.extract_ruby_code(content)
        self.assertIsNotNone(code)
        self.assertIn('sql = oracledb_session', code)
        self.assertIn("v$instance", code)
        # Should not include the trailing `end` of the control block.
        self.assertFalse(code.strip().endswith('end\nend'))

    def test_no_sql_block_returns_none(self):
        self.assertIsNone(mc.extract_ruby_code('control \'V-1\' do\nend\n'))


class ProcessControlTests(unittest.TestCase):
    """End-to-end: regenerate V-270521 and assert on the match metadata.

    Note: the exact generated file format is intentionally NOT asserted here,
    since the control template/formatting may evolve over time. We assert on
    the semantic outcomes (selected match, match list, check-changed flag).
    """

    def test_v270521_selects_expected_match(self):
        stig = json.loads((FIXTURES / '19c_sample_stig.json').read_text())
        control_19c = stig['groups'][0]
        control_19c.setdefault('benchmarkId', stig.get('benchmarkId') or stig.get('id'))

        files = sorted(CONTROLS_12C.glob('*.rb'))

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            result = mc.process_control(control_19c, files, out_dir)
            generated = (out_dir / 'V-270521.rb').read_text()

        # A file was produced for the 19c group ID.
        self.assertTrue(generated.startswith("control 'V-270521' do"))
        # Carried over the Ruby check logic from the matched 12c control.
        self.assertIn('sql = oracledb_session', generated)
        # Match metadata is correct.
        self.assertEqual(result['primary'], 'V-61413')
        self.assertEqual(result['all_matches'], ['V-61413'])
        self.assertTrue(result['check_changed'])



if __name__ == '__main__':
    unittest.main()
