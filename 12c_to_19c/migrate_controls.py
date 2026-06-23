#!/usr/bin/env python3
"""
Migrate Oracle 12c InSpec controls to Oracle 19c format (Version 3).

This script iterates through the 19c STIG controls (from a STIG JSON export)
and, for each one:

  1. Writes a new InSpec control to the output directory, named for the 19c
     group ID (e.g. ``V-270521.rb``).
  2. Populates the standard 19c ``tag`` elements from the STIG JSON.
  3. Searches the 12c controls directory for the closest matching control
     (by title similarity).
  4. Copies the check logic (Ruby code) from the matched 12c control.
  5. Records all matches above the threshold in the ``12c_matches`` tag and
     copies the carry-over tags (nist, stig_id, etc.) from the primary match.

The output control format mirrors ``fixtures/V-270521.rb`` (the gold fixture).
"""

import argparse
import json
import re
import textwrap
from pathlib import Path
from difflib import SequenceMatcher


# Threshold below which a 12c control is not considered a match.
MATCH_THRESHOLD = 0.85

# STIG severity -> InSpec impact mapping (see top-level README.md):
#   high -> 0.7, medium -> 0.5, low -> 0.3, (non-applicable) -> 0.0
SEVERITY_TO_IMPACT = {
    'high': 0.7,
    'medium': 0.5,
    'low': 0.3,
}

# Carry-over tags pulled from the matched 12c control when present.
CARRYOVER_TAGS = [
    'stig_id',
    'nist',
    'false_negatives',
    'false_positives',
    'documentable',
    'mitigations',
    'severity_override_guidance',
    'potential_impacts',
    'third_party_tools',
    'mitigation_controls',
    'responsibility',
    'ia_controls',
]


def similarity(a, b):
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def extract_title_from_rb(rb_content):
    """Extract the title field from a Ruby control file."""
    match = re.search(r"title\s+['\"](.+?)['\"]", rb_content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def extract_tag_value(rb_content, tag_name):
    """Extract the raw (verbatim) value of a single-line tag from a 12c control.

    Returns the text exactly as it appears to the right of the colon (e.g.
    ``['CM-6 b', 'Rev_4']`` or ``nil`` or ``false``), or ``None`` if the tag
    is not present in the control.
    """
    pattern = re.compile(
        rf"^\s*tag\s+['\"]{re.escape(tag_name)}['\"]\s*:\s*(.+?)\s*$",
        re.MULTILINE,
    )
    match = pattern.search(rb_content)
    if match:
        return match.group(1).strip()
    return None


def extract_check_text(rb_content):
    """Extract the verbatim body of the 12c ``check`` tag (without quotes)."""
    match = re.search(
        r'tag\s+["\']check["\']\s*:\s*"(.+?)"(?=\s*\n\s*(?:tag|sql|describe|\Z))',
        rb_content,
        re.DOTALL,
    )
    if match:
        return match.group(1)
    return ""


def extract_ruby_code(rb_content):
    """Extract the Ruby check logic (everything from ``sql =`` up to the final ``end``).

    Returns the code block as a string, or ``None`` if no ``sql =`` line is found.
    """
    match = re.search(r'\n(\s*sql\s*=\s*oracledb_session.*?)\nend\s*\Z',
                      rb_content, re.DOTALL)
    if match:
        return match.group(1).rstrip()
    return None


def escape_ruby_dq(text):
    """Escape a string for use inside a Ruby double-quoted literal."""
    if text is None:
        return ""
    text = text.replace('\\', '\\\\')
    text = text.replace('"', '\\"')
    return text


def format_desc(text, wrap_width=80):
    """Format the ``desc`` body to match the fixture style.

    The first line begins on the same line as ``desc "`` (which contributes a
    6-character prefix: 2-space indent + ``desc "``). Continuation lines are
    indented 6 spaces, word-wrapped at ``wrap_width``. Paragraph breaks
    (``\\n\\n``) are preserved.
    """
    if not text:
        return ""
    prefix_len = len('  desc "')
    paragraphs = text.split('\n\n')
    out_paras = []
    for para in paragraphs:
        para = para.replace('\n', ' ').strip()
        # Account for the `  desc "` prefix on the first line by initially
        # indenting that many spaces, then stripping them back off.
        wrapped = textwrap.fill(
            para,
            width=wrap_width,
            initial_indent=' ' * prefix_len,
            subsequent_indent='      ',
            break_long_words=False,
            break_on_hyphens=False,
        )
        wrapped = wrapped[prefix_len:]
        out_paras.append(wrapped)
    return '\n\n'.join(out_paras)


def format_check_body(text):
    """Format a multi-line check/12c_check body to match the fixture style.

    The first line follows the opening quote directly; every subsequent
    non-empty line is indented 2 spaces. Blank lines are preserved verbatim.
    Original line breaks from the source are retained.
    """
    if not text:
        return ""
    lines = text.split('\n')
    out = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if i == 0:
            out.append(stripped)
        elif stripped == '':
            out.append('')
        else:
            out.append('  ' + stripped)
    return '\n'.join(out)


def find_all_matches(title_19c, control_files_12c):
    """Find all 12c controls scored by title similarity, sorted descending."""
    matches = []
    for file_12c in control_files_12c:
        content_12c = Path(file_12c).read_text()
        title_12c = extract_title_from_rb(content_12c)
        if title_12c:
            matches.append({
                'file': Path(file_12c),
                'group_id': Path(file_12c).stem,
                'title': title_12c,
                'score': similarity(title_19c, title_12c),
                'content': content_12c,
            })
    matches.sort(key=lambda x: x['score'], reverse=True)
    return matches


def severity_to_impact(severity):
    """Map a STIG severity string to an InSpec impact value."""
    return SEVERITY_TO_IMPACT.get((severity or '').lower(), 0.0)


def ruby_list_literal(items):
    """Render a Python list of strings as a Ruby array literal."""
    return '[' + ', '.join(f'"{i}"' for i in items) + ']'


def build_control(control_19c, primary, good_matches):
    """Construct the full 19c InSpec control text.

    ``primary`` is the selected 12c match dict (or ``None`` if no match).
    ``good_matches`` is the list of all matches at/above threshold.
    """
    group_id = control_19c['groupId']
    impact = severity_to_impact(control_19c.get('ruleSeverity'))

    # rule_title with any trailing period stripped (matches fixture convention).
    rule_title = control_19c['ruleTitle'].rstrip('.')

    # Carry-over tags from the primary 12c match.
    carryover = {}
    if primary:
        for name in CARRYOVER_TAGS:
            val = extract_tag_value(primary['content'], name)
            if val is not None:
                carryover[name] = val

    nist_val = carryover.get('nist', "['CM-6 b', 'Rev_4']")
    stig_id_val = carryover.get('stig_id', "'O121-BP-021300'")

    # All matches at/above threshold listed in 12c_matches.
    matches_ids = [m['group_id'] for m in good_matches] if good_matches else []

    # 12c check text and Ruby code from the primary match.
    check_12c = extract_check_text(primary['content']) if primary else ""
    ruby_code = extract_ruby_code(primary['content']) if primary else None

    # Description: indented/wrapped vuln discussion (escape first, then layout).
    desc = format_desc(escape_ruby_dq(control_19c.get('ruleVulnDiscussion', '')))

    lines = []
    lines.append(f"control '{group_id}' do")
    lines.append(f'  title "{escape_ruby_dq(control_19c["ruleTitle"])}"')
    lines.append(f'  desc "{desc}"')
    lines.append(f'  impact {impact}')
    lines.append(f"  tag 'benchmark_id': {control_19c.get('benchmarkId')}")
    lines.append(f"  tag 'title': '{control_19c['title']}'")
    lines.append(f"  tag 'rule_title': '{rule_title}'")
    lines.append(f"  tag 'group_id': '{group_id}'")
    lines.append(f"  tag 'rule_id': '{control_19c['ruleId']}'")
    lines.append(f"  tag 'rule_weight': \"{control_19c.get('ruleWeight')}\"")
    lines.append(f"  tag 'rule_severity': '{control_19c.get('ruleSeverity')}'")
    lines.append(f'  tag "rule_version": "{control_19c.get("ruleVersion")}"')
    lines.append(f'  tag "stig_id": {stig_id_val}')
    lines.append(f"  tag 'fix_id': '{control_19c['ruleFixId']}'")
    lines.append(f'  tag "rule_ident": [\'{control_19c.get("ruleIdent")}\']')
    lines.append(f'  tag "nist": {nist_val} # from 12c control')
    lines.append(f'  tag "false_negatives": {carryover.get("false_negatives", "nil")}')
    lines.append(f'  tag "false_positives": {carryover.get("false_positives", "nil")}')
    lines.append(f'  tag "documentable": {carryover.get("documentable", "false")}')
    lines.append(f'  tag "mitigations": {carryover.get("mitigations", "nil")}')
    lines.append(f'  tag "severity_override_guidance": {carryover.get("severity_override_guidance", "false")}')
    lines.append(f'  tag "potential_impacts": {carryover.get("potential_impacts", "nil")}')
    lines.append(f'  tag "third_party_tools": {carryover.get("third_party_tools", "nil")}')
    lines.append(f'  tag "mitigation_controls": {carryover.get("mitigation_controls", "nil")}')
    lines.append(f'  tag "responsibility": {carryover.get("responsibility", "nil")}')
    lines.append(f'  tag "ia_controls": {carryover.get("ia_controls", "nil")}')
    lines.append(f'  tag "rule_vuln_discussion": "{escape_ruby_dq(control_19c.get("ruleVulnDiscussion", ""))}"')
    lines.append(f'  tag "fix": "{escape_ruby_dq(control_19c.get("ruleFixText", ""))}"')
    lines.append(f'  tag "rule_fix_id": "{control_19c["ruleFixId"]}"')
    lines.append(f'  tag "rule_check_system": "{control_19c.get("ruleCheckSystem", "")}"')
    lines.append(f'  tag "12c_matches": {ruby_list_literal(matches_ids)}')
    lines.append(f'  tag "12c_match_threshold": {MATCH_THRESHOLD}')
    lines.append('')
    lines.append(f'  tag "12c_check": "{format_check_body(check_12c)}"')
    lines.append('')
    lines.append(f'  tag "check": "{format_check_body(escape_ruby_dq(control_19c.get("ruleCheckContent", "")))}"')
    lines.append('')
    lines.append('')

    # Note whether the check content changed from 12c to 19c.
    check_changed = (
        format_check_body(check_12c).strip()
        != format_check_body(escape_ruby_dq(control_19c.get('ruleCheckContent', ''))).strip()
    )
    if check_changed:
        lines.append('  # NOTE: Check content has changed from 12c to 19c - Ruby code may need to be updated')

    if ruby_code is not None:
        lines.append(ruby_code)
    else:
        lines.append('  # NOTE: No matching 12c control found - check logic must be written manually')
        lines.append('  describe \'Manual review required\' do')
        lines.append('    skip \'No matching 12c control; implement check logic.\'')
        lines.append('  end')

    lines.append('')
    lines.append('end')
    lines.append('')

    return '\n'.join(lines), check_changed


def process_control(control_19c, control_files_12c, output_dir):
    """Find matches, build, and write a single 19c control file."""
    group_id = control_19c['groupId']
    title_19c = control_19c['ruleTitle']

    matches = find_all_matches(title_19c, control_files_12c)
    good_matches = [m for m in matches if m['score'] >= MATCH_THRESHOLD]
    primary = good_matches[0] if good_matches else None

    content, check_changed = build_control(control_19c, primary, good_matches)

    output_path = output_dir / f"{group_id}.rb"
    output_path.write_text(content)

    return {
        'group_id': group_id,
        'primary': primary['group_id'] if primary else None,
        'primary_score': primary['score'] if primary else (matches[0]['score'] if matches else 0.0),
        'all_matches': [m['group_id'] for m in good_matches],
        'check_changed': check_changed,
        'output_path': output_path,
    }


def main():
    parser = argparse.ArgumentParser(
        description='Migrate Oracle 12c InSpec controls to 19c format.'
    )
    parser.add_argument(
        '--stig-json',
        default='fixtures/19c_sample_stig.json',
        help='Path to the 19c STIG JSON export (default: fixtures/19c_sample_stig.json).',
    )
    parser.add_argument(
        '--controls-12c',
        default='12c_controls',
        help='Directory containing the 12c InSpec control .rb files.',
    )
    parser.add_argument(
        '--output-dir',
        default='19c_controls',
        help='Directory to write generated 19c controls into.',
    )
    parser.add_argument(
        '--group-ids',
        nargs='*',
        default=None,
        help='Optional list of 19c group IDs to limit processing to.',
    )
    args = parser.parse_args()

    stig_json = Path(args.stig_json)
    controls_12c_dir = Path(args.controls_12c)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    data_19c = json.loads(stig_json.read_text())
    controls_19c = data_19c['groups']
    # Propagate the benchmark id onto each group for tag emission.
    benchmark_id = data_19c.get('benchmarkId') or data_19c.get('id')
    for g in controls_19c:
        g.setdefault('benchmarkId', benchmark_id)

    if args.group_ids:
        controls_19c = [g for g in controls_19c if g['groupId'] in args.group_ids]

    control_files_12c = sorted(controls_12c_dir.glob('*.rb'))

    print(f"Loaded {len(controls_19c)} Oracle 19c control(s)")
    print(f"Found {len(control_files_12c)} Oracle 12c control files")
    print()

    matched = []
    no_match = []

    for idx, control_19c in enumerate(controls_19c, 1):
        group_id = control_19c['groupId']
        print(f"[{idx}/{len(controls_19c)}] Processing {group_id}...")

        result = process_control(control_19c, control_files_12c, output_dir)

        if result['primary']:
            extra = result['all_matches'][1:]
            extra_note = f" (+{len(extra)} other match(es): {extra})" if extra else ""
            changed = " [CHECK CHANGED]" if result['check_changed'] else ""
            print(f"  ✓ Matched to {result['primary']} "
                  f"(score: {result['primary_score']:.2f}){extra_note}{changed}")
            matched.append(result)
        else:
            print(f"  ✗ No match >= {MATCH_THRESHOLD:.2f} "
                  f"(best: {result['primary_score']:.2f})")
            no_match.append(result)

    print()
    print("=" * 80)
    print("MIGRATION SUMMARY")
    print("=" * 80)
    print(f"Total processed:   {len(controls_19c)}")
    print(f"Matched:           {len(matched)}")
    print(f"No match found:    {len(no_match)}")
    print(f"Check content changed: {sum(1 for m in matched if m['check_changed'])}")
    print(f"Output directory:  {output_dir.resolve()}")


if __name__ == '__main__':
    main()
