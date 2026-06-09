#!/usr/bin/env python3
"""
Migrate Oracle 12c InSpec controls to Oracle 19c format (Version 2).

This script iterates through 19c controls and finds matching 12c controls,
with interactive selection for ambiguous matches.
"""

import json
import os
import re
from pathlib import Path
from difflib import SequenceMatcher
import shutil


def similarity(a, b):
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def extract_title_from_rb(rb_content):
    """Extract the title field from a Ruby control file."""
    # Look for: title "..." or title 'title "...'
    match = re.search(r"title\s+['\"](.+?)['\"]", rb_content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def find_all_matches(title_19c, control_files_12c):
    """Find all matching 12c controls for a 19c title."""
    matches = []
    
    for file_12c in control_files_12c:
        with open(file_12c, 'r') as f:
            content_12c = f.read()
        
        title_12c = extract_title_from_rb(content_12c)
        if title_12c:
            score = similarity(title_19c, title_12c)
            matches.append({
                'file': file_12c,
                'title': title_12c,
                'score': score,
                'content': content_12c
            })
    
    # Sort by score descending
    matches.sort(key=lambda x: x['score'], reverse=True)
    return matches


def escape_ruby_string(text):
    """Escape special characters in a string for Ruby."""
    if text is None:
        return ""
    # Escape backslashes and quotes
    text = text.replace('\\', '\\\\')
    text = text.replace('"', '\\"')
    return text


def extract_tags_section(rb_content):
    """Extract all tag lines from the control file."""
    tags = {}
    tag_pattern = re.compile(r"^\s*tag\s+['\"](\w+)['\"]\s*:\s*(.+?)$", re.MULTILINE)
    
    for match in tag_pattern.finditer(rb_content):
        tag_name = match.group(1)
        tag_value = match.group(2).strip()
        tags[tag_name] = tag_value
    
    return tags


def update_control_file(file_path_12c, control_19c, output_dir):
    """Update a 12c control file with 19c metadata and save to output directory."""
    with open(file_path_12c, 'r') as f:
        content = f.read()
    
    # Extract the current title from 12c file
    title_12c = extract_title_from_rb(content)
    
    # Extract existing tags
    existing_tags = extract_tags_section(content)
    
    # Preserve the 12c check content
    check_12c = existing_tags.get('check', '')
    check_19c = control_19c['ruleCheckContent']
    check_changed = check_12c.strip() != check_19c.strip()
    
    # Update control ID at the top
    old_control_id = re.search(r"control\s+['\"]([^'\"]+)['\"]", content)
    if old_control_id:
        new_control_id = control_19c['groupId']
        content = content.replace(
            f"control '{old_control_id.group(1)}'",
            f"control '{new_control_id}'"
        )
    
    # Update title
    title_19c = escape_ruby_string(control_19c['ruleTitle'])
    content = re.sub(
        r"(title\s+['\"])(.+?)(['\"])",
        f"title \"{title_19c}\"",
        content,
        count=1,
        flags=re.DOTALL
    )
    
    # Update desc
    desc_19c = escape_ruby_string(control_19c['ruleVulnDiscussion'])
    content = re.sub(
        r"(desc\s+['\"])(.+?)(['\"])",
        f"desc \"{desc_19c}\"",
        content,
        count=1,
        flags=re.DOTALL
    )
    
    # Update tags
    # gtitle
    content = re.sub(
        r"(tag\s+['\"]gtitle['\"]:\s*['\"])([^'\"]*?)(['\"])",
        f"tag 'gtitle': '{control_19c['title']}'",
        content
    )
    
    # gid
    content = re.sub(
        r"(tag\s+['\"]gid['\"]:\s*['\"])([^'\"]*?)(['\"])",
        f"tag 'gid': '{control_19c['groupId']}'",
        content
    )
    
    # rid
    content = re.sub(
        r"(tag\s+['\"]rid['\"]:\s*['\"])([^'\"]*?)(['\"])",
        f"tag 'rid': '{control_19c['ruleId']}'",
        content
    )
    
    # fix_id
    content = re.sub(
        r"(tag\s+['\"]fix_id['\"]:\s*['\"])([^'\"]*?)(['\"])",
        f"tag 'fix_id': '{control_19c['ruleFixId']}'",
        content
    )
    
    # Rename the old check tag to check_12c and add new check tag with 19c content
    check_19c_content = escape_ruby_string(control_19c['ruleCheckContent'])
    
    # First, find and rename the existing check tag to check_12c
    # Match: tag "check": "content..." (with potential multiline content)
    check_tag_pattern = r'(tag\s+["\'])check(["\']\s*:\s*["\'])(.+?)(["\'])'
    
    def replace_check_tag(match):
        # Return the renamed check_12c tag preserving the original content
        return f'{match.group(1)}check_12c{match.group(2)}{match.group(3)}{match.group(4)}'
    
    content = re.sub(check_tag_pattern, replace_check_tag, content, count=1, flags=re.DOTALL)
    
    # Then add the new check tag with 19c content right after check_12c
    check_12c_tag_match = re.search(r'(tag\s+["\']check_12c["\']\s*:.*?["\']\s*\n)', content, re.DOTALL)
    if check_12c_tag_match:
        insert_pos = check_12c_tag_match.end()
        indent = '  '  # Standard 2-space indent
        new_check_tag = f'{indent}tag "check": "{check_19c_content}"\n'
        content = content[:insert_pos] + new_check_tag + content[insert_pos:]
    
    # Update fix tag
    fix_content = escape_ruby_string(control_19c['ruleFixText'])
    content = re.sub(
        r"(tag\s+['\"]fix['\"]:\s*['\"])(.+?)(['\"](?:\s*$|\s*sql\s*=))",
        f'tag "fix": "{fix_content}"\\3',
        content,
        flags=re.DOTALL | re.MULTILINE
    )
    
    # Add comment about code changes if check has changed
    if check_changed:
        # Find the Ruby code section (after all tags, before or at the sql = line)
        sql_match = re.search(r'(\n\s*sql\s*=\s*oracledb_session)', content)
        if sql_match:
            insert_pos = sql_match.start() + 1
            comment = "  # NOTE: Check content has changed from 12c to 19c - Ruby code may need to be updated\n"
            content = content[:insert_pos] + comment + content[insert_pos:]
    
    # Write to output directory with new filename
    output_filename = f"{control_19c['groupId']}.rb"
    output_path = os.path.join(output_dir, output_filename)
    
    with open(output_path, 'w') as f:
        f.write(content)
    
    return output_path, check_changed


def interactive_select(control_19c, matches):
    """Prompt user to select from multiple matching 12c controls."""
    print("\n" + "="*80)
    print(f"19c Control: {control_19c['groupId']}")
    print(f"19c Title: {control_19c['ruleTitle']}")
    print("="*80)
    print("\nMultiple possible matches found:")
    print()
    
    for idx, match in enumerate(matches, 1):
        print(f"{idx}. Score: {match['score']:.2f} - {match['file'].name}")
        print(f"   Title: {match['title'][:100]}...")
        print()
    
    print(f"{len(matches) + 1}. SKIP - No match found")
    print()
    
    while True:
        try:
            choice = input(f"Select option (1-{len(matches) + 1}): ").strip()
            choice_num = int(choice)
            if 1 <= choice_num <= len(matches) + 1:
                if choice_num == len(matches) + 1:
                    return None  # Skip
                return matches[choice_num - 1]
            else:
                print(f"Please enter a number between 1 and {len(matches) + 1}")
        except ValueError:
            print("Please enter a valid number")
        except KeyboardInterrupt:
            print("\n\nAborted by user")
            exit(1)


def main():
    # Paths
    controls_12c_dir = Path('./12c-controls')
    controls_19c_json = Path('./oracle_database_19c_stig_controls.json')
    output_dir = Path('./controls')
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(exist_ok=True)
    
    # Load 19c controls
    with open(controls_19c_json) as f:
        data_19c = json.load(f)
        controls_19c = data_19c['groups']
    
    print(f"Loaded {len(controls_19c)} Oracle 19c controls")
    
    # Load all 12c control files
    control_files_12c = sorted(controls_12c_dir.glob('*.rb'))
    print(f"Found {len(control_files_12c)} Oracle 12c control files")
    print()
    
    # Statistics
    matched_auto = []  # Auto-matched (score >= 90%)
    matched_interactive = []  # Interactively selected
    no_match = []  # No matches found
    
    # Process each 19c control
    target_group_ids = ['V-270589', 'V-270521'] # Only run for these specific controls
    for idx, control_19c in enumerate(controls_19c, 1):
        group_id = control_19c['groupId']
        # Skip if not in target_group_ids
        if group_id not in target_group_ids:
            continue
        title_19c = control_19c['ruleTitle']
        
        print(f"[{idx}/{len(controls_19c)}] Processing {group_id}...")
        
        # Find all matches
        matches = find_all_matches(title_19c, control_files_12c)
        
        # Filter matches above threshold (60% or higher)
        good_matches = [m for m in matches if m['score'] >= 0.60]
        
        selected_match = None
        match_type = None
        
        if len(good_matches) == 1:
            # Auto-select single high-confidence match
            selected_match = good_matches[0]
            match_type = 'auto'
            print(f"  ✓ Auto-matched to {selected_match['file'].name} (score: {selected_match['score']:.2f})")
            
        elif len(good_matches) > 1:
            # Interactive selection for multiple candidates
            selected_match = interactive_select(control_19c, good_matches[:10])  # Show top 10
            match_type = 'interactive'
            if selected_match:
                print(f"  ✓ Selected {selected_match['file'].name} (score: {selected_match['score']:.2f})")
            else:
                print(f"  ✗ Skipped - no match")
        
        else:
            # No matches found above threshold
            print(f"  ✗ No matches found (best score: {matches[0]['score']:.2f} - {matches[0]['file'].name})")
        
        # Update control file if we have a match
        if selected_match:
            output_path, check_changed = update_control_file(
                selected_match['file'],
                control_19c,
                output_dir
            )
            
            result = {
                'group_id_19c': group_id,
                'file_12c': selected_match['file'].name,
                'score': selected_match['score'],
                'check_changed': check_changed,
                'match_type': match_type
            }
            
            if match_type == 'auto':
                matched_auto.append(result)
            else:
                matched_interactive.append(result)
        else:
            no_match.append({
                'group_id_19c': group_id,
                'title_19c': title_19c,
                'best_score': matches[0]['score'] if matches else 0.0,
                'best_match': matches[0]['file'].name if matches else 'None'
            })
    
    # Summary
    print("\n" + "="*80)
    print("MIGRATION SUMMARY")
    print("="*80)
    print(f"Total 19c controls processed: {len(controls_19c)}")
    print(f"Auto-matched (single match >= 60%): {len(matched_auto)}")
    print(f"Interactively matched (multiple matches >= 60%): {len(matched_interactive)}")
    print(f"No match found (< 60% threshold): {len(no_match)}")
    print(f"Output directory: {output_dir.absolute()}")
    
    # Count check changes
    total_matched = matched_auto + matched_interactive
    check_changes = sum(1 for m in total_matched if m['check_changed'])
    print(f"Controls with check changes: {check_changes}")
    
    # Write detailed report
    report_path = output_dir / 'migration_report_v2.txt'
    with open(report_path, 'w') as f:
        f.write("Oracle 12c to 19c Control Migration Report (Version 2)\n")
        f.write("="*80 + "\n\n")
        
        f.write("AUTO-MATCHED CONTROLS (single match >= 60%)\n")
        f.write("-"*80 + "\n")
        for m in matched_auto:
            status = " [CHECK CHANGED]" if m['check_changed'] else ""
            f.write(f"{m['group_id_19c']:15s} <- {m['file_12c']:30s} (score: {m['score']:.2f}){status}\n")
        
        f.write("\n\nINTERACTIVELY MATCHED CONTROLS (multiple matches >= 60%)\n")
        f.write("-"*80 + "\n")
        for m in matched_interactive:
            status = " [CHECK CHANGED]" if m['check_changed'] else ""
            f.write(f"{m['group_id_19c']:15s} <- {m['file_12c']:30s} (score: {m['score']:.2f}){status}\n")
        
        f.write("\n\nNO MATCH FOUND\n")
        f.write("-"*80 + "\n")
        for m in no_match:
            f.write(f"{m['group_id_19c']:15s} - {m['title_19c'][:60]}\n")
            f.write(f"  Best candidate: {m['best_match']} (score: {m['best_score']:.2f})\n\n")
    
    print(f"\nDetailed report written to: {report_path.absolute()}")
    
    if check_changes > 0:
        print("\n⚠️  IMPORTANT: Review controls marked with [CHECK CHANGED] - Ruby code may need updates!")


if __name__ == '__main__':
    main()
