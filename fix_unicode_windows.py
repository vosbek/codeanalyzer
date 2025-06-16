#!/usr/bin/env python3
"""
Fix Unicode characters for Windows compatibility
"""

import re

def fix_unicode_in_file(filepath):
    """Replace Unicode emojis with ASCII equivalents"""
    
    # Read the file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Unicode replacements for Windows compatibility
    replacements = {
        '✅': '[PASS]',
        '❌': '[FAIL]', 
        '🎉': '[EXCELLENT]',
        '⚠️': '[WARNING]',
        '📊': '[INFO]',
        '🔍': '[TESTING]',
        '🧪': '[TEST]',
        '🎯': '[TARGET]',
        '📈': '[STATS]',
        '📌': '[NOTE]',
        '📁': '[FILES]',
        '💾': '[SAVE]',
        '⚡': '[FAST]',
        '🔗': '[LINK]',
        '🔒': '[SECURE]',
        '📄': '[DOC]',
        '•': '*',
        '🔧': '[FIX]',
        '💡': '[TIP]'
    }
    
    # Apply replacements
    for unicode_char, replacement in replacements.items():
        content = content.replace(unicode_char, replacement)
    
    # Write back the file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed Unicode characters in {filepath}")

if __name__ == "__main__":
    files_to_fix = [
        'test_enhanced_java_analysis.py',
        'test_corba_detection.py',
        'diagnose_windows_issues.py'
    ]
    
    for filename in files_to_fix:
        try:
            fix_unicode_in_file(filename)
        except FileNotFoundError:
            print(f"File not found: {filename}")
        except Exception as e:
            print(f"Error fixing {filename}: {e}")
    
    print("Unicode fix complete!")