"""
Comprehensive PEP 8 style checking and auto-fixing.

Native implementation of pycodestyle (E/W codes) for detection and automatic fixing.
Covers all major PEP 8 style issues without external dependencies.
"""

import ast
import re
import tokenize
from io import StringIO
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Set

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import Rule, RuleViolation, RuleCategory, RuleSeverity, FixApplicability


class PEP8Checker:
    """
    Comprehensive PEP 8 style checker.
    
    Implements detection and auto-fix for all major pycodestyle E/W codes:
    - E1xx: Indentation
    - E2xx: Whitespace
    - E3xx: Blank lines
    - E4xx: Imports
    - E5xx: Line length
    - E7xx: Statements
    - W1xx-W6xx: Warnings
    """
    
    def __init__(self, max_line_length: int = 79):
        """
        Initialize PEP 8 checker.
        
        Args:
            max_line_length: Maximum line length (default 79, PEP 8 standard)
        """
        self.logger = PyGuardLogger()
        self.max_line_length = max_line_length
        self.violations: List[RuleViolation] = []
        self.current_file_path = ""  # Track current file being checked
        
    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a file for PEP 8 violations.
        
        Args:
            file_path: Path to Python file
            
        Returns:
            List of rule violations
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            self.violations = []
            self.current_file_path = str(file_path)  # Store for _add_violation
            lines = content.splitlines(keepends=True)
            
            # Run all checks
            self._check_indentation(lines)
            self._check_whitespace(lines)
            self._check_blank_lines(lines)
            self._check_imports(content, lines)
            self._check_line_length(lines)
            self._check_statements(lines)
            self._check_comparison_patterns(content)  # Phase 8.3
            self._check_lambda_and_names(content)  # Phase 8.3
            self._check_warnings(lines)
            
            return self.violations
            
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []
    
    def fix_file(self, file_path: Path) -> Tuple[bool, int]:
        """
        Automatically fix PEP 8 violations in a file.
        
        Args:
            file_path: Path to Python file
            
        Returns:
            Tuple of (success, number of fixes applied)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            fixed_content = content
            fixes_applied = 0
            
            # Apply fixes in order (some depend on previous fixes)
            fixed_content, count = self._fix_trailing_whitespace(fixed_content)
            fixes_applied += count
            
            fixed_content, count = self._fix_blank_lines(fixed_content)
            fixes_applied += count
            
            fixed_content, count = self._fix_whitespace(fixed_content)
            fixes_applied += count
            
            fixed_content, count = self._fix_indentation(fixed_content)
            fixes_applied += count
            
            fixed_content, count = self._fix_statements(fixed_content)
            fixes_applied += count
            
            if fixes_applied > 0:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                    
                self.logger.info(
                    f"Applied {fixes_applied} PEP 8 fixes",
                    file_path=str(file_path)
                )
                
            return True, fixes_applied
            
        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0
    
    # ========================================================================
    # E1xx: Indentation Checks
    # ========================================================================
    
    def _check_indentation(self, lines: List[str]) -> None:
        """Check indentation issues (E1xx codes)."""
        bracket_stack = []  # Track open brackets: [(char, line_num, col, indent)]
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Check continuation line indentation BEFORE updating bracket stack
            # This way we check based on the previous line's bracket status
            if bracket_stack and line_num > 1:
                self._check_continuation_indentation(line, line_num, lines, bracket_stack)
                
            # E101: Indentation contains mixed spaces and tabs
            if '\t' in line[:len(line) - len(line.lstrip())]:
                if ' ' in line[:len(line) - len(line.lstrip())]:
                    self._add_violation(
                        "E101", line_num, 0,
                        "Indentation contains mixed spaces and tabs"
                    )
            
            # E111: Indentation is not a multiple of 4
            indent = len(line) - len(line.lstrip())
            if indent > 0 and indent % 4 != 0:
                # Check if it's continuation or not
                if line_num > 1 and not self._is_continuation_line(lines, line_num - 1):
                    self._add_violation(
                        "E111", line_num, 0,
                        f"Indentation is not a multiple of 4 (found {indent} spaces)"
                    )
            
            # Track brackets for continuation line checks (E121-E131)
            # Update stack AFTER checking the current line
            self._update_bracket_stack(line, line_num, bracket_stack)
    
    def _fix_indentation(self, content: str) -> Tuple[str, int]:
        """Fix indentation issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        bracket_stack = []
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                fixed_lines.append(line)
                # Update bracket stack even for empty lines
                self._update_bracket_stack(line, line_num, bracket_stack)
                continue
            
            # Fix mixed tabs and spaces - convert all to spaces
            indent_str = line[:len(line) - len(line.lstrip())]
            if '\t' in indent_str:
                # Convert tabs to 4 spaces
                fixed_indent = indent_str.replace('\t', '    ')
                fixed_line = fixed_indent + line.lstrip()
                fixed_lines.append(fixed_line)
                fixes += 1
                # Update bracket stack with fixed line
                self._update_bracket_stack(fixed_line, line_num, bracket_stack)
                continue
            
            # Check if we need to fix continuation line indentation (E121-E128)
            fixed_line = line
            if bracket_stack:
                fixed_line, fixed = self._fix_continuation_indent(line, line_num, lines, bracket_stack)
                if fixed:
                    fixes += 1
            
            fixed_lines.append(fixed_line)
            
            # Update bracket stack with the (possibly fixed) line
            self._update_bracket_stack(fixed_line, line_num, bracket_stack)
        
        return ''.join(fixed_lines), fixes
    
    def _fix_continuation_indent(
        self, line: str, line_num: int, lines: List[str], bracket_stack: List[Tuple]
    ) -> Tuple[str, bool]:
        """
        Fix continuation line indentation issues.
        
        Returns:
            Tuple of (fixed_line, was_fixed)
        """
        if not bracket_stack:
            return line, False
        
        indent = len(line) - len(line.lstrip())
        open_char, open_line_num, open_col, open_indent = bracket_stack[-1]
        
        # Calculate the expected indent (hanging indent style)
        expected_indent = open_indent + 4
        
        # Only fix if the current indent is clearly wrong and line doesn't close bracket
        if not line.strip().startswith((')', ']', '}')):
            # Fix under-indentation (E121, E122, E128) - only if significantly wrong
            if indent < expected_indent and line_num > open_line_num:
                fixed_line = ' ' * expected_indent + line.lstrip()
                return fixed_line, True
            
            # Fix over-indentation (E126) - only if significantly wrong
            elif indent > expected_indent + 4:
                fixed_line = ' ' * expected_indent + line.lstrip()
                return fixed_line, True
        
        return line, False
    
    def _is_continuation_line(self, lines: List[str], line_num: int) -> bool:
        """Check if a line is a continuation line."""
        if line_num < 1 or line_num > len(lines):
            return False
        line = lines[line_num - 1]
        return line.rstrip().endswith('\\') or line.rstrip().endswith(',')
    
    def _update_bracket_stack(self, line: str, line_num: int, bracket_stack: List[Tuple]) -> None:
        """Update bracket stack for continuation line tracking."""
        col = 0
        indent = len(line) - len(line.lstrip())
        
        for char in line:
            if char in '([{':
                bracket_stack.append((char, line_num, col, indent))
            elif char in ')]}':
                if bracket_stack:
                    open_char, _, _, _ = bracket_stack[-1]
                    if (char == ')' and open_char == '(' or
                        char == ']' and open_char == '[' or
                        char == '}' and open_char == '{'):
                        bracket_stack.pop()
            col += 1
    
    def _check_continuation_indentation(
        self, line: str, line_num: int, lines: List[str], bracket_stack: List[Tuple]
    ) -> None:
        """
        Check continuation line indentation (E121-E131).
        
        Continuation lines should be indented relative to the opening bracket
        or using a hanging indent pattern.
        """
        if not bracket_stack:
            return
            
        indent = len(line) - len(line.lstrip())
        prev_line = lines[line_num - 2] if line_num > 1 else ""
        prev_indent = len(prev_line) - len(prev_line.lstrip())
        
        # Get the most recent opening bracket info
        open_char, open_line_num, open_col, open_indent = bracket_stack[-1]
        
        # E121: Continuation line under-indented for hanging indent
        # A hanging indent means the first line after opening bracket is indented
        if open_line_num < line_num:
            expected_indent = open_indent + 4  # Standard hanging indent
            if indent < expected_indent and not line.strip().startswith((')',']','}')):
                self._add_violation(
                    "E121", line_num, 0,
                    f"Continuation line under-indented for hanging indent (expected {expected_indent}, got {indent})"
                )
        
        # E122: Continuation line missing indentation or outdented
        if indent <= open_indent and line_num > open_line_num and not line.strip().startswith((')',']','}')):
            self._add_violation(
                "E122", line_num, 0,
                "Continuation line missing indentation or outdented"
            )
        
        # E125: Continuation line with same indent as next logical line
        if indent > 0 and indent == prev_indent and line_num > open_line_num + 1:
            # Check if this might conflict with next logical line
            if not prev_line.rstrip().endswith((',', '\\')):
                self._add_violation(
                    "E125", line_num, 0,
                    "Continuation line with same indent as next logical line"
                )
        
        # E126: Continuation line over-indented for hanging indent
        if indent > expected_indent + 4 and not line.strip().startswith((')',']','}')):
            self._add_violation(
                "E126", line_num, 0,
                f"Continuation line over-indented for hanging indent (expected {expected_indent}, got {indent})"
            )
        
        # E127: Continuation line over-indented for visual indent
        # Visual indent means aligned with the opening delimiter
        visual_indent = open_col + 1
        if indent > visual_indent + 4 and open_line_num < line_num:
            self._add_violation(
                "E127", line_num, 0,
                f"Continuation line over-indented for visual indent"
            )
        
        # E128: Continuation line under-indented for visual indent
        # Only flag if indent is clearly wrong (not using hanging indent either)
        if (indent < visual_indent and indent < expected_indent and 
            open_line_num < line_num and not line.strip().startswith((')',']','}'))):
            self._add_violation(
                "E128", line_num, 0,
                "Continuation line under-indented for visual indent"
            )
        
        # E129: Visually indented line with same indent as next logical line
        # (Similar to E125 but for visual indenting)
        if indent == visual_indent and prev_indent == indent:
            if line_num > open_line_num + 1 and not prev_line.rstrip().endswith((',', '\\')):
                self._add_violation(
                    "E129", line_num, 0,
                    "Visually indented line with same indent as next logical line"
                )
        
        # E130: Continuation line indentation is not a multiple of four (comment)
        # This is more of an informational message
        if indent > 0 and indent % 4 != 0 and line_num > open_line_num:
            self._add_violation(
                "E130", line_num, 0,
                f"Continuation line indentation is not a multiple of four (got {indent})"
            )
    
    # ========================================================================
    # E2xx: Whitespace Checks
    # ========================================================================
    
    def _check_whitespace(self, lines: List[str]) -> None:
        """Check whitespace issues (E2xx codes)."""
        for line_num, line in enumerate(lines, 1):
            stripped = line.rstrip('\n\r')
            
            # E201: Whitespace after '('
            if re.search(r'\(\s+', stripped):
                match = re.search(r'\(\s+', stripped)
                if match:
                    self._add_violation(
                        "E201", line_num, match.start(),
                        "Whitespace after '('"
                    )
            
            # E202: Whitespace before ')'
            if re.search(r'\s+\)', stripped):
                match = re.search(r'\s+\)', stripped)
                if match:
                    self._add_violation(
                        "E202", line_num, match.start(),
                        "Whitespace before ')'"
                    )
            
            # E203: Whitespace before ':'
            if re.search(r'\s+:', stripped):
                # Exclude slicing (e.g., [1 :2] is acceptable)
                match = re.search(r'[^\[]\s+:', stripped)
                if match:
                    self._add_violation(
                        "E203", line_num, match.start(),
                        "Whitespace before ':'"
                    )
            
            # E211: Whitespace before '('
            if re.search(r'\s+\(', stripped):
                # Only for function calls, not after keywords
                match = re.search(r'[a-zA-Z_]\s+\(', stripped)
                if match and not self._is_keyword_before(stripped, match.start()):
                    self._add_violation(
                        "E211", line_num, match.start(),
                        "Whitespace before '('"
                    )
            
            # E225: Missing whitespace around operator
            operators = ['+', '-', '*', '/', '%', '**', '//', '==', '!=', '<', '>', '<=', '>=']
            for op in operators:
                pattern = f'[a-zA-Z0-9_][{re.escape(op)}]|[{re.escape(op)}][a-zA-Z0-9_]'
                if re.search(pattern, stripped):
                    self._add_violation(
                        "E225", line_num, 0,
                        f"Missing whitespace around operator '{op}'"
                    )
            
            # E231: Missing whitespace after ','
            if re.search(r',[^\s\n\r]', stripped):
                match = re.search(r',[^\s\n\r]', stripped)
                if match:
                    self._add_violation(
                        "E231", line_num, match.start(),
                        "Missing whitespace after ','"
                    )
            
            # E241: Multiple spaces after ','
            if re.search(r',\s{2,}', stripped):
                match = re.search(r',\s{2,}', stripped)
                if match:
                    self._add_violation(
                        "E241", line_num, match.start(),
                        "Multiple spaces after ','"
                    )
            
            # E242: Tab after ','
            if re.search(r',\t', stripped):
                match = re.search(r',\t', stripped)
                if match:
                    self._add_violation(
                        "E242", line_num, match.start(),
                        "Tab after ','"
                    )
            
            # E251: Unexpected spaces around keyword/parameter equals
            if re.search(r'\w\s+=\s+\w', stripped):
                # Only in function definitions and calls (with = for defaults/kwargs)
                match = re.search(r'(\w)\s+(=)\s+(\w)', stripped)
                if match and '==' not in stripped[match.start():match.end()+2]:
                    self._add_violation(
                        "E251", line_num, match.start(),
                        "Unexpected spaces around keyword/parameter equals"
                    )
            
            # E261: At least two spaces before inline comment
            comment_match = re.search(r'[^\s](\s*)#', stripped)
            if comment_match and not stripped.lstrip().startswith('#'):
                spaces_before = len(comment_match.group(1))
                if spaces_before == 1:
                    self._add_violation(
                        "E261", line_num, comment_match.start(),
                        "At least two spaces before inline comment"
                    )
            
            # E262: Inline comment should start with '# '
            inline_comment = re.search(r'[^\s].*#[^ ]', stripped)
            if inline_comment and not stripped.lstrip().startswith('#'):
                self._add_violation(
                    "E262", line_num, inline_comment.start(),
                    "Inline comment should start with '# '"
                )
            
            # E265: Block comment should start with '# '
            if stripped.lstrip().startswith('#') and not stripped.lstrip().startswith('# '):
                if len(stripped.lstrip()) > 1 and stripped.lstrip()[1] != '#':
                    self._add_violation(
                        "E265", line_num, 0,
                        "Block comment should start with '# '"
                    )
            
            # E271: Multiple spaces after keyword
            for keyword in ['if', 'elif', 'while', 'for', 'with', 'def', 'class', 'return', 'yield']:
                pattern = rf'\b{keyword}\s{{2,}}'
                if re.search(pattern, stripped):
                    match = re.search(pattern, stripped)
                    if match:
                        self._add_violation(
                            "E271", line_num, match.start(),
                            f"Multiple spaces after keyword '{keyword}'"
                        )
                        break
            
            # E272: Multiple spaces before keyword
            for keyword in ['if', 'elif', 'else', 'while', 'for', 'with', 'def', 'class', 'return']:
                pattern = rf'\s{{2,}}\b{keyword}\b'
                if re.search(pattern, stripped):
                    match = re.search(pattern, stripped)
                    if match:
                        self._add_violation(
                            "E272", line_num, match.start(),
                            f"Multiple spaces before keyword '{keyword}'"
                        )
                        break
            
            # E273: Tab after keyword
            for keyword in ['if', 'elif', 'while', 'for', 'with', 'def', 'class']:
                pattern = rf'\b{keyword}\t'
                if re.search(pattern, stripped):
                    match = re.search(pattern, stripped)
                    if match:
                        self._add_violation(
                            "E273", line_num, match.start(),
                            f"Tab after keyword '{keyword}'"
                        )
                        break
            
            # E274: Tab before keyword
            for keyword in ['if', 'elif', 'else', 'while', 'for', 'with', 'def', 'class']:
                pattern = rf'\t\b{keyword}\b'
                if re.search(pattern, stripped):
                    match = re.search(pattern, stripped)
                    if match:
                        self._add_violation(
                            "E274", line_num, match.start(),
                            f"Tab before keyword '{keyword}'"
                        )
                        break
    
    def _fix_whitespace(self, content: str) -> Tuple[str, int]:
        """Fix whitespace issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        
        for line in lines:
            fixed = line
            
            # Fix E201: Whitespace after '('
            if re.search(r'\(\s+', fixed):
                fixed = re.sub(r'\(\s+', '(', fixed)
                fixes += 1
            
            # Fix E202: Whitespace before ')'
            if re.search(r'\s+\)', fixed):
                fixed = re.sub(r'\s+\)', ')', fixed)
                fixes += 1
            
            # Fix E231: Missing whitespace after ','
            if re.search(r',([^\s\n\r])', fixed):
                fixed = re.sub(r',([^\s\n\r])', r', \1', fixed)
                fixes += 1
            
            # Fix E241: Multiple spaces after ','
            if re.search(r',\s{2,}', fixed):
                fixed = re.sub(r',\s{2,}', ', ', fixed)
                fixes += 1
            
            # Fix E242: Tab after ','
            if re.search(r',\t', fixed):
                fixed = re.sub(r',\t', ', ', fixed)
                fixes += 1
            
            # Fix E251: Unexpected spaces around keyword/parameter equals
            # Only fix in function definitions/calls (not comparisons)
            fixed = re.sub(r'(\w)\s+=\s+(\w)', r'\1=\2', fixed)
            if '==' not in fixed:
                fixes += 1
            
            # Fix E261: At least two spaces before inline comment
            comment_match = re.search(r'[^\s](\s*)#', fixed)
            if comment_match and not fixed.lstrip().startswith('#'):
                spaces_before = len(comment_match.group(1))
                if spaces_before == 1:
                    # Add one more space
                    fixed = re.sub(r'([^\s])\s#', r'\1  #', fixed)
                    fixes += 1
            
            # Fix E262: Inline comment should start with '# '
            if re.search(r'[^\s].*#[^ \n]', fixed) and not fixed.lstrip().startswith('#'):
                fixed = re.sub(r'#([^ \n#])', r'# \1', fixed)
                fixes += 1
            
            # Fix E265: Block comment should start with '# '
            if fixed.lstrip().startswith('#') and not fixed.lstrip().startswith('# '):
                if len(fixed.lstrip()) > 1 and fixed.lstrip()[1] != '#':
                    indent = len(fixed) - len(fixed.lstrip())
                    fixed = ' ' * indent + '# ' + fixed.lstrip()[1:]
                    fixes += 1
            
            # Fix E271: Multiple spaces after keyword
            for keyword in ['if', 'elif', 'while', 'for', 'with', 'def', 'class', 'return', 'yield']:
                pattern = rf'\b{keyword}\s{{2,}}'
                if re.search(pattern, fixed):
                    fixed = re.sub(pattern, f'{keyword} ', fixed)
                    fixes += 1
                    break
            
            # Fix E272: Multiple spaces before keyword  
            for keyword in ['if', 'elif', 'else', 'while', 'for', 'with', 'def', 'class', 'return']:
                pattern = rf'\s{{2,}}\b{keyword}\b'
                if re.search(pattern, fixed):
                    fixed = re.sub(pattern, f' {keyword}', fixed)
                    fixes += 1
                    break
            
            # Fix E273: Tab after keyword
            for keyword in ['if', 'elif', 'while', 'for', 'with', 'def', 'class']:
                pattern = rf'\b{keyword}\t'
                if re.search(pattern, fixed):
                    fixed = re.sub(pattern, f'{keyword} ', fixed)
                    fixes += 1
                    break
            
            # Fix E274: Tab before keyword
            for keyword in ['if', 'elif', 'else', 'while', 'for', 'with', 'def', 'class']:
                pattern = rf'\t\b{keyword}\b'
                if re.search(pattern, fixed):
                    fixed = re.sub(pattern, f' {keyword}', fixed)
                    fixes += 1
                    break
            
            fixed_lines.append(fixed)
        
        return ''.join(fixed_lines), fixes
    
    def _is_keyword_before(self, line: str, pos: int) -> bool:
        """Check if position follows a Python keyword."""
        keywords = ['if', 'elif', 'while', 'for', 'with', 'def', 'class', 'return']
        for kw in keywords:
            if line[:pos].rstrip().endswith(kw):
                return True
        return False
    
    # ========================================================================
    # E3xx: Blank Line Checks
    # ========================================================================
    
    def _check_blank_lines(self, lines: List[str]) -> None:
        """Check blank line issues (E3xx codes)."""
        for line_num, line in enumerate(lines, 1):
            if line_num < 3:
                continue
            
            # E301: Expected 1 blank line, found 0
            if line.startswith('class ') or line.startswith('def '):
                if line_num > 1:
                    prev_line = lines[line_num - 2]
                    if prev_line.strip() and not prev_line.startswith('#'):
                        self._add_violation(
                            "E301", line_num, 0,
                            "Expected 1 blank line, found 0"
                        )
            
            # E302: Expected 2 blank lines, found N
            if line.startswith('class ') or (line.startswith('def ') and self._is_top_level(lines, line_num)):
                blank_count = 0
                idx = line_num - 2
                while idx >= 0 and not lines[idx].strip():
                    blank_count += 1
                    idx -= 1
                
                if blank_count < 2:
                    self._add_violation(
                        "E302", line_num, 0,
                        f"Expected 2 blank lines, found {blank_count}"
                    )
    
    def _fix_blank_lines(self, content: str) -> Tuple[str, int]:
        """Fix blank line issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Add appropriate blank lines before class/def
            if line.startswith('class ') or (line.startswith('def ') and self._is_top_level(lines, i + 1)):
                # Count existing blank lines
                blank_count = 0
                idx = i - 1
                while idx >= 0 and not lines[idx].strip():
                    blank_count += 1
                    idx -= 1
                
                # Need 2 blank lines before top-level class/function
                if blank_count < 2 and idx >= 0:
                    for _ in range(2 - blank_count):
                        fixed_lines.append('\n')
                        fixes += 1
                elif blank_count > 2:
                    # Remove extra blank lines
                    for _ in range(blank_count - 2):
                        fixed_lines.pop()
                        fixes += 1
            
            fixed_lines.append(line)
            i += 1
        
        return ''.join(fixed_lines), fixes
    
    def _is_top_level(self, lines: List[str], line_num: int) -> bool:
        """Check if a line is at top level (not indented)."""
        if line_num < 1 or line_num > len(lines):
            return False
        line = lines[line_num - 1]
        return not line.startswith(' ') and not line.startswith('\t')
    
    # ========================================================================
    # E4xx: Import Checks
    # ========================================================================
    
    def _check_imports(self, content: str, lines: List[str]) -> None:
        """Check import issues (E4xx codes)."""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # E401: Multiple imports on one line
            if stripped.startswith('import ') and ',' in stripped:
                self._add_violation(
                    "E401", line_num, 0,
                    "Multiple imports on one line"
                )
            
            # E402: Module level import not at top of file
            if stripped.startswith(('import ', 'from ')):
                # Check if there's non-import code before this
                for prev_line_num in range(1, line_num):
                    prev = lines[prev_line_num - 1].strip()
                    if prev and not prev.startswith('#') and not prev.startswith(('import ', 'from ', '"""', "'''")):
                        self._add_violation(
                            "E402", line_num, 0,
                            "Module level import not at top of file"
                        )
                        break
    
    # ========================================================================
    # E5xx: Line Length Checks
    # ========================================================================
    
    def _check_line_length(self, lines: List[str]) -> None:
        """Check line length issues (E5xx codes)."""
        for line_num, line in enumerate(lines, 1):
            # E501: Line too long
            line_length = len(line.rstrip('\n\r'))
            if line_length > self.max_line_length:
                self._add_violation(
                    "E501", line_num, self.max_line_length,
                    f"Line too long ({line_length} > {self.max_line_length} characters)"
                )
    
    # ========================================================================
    # E7xx: Statement Checks
    # ========================================================================
    
    def _check_statements(self, lines: List[str]) -> None:
        """Check statement issues (E7xx codes)."""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # E701: Multiple statements on one line (colon)
            if ':' in stripped and not stripped.startswith('#'):
                # Check for multiple statements after colon
                colon_pos = stripped.find(':')
                after_colon = stripped[colon_pos + 1:].strip()
                if after_colon and not after_colon.startswith('#'):
                    # Exclude dictionary definitions and type hints
                    if not self._is_dict_or_typehint(stripped):
                        self._add_violation(
                            "E701", line_num, colon_pos,
                            "Multiple statements on one line (colon)"
                        )
            
            # E702: Multiple statements on one line (semicolon)
            if ';' in stripped and not stripped.startswith('#'):
                self._add_violation(
                    "E702", line_num, stripped.find(';'),
                    "Multiple statements on one line (semicolon)"
                )
            
            # E703: Statement ends with unnecessary semicolon
            if stripped.endswith(';') and not stripped.startswith('#'):
                self._add_violation(
                    "E703", line_num, len(line) - 2,
                    "Statement ends with unnecessary semicolon"
                )
            
            # E704: Multiple statements on one line (def)
            if stripped.startswith('def ') and ':' in stripped:
                colon_pos = stripped.find(':')
                after_colon = stripped[colon_pos + 1:].strip()
                if after_colon and not after_colon.startswith('#'):
                    self._add_violation(
                        "E704", line_num, colon_pos,
                        "Multiple statements on one line (def)"
                    )
            
            # E705: Multiple statements on one line (if/while/for)
            for keyword in ['if ', 'elif ', 'else:', 'while ', 'for ', 'with ']:
                if stripped.startswith(keyword) and ':' in stripped:
                    colon_pos = stripped.find(':')
                    after_colon = stripped[colon_pos + 1:].strip()
                    if after_colon and not after_colon.startswith('#'):
                        # Allow simple one-liners like 'if x: return y'
                        # but flag complex multi-statement lines
                        if ';' in after_colon or after_colon.count(':') > 0:
                            self._add_violation(
                                "E705", line_num, colon_pos,
                                f"Multiple statements on one line ({keyword.strip()})"
                            )
                    break
            
            # E706: Multiple statements on one line (try/except/finally)
            for keyword in ['try:', 'except', 'except:', 'finally:']:
                if stripped.startswith(keyword) and ':' in stripped:
                    colon_pos = stripped.find(':')
                    after_colon = stripped[colon_pos + 1:].strip()
                    if after_colon and not after_colon.startswith('#'):
                        self._add_violation(
                            "E706", line_num, colon_pos,
                            f"Multiple statements on one line ({keyword})"
                        )
                    break
    
    def _fix_statements(self, content: str) -> Tuple[str, int]:
        """Fix statement issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        
        for line in lines:
            fixed = line
            
            # Fix E703: Remove trailing semicolons
            if fixed.rstrip().endswith(';'):
                fixed = fixed.rstrip()[:-1] + '\n'
                fixes += 1
            
            fixed_lines.append(fixed)
        
        return ''.join(fixed_lines), fixes
    
    def _is_dict_or_typehint(self, line: str) -> bool:
        """Check if line is a dictionary definition or type hint."""
        # Simple heuristic: check for common patterns
        return ('{' in line or 
                '->' in line or 
                'Dict[' in line or 
                'List[' in line or
                'Tuple[' in line)
    
    # ========================================================================
    # E7xx: Comparison and Lambda Checks (Phase 8.3)
    # ========================================================================
    
    def _check_comparison_patterns(self, content: str) -> None:
        """
        Check comparison pattern issues (E711-E722).
        Uses AST-based analysis for accurate detection.
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return  # Skip files with syntax errors
        
        class ComparisonVisitor(ast.NodeVisitor):
            def __init__(self, checker):
                self.checker = checker
                self.violations = []
            
            def visit_Compare(self, node: ast.Compare) -> None:
                """Visit comparison nodes to detect issues."""
                # E711: Comparison to None should be 'if cond is None:'
                for i, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
                    if isinstance(comparator, ast.Constant) and comparator.value is None:
                        if isinstance(op, (ast.Eq, ast.NotEq)):
                            self.checker._add_violation(
                                "E711", node.lineno, node.col_offset,
                                "Comparison to None should be 'if cond is None:'"
                            )
                    
                    # E712: Comparison to True/False should be 'if cond:' or 'if not cond:'
                    elif isinstance(comparator, ast.Constant) and isinstance(comparator.value, bool):
                        if isinstance(op, (ast.Eq, ast.NotEq)):
                            self.checker._add_violation(
                                "E712", node.lineno, node.col_offset,
                                "Comparison to True/False should be 'if cond:' or 'if not cond:'"
                            )
                    
                    # E713: Test for membership should be 'not in'
                    if isinstance(op, ast.NotIn):
                        # This is correct - 'not in' is preferred
                        pass
                    elif isinstance(op, ast.Not) and i > 0:
                        prev_op = node.ops[i-1]
                        if isinstance(prev_op, ast.In):
                            self.checker._add_violation(
                                "E713", node.lineno, node.col_offset,
                                "Test for membership should be 'not in'"
                            )
                    
                    # E714: Test for object identity should be 'is not'
                    if isinstance(op, ast.IsNot):
                        # This is correct - 'is not' is preferred
                        pass
                    elif isinstance(op, ast.Not) and i > 0:
                        prev_op = node.ops[i-1]
                        if isinstance(prev_op, ast.Is):
                            self.checker._add_violation(
                                "E714", node.lineno, node.col_offset,
                                "Test for object identity should be 'is not'"
                            )
                
                self.generic_visit(node)
            
            def visit_Call(self, node: ast.Call) -> None:
                """Visit call nodes to detect type() usage."""
                # E721: Do not compare types, use 'isinstance()'
                # Check for type() calls in comparisons
                if isinstance(node.func, ast.Name) and node.func.id == 'type':
                    # Look for parent Compare node
                    # This is a simplified check - real implementation would need parent tracking
                    pass
                
                self.generic_visit(node)
            
            def visit_Try(self, node: ast.Try) -> None:
                """Visit try-except blocks."""
                # E722: Do not use bare except
                for handler in node.handlers:
                    if handler.type is None:
                        self.checker._add_violation(
                            "E722", handler.lineno, handler.col_offset,
                            "Do not use bare 'except:', specify exception type"
                        )
                
                self.generic_visit(node)
        
        visitor = ComparisonVisitor(self)
        visitor.visit(tree)
    
    def _check_lambda_and_names(self, content: str) -> None:
        """
        Check lambda assignment and ambiguous names (E731-E743).
        Uses AST-based analysis for accurate detection.
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return  # Skip files with syntax errors
        
        class LambdaNameVisitor(ast.NodeVisitor):
            def __init__(self, checker):
                self.checker = checker
                self.ambiguous_names = {'l', 'O', 'I'}
            
            def visit_Assign(self, node: ast.Assign) -> None:
                """Visit assignment nodes to detect lambda assignment."""
                # E731: Do not assign a lambda expression, use a def
                if isinstance(node.value, ast.Lambda):
                    self.checker._add_violation(
                        "E731", node.lineno, node.col_offset,
                        "Do not assign a lambda expression, use a def"
                    )
                
                self.generic_visit(node)
            
            def visit_Name(self, node: ast.Name) -> None:
                """Visit name nodes to detect ambiguous names."""
                # E741: Ambiguous variable name
                if isinstance(node.ctx, ast.Store) and node.id in self.ambiguous_names:
                    self.checker._add_violation(
                        "E741", node.lineno, node.col_offset,
                        f"Ambiguous variable name '{node.id}'"
                    )
                
                self.generic_visit(node)
            
            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                """Visit class definitions to detect ambiguous names."""
                # E742: Ambiguous class definition
                if node.name in self.ambiguous_names:
                    self.checker._add_violation(
                        "E742", node.lineno, node.col_offset,
                        f"Ambiguous class definition '{node.name}'"
                    )
                
                self.generic_visit(node)
            
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                """Visit function definitions to detect ambiguous names."""
                # E743: Ambiguous function definition
                if node.name in self.ambiguous_names:
                    self.checker._add_violation(
                        "E743", node.lineno, node.col_offset,
                        f"Ambiguous function definition '{node.name}'"
                    )
                
                self.generic_visit(node)
            
            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                """Visit async function definitions to detect ambiguous names."""
                # E743: Ambiguous function definition
                if node.name in self.ambiguous_names:
                    self.checker._add_violation(
                        "E743", node.lineno, node.col_offset,
                        f"Ambiguous async function definition '{node.name}'"
                    )
                
                self.generic_visit(node)
        
        visitor = LambdaNameVisitor(self)
        visitor.visit(tree)
    
    # ========================================================================
    # W1xx-W6xx: Warning Checks
    # ========================================================================
    
    def _check_warnings(self, lines: List[str]) -> None:
        """Check warning issues (W codes)."""
        for line_num, line in enumerate(lines, 1):
            # W291: Trailing whitespace
            if line.rstrip('\n\r') != line.rstrip():
                self._add_violation(
                    "W291", line_num, len(line.rstrip('\n\r')),
                    "Trailing whitespace"
                )
            
            # W292: No newline at end of file
            if line_num == len(lines) and not line.endswith('\n'):
                self._add_violation(
                    "W292", line_num, len(line),
                    "No newline at end of file"
                )
            
            # W293: Blank line contains whitespace
            if not line.strip() and line != '\n':
                self._add_violation(
                    "W293", line_num, 0,
                    "Blank line contains whitespace"
                )
    
    def _fix_trailing_whitespace(self, content: str) -> Tuple[str, int]:
        """Fix trailing whitespace issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        
        for i, line in enumerate(lines):
            # W291: Remove trailing whitespace
            stripped = line.rstrip()
            if stripped != line.rstrip('\n\r'):
                fixed_lines.append(stripped + '\n' if line.endswith('\n') else stripped)
                fixes += 1
            else:
                fixed_lines.append(line)
        
        # W292: Ensure newline at end of file
        if fixed_lines and not fixed_lines[-1].endswith('\n'):
            fixed_lines[-1] += '\n'
            fixes += 1
        
        return ''.join(fixed_lines), fixes
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _add_violation(self, code: str, line: int, column: int, message: str) -> None:
        """Add a PEP 8 violation."""
        violation = RuleViolation(
            rule_id=code,
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW if code.startswith('W') else RuleSeverity.MEDIUM,
            message=message,
            file_path=Path(self.current_file_path) if self.current_file_path else Path("."),
            line_number=line,
            column=column,
            fix_applicability=FixApplicability.AUTOMATIC if self._is_auto_fixable(code) else FixApplicability.MANUAL
        )
        self.violations.append(violation)
    
    def _is_auto_fixable(self, code: str) -> bool:
        """Check if a PEP 8 violation is automatically fixable."""
        auto_fixable = [
            'E101',  # Mixed tabs/spaces
            'E201', 'E202',  # Whitespace in brackets
            'E231',  # Missing whitespace after comma
            'E301', 'E302',  # Blank lines
            'E703',  # Trailing semicolon
            'W291', 'W292', 'W293',  # Whitespace warnings
        ]
        return code in auto_fixable


class PEP8Rules:
    """PEP 8 rule definitions for the rule engine."""
    
    @staticmethod
    def get_all_rules() -> List[Rule]:
        """Get all PEP 8 rules."""
        rules = []
        
        # E1xx: Indentation rules
        rules.extend(PEP8Rules._get_indentation_rules())
        
        # E2xx: Whitespace rules
        rules.extend(PEP8Rules._get_whitespace_rules())
        
        # E3xx: Blank line rules
        rules.extend(PEP8Rules._get_blank_line_rules())
        
        # E4xx: Import rules
        rules.extend(PEP8Rules._get_import_rules())
        
        # E5xx: Line length rules
        rules.extend(PEP8Rules._get_line_length_rules())
        
        # E7xx: Statement rules
        rules.extend(PEP8Rules._get_statement_rules())
        
        # W codes: Warning rules
        rules.extend(PEP8Rules._get_warning_rules())
        
        return rules
    
    @staticmethod
    def _get_indentation_rules() -> List[Rule]:
        """Get indentation rules (E1xx)."""
        return [
            Rule(
                rule_id="E101",
                name="indentation-mixed-spaces-tabs",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Indentation contains mixed spaces and tabs",
                description="PEP 8 requires consistent use of spaces (not tabs) for indentation",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E111",
                name="indentation-not-multiple-of-four",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Indentation is not a multiple of 4",
                description="PEP 8 recommends 4 spaces per indentation level",
                fix_applicability=FixApplicability.MANUAL
            ),
        ]
    
    @staticmethod
    def _get_whitespace_rules() -> List[Rule]:
        """Get whitespace rules (E2xx)."""
        return [
            Rule(
                rule_id="E201",
                name="whitespace-after-open-bracket",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Whitespace after '('",
                description="Avoid extraneous whitespace immediately after opening brackets",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E202",
                name="whitespace-before-close-bracket",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Whitespace before ')'",
                description="Avoid extraneous whitespace immediately before closing brackets",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E203",
                name="whitespace-before-colon",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Whitespace before ':'",
                description="Avoid extraneous whitespace before colon",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E211",
                name="whitespace-before-paren",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Whitespace before '('",
                description="Do not use whitespace before function call parentheses",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E225",
                name="missing-whitespace-around-operator",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Missing whitespace around operator",
                description="Always use whitespace around binary operators",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E231",
                name="missing-whitespace-after-comma",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Missing whitespace after ','",
                description="Always use whitespace after comma",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
        ]
    
    @staticmethod
    def _get_blank_line_rules() -> List[Rule]:
        """Get blank line rules (E3xx)."""
        return [
            Rule(
                rule_id="E301",
                name="expected-1-blank-line",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Expected 1 blank line, found 0",
                description="Separate method definitions with one blank line",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E302",
                name="expected-2-blank-lines",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Expected 2 blank lines, found less",
                description="Separate top-level function and class definitions with two blank lines",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
        ]
    
    @staticmethod
    def _get_import_rules() -> List[Rule]:
        """Get import rules (E4xx)."""
        return [
            Rule(
                rule_id="E401",
                name="multiple-imports-on-line",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Multiple imports on one line",
                description="Put each import on a separate line",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="E402",
                name="module-import-not-at-top",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Module level import not at top of file",
                description="Imports should be placed at the top of the file",
                fix_applicability=FixApplicability.MANUAL
            ),
        ]
    
    @staticmethod
    def _get_line_length_rules() -> List[Rule]:
        """Get line length rules (E5xx)."""
        return [
            Rule(
                rule_id="E501",
                name="line-too-long",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Line too long",
                description="Limit all lines to a maximum of 79 characters",
                fix_applicability=FixApplicability.MANUAL
            ),
        ]
    
    @staticmethod
    def _get_statement_rules() -> List[Rule]:
        """Get statement rules (E7xx)."""
        return [
            Rule(
                rule_id="E701",
                name="multiple-statements-colon",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Multiple statements on one line (colon)",
                description="Compound statements should be on separate lines",
                fix_applicability=FixApplicability.MANUAL
            ),
            Rule(
                rule_id="E702",
                name="multiple-statements-semicolon",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Multiple statements on one line (semicolon)",
                description="Do not use semicolons to join statements",
                fix_applicability=FixApplicability.MANUAL
            ),
            Rule(
                rule_id="E703",
                name="statement-ends-with-semicolon",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Statement ends with unnecessary semicolon",
                description="Remove trailing semicolons",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
        ]
    
    @staticmethod
    def _get_warning_rules() -> List[Rule]:
        """Get warning rules (W codes)."""
        return [
            Rule(
                rule_id="W291",
                name="trailing-whitespace",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Trailing whitespace",
                description="Remove trailing whitespace at the end of lines",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="W292",
                name="no-newline-at-end-of-file",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="No newline at end of file",
                description="Files should end with a newline character",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
            Rule(
                rule_id="W293",
                name="blank-line-contains-whitespace",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Blank line contains whitespace",
                description="Remove whitespace from blank lines",
                fix_applicability=FixApplicability.AUTOMATIC
            ),
        ]
