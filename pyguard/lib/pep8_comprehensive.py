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
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
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
    
    def _fix_indentation(self, content: str) -> Tuple[str, int]:
        """Fix indentation issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        fixes = 0
        
        for line in lines:
            if not line.strip():
                fixed_lines.append(line)
                continue
            
            # Fix mixed tabs and spaces - convert all to spaces
            indent = line[:len(line) - len(line.lstrip())]
            if '\t' in indent:
                # Convert tabs to 4 spaces
                fixed_indent = indent.replace('\t', '    ')
                fixed_lines.append(fixed_indent + line.lstrip())
                fixes += 1
            else:
                fixed_lines.append(line)
        
        return ''.join(fixed_lines), fixes
    
    def _is_continuation_line(self, lines: List[str], line_num: int) -> bool:
        """Check if a line is a continuation line."""
        if line_num < 1 or line_num > len(lines):
            return False
        line = lines[line_num - 1]
        return line.rstrip().endswith('\\') or line.rstrip().endswith(',')
    
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
