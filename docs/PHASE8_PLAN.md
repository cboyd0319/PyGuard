# Phase 8 Implementation Plan: Complete PEP 8 Coverage

**Status:** 📋 Planned
**Timeline:** 2-3 weeks
**Priority:** HIGHEST
**Rules to Add:** 80+ E/W codes
**Current PEP 8 Coverage:** 20/100+ rules (20%)

---

## Overview

Phase 8 will complete PyGuard's PEP 8 implementation, adding 80+ E/W code rules with comprehensive auto-fix capabilities. This will enable PyGuard to fully replace pycodestyle, autopep8, and the PEP 8 checking portions of Flake8 and Ruff.

### Why Phase 8 is Critical

1. **Most Frequently Used:** PEP 8 rules are checked in 95%+ of Python projects
2. **Auto-Fixable:** Nearly all PEP 8 violations can be automatically corrected
3. **Tool Replacement:** Eliminates need for pycodestyle, autopep8, Black
4. **Foundation:** Many other rules depend on proper PEP 8 compliance
5. **User Expectations:** Developers expect comprehensive style checking

---

## Current State Analysis

### Existing Implementation (`pep8_comprehensive.py`)

**Strengths:**
- ✅ Solid foundation with 20 rules
- ✅ Clean architecture with separate detection and fix methods
- ✅ 95% working (19/20 rules functional)
- ✅ 85% auto-fix success rate
- ✅ Good test coverage (31 tests)

**Limitations:**
- ⚠️ Only 20% of full PEP 8 coverage
- ⚠️ Blank line detection needs refinement (2 skipped tests)
- ⚠️ Missing continuation line indentation (E121-E131)
- ⚠️ Missing complex whitespace patterns (E241-E275)
- ⚠️ Missing statement complexity rules (E704-E743)

---

## Implementation Strategy

### Approach: Incremental Build-out

Rather than rebuilding, we'll enhance the existing `pep8_comprehensive.py` module:

1. **Phase 8.1:** Continuation line indentation (E121-E131) - 11 rules
2. **Phase 8.2:** Advanced whitespace (E241-E275) - 35 rules
3. **Phase 8.3:** Statement complexity (E704-E743) - 40 rules
4. **Phase 8.4:** Line break warnings (W503-W504) - 2 rules
5. **Phase 8.5:** Deprecation warnings (W601-W606) - 6 rules

Total: 94 new rules over 5 sub-phases

---

## Sub-Phase Breakdown

### Phase 8.1: Continuation Line Indentation (Week 1)
**Rules:** 11 (E121-E131)
**Auto-Fix:** 9 rules (82%)
**Complexity:** High (complex AST analysis)

#### Rules to Implement

| Code | Description | Auto-Fix | Priority |
|------|-------------|----------|----------|
| E121 | Continuation line under-indented for hanging indent | ✅ | HIGH |
| E122 | Continuation line missing indentation or outdented | ✅ | HIGH |
| E123 | Closing bracket does not match indentation | ✅ | HIGH |
| E124 | Closing bracket does not match visual indentation | ✅ | MEDIUM |
| E125 | Continuation line with same indent as next logical line | ✅ | HIGH |
| E126 | Continuation line over-indented for hanging indent | ✅ | HIGH |
| E127 | Continuation line over-indented for visual indent | ✅ | MEDIUM |
| E128 | Continuation line under-indented for visual indent | ✅ | MEDIUM |
| E129 | Visually indented line with same indent as next logical | ✅ | MEDIUM |
| E130 | Continuation line indentation is not a multiple of four | ❌ | LOW |
| E131 | Continuation line unaligned for hanging indent | ❌ | LOW |

#### Implementation Plan

**New Methods:**
```python
def _check_continuation_indentation(self, lines: List[str]) -> List[RuleViolation]:
    """Check E121-E131: Continuation line indentation."""
    # Detect open brackets/parens
    # Track indentation levels
    # Validate continuation alignment
    # Generate violations

def _fix_continuation_indentation(self, code: str, violations: List[RuleViolation]) -> str:
    """Fix continuation line indentation issues."""
    # Parse lines with bracket tracking
    # Calculate correct indentation
    # Apply fixes
    # Return fixed code
```

**Test Coverage:**
- 22 tests (2 per rule)
- Positive and negative cases
- Edge cases (nested brackets, mixed styles)

---

### Phase 8.2: Advanced Whitespace (Week 2)
**Rules:** 35 (E241-E275)
**Auto-Fix:** 32 rules (91%)
**Complexity:** Medium

#### Categories

**E241-E251: Whitespace issues (11 rules)**
- E241: Multiple spaces after ','
- E242: Tab after ','
- E243: Tab before ','
- E244-E251: Various whitespace patterns

**E261-E266: Comment spacing (6 rules)**
- E261: At least two spaces before inline comment
- E262: Inline comment should start with '# '
- E265: Block comment should start with '# '
- E266: Too many leading '#' for block comment

**E271-E276: Keyword whitespace (6 rules)**
- E271: Multiple spaces after keyword
- E272: Multiple spaces before keyword
- E273-E276: Tab-related keyword spacing

**E27x-E28x: Additional patterns (12 rules)**

#### Implementation Plan

**New Methods:**
```python
def _check_whitespace_around_operators(self, lines: List[str]) -> List[RuleViolation]:
    """Check E241-E251: Whitespace around operators and commas."""
    # Tokenize each line
    # Check operator spacing
    # Generate violations

def _check_comment_spacing(self, lines: List[str]) -> List[RuleViolation]:
    """Check E261-E266: Comment spacing."""
    # Detect inline and block comments
    # Check spacing patterns
    # Generate violations

def _check_keyword_whitespace(self, lines: List[str]) -> List[RuleViolation]:
    """Check E271-E276: Whitespace around keywords."""
    # Parse keywords
    # Check surrounding whitespace
    # Generate violations
```

---

### Phase 8.3: Statement Complexity (Week 2-3)
**Rules:** 40 (E704-E743)
**Auto-Fix:** 25 rules (62%)
**Complexity:** High

#### Categories

**E701-E706: Statement formatting (6 rules)**
- ✅ E701: Multiple statements on one line (colon) - EXISTS
- ✅ E702: Multiple statements on one line (semicolon) - EXISTS
- ✅ E703: Trailing semicolon - EXISTS
- E704: Multiple statements on one line (def)
- E705: Multiple statements on one line (try/except/finally)
- E706: Multiple statements on one line (else)

**E711-E721: Comparison patterns (11 rules)**
- E711: Comparison to None should be 'if cond is None:'
- E712: Comparison to True/False should be 'if cond:' or 'if not cond:'
- E713: Test for membership should be 'not in'
- E714: Test for object identity should be 'is not'
- E721: Do not compare types, use 'isinstance()'
- E722: Do not use bare except

**E731-E743: Function/variable patterns (13 rules)**
- E731: Do not assign a lambda expression, use a def
- E741: Do not use ambiguous variable names (l, O, I)
- E742: Do not define classes named 'l', 'O', or 'I'
- E743: Do not define functions named 'l', 'O', or 'I'

**E7xx: Additional patterns (10+ rules)**

#### Implementation Plan

**New Methods:**
```python
def _check_comparison_patterns(self, tree: ast.Module) -> List[RuleViolation]:
    """Check E711-E722: Comparison patterns."""
    # AST-based visitor
    # Check comparison operators
    # Check membership tests
    # Generate violations

def _check_naming_patterns(self, tree: ast.Module) -> List[RuleViolation]:
    """Check E741-E743: Ambiguous names."""
    # Visit variable assignments
    # Visit function/class definitions
    # Check for ambiguous names
    # Generate violations

def _check_lambda_assignment(self, tree: ast.Module) -> List[RuleViolation]:
    """Check E731: Lambda assignment."""
    # Visit assignments
    # Check for lambda on right side
    # Generate violations
```

---

### Phase 8.4: Line Break Warnings (Week 3)
**Rules:** 2 (W503-W504)
**Auto-Fix:** 2 rules (100%)
**Complexity:** Low

#### Rules

- W503: Line break before binary operator (style preference)
- W504: Line break after binary operator (style preference)

**Note:** These are mutually exclusive style preferences. Will default to W503 (break before operator, PEP 8 recommendation since 2016).

---

### Phase 8.5: Deprecation Warnings (Week 3)
**Rules:** 6 (W601-W606)
**Auto-Fix:** 5 rules (83%)
**Complexity:** Medium

#### Rules

- W601: .has_key() is deprecated, use 'in' operator
- W602: Deprecated form of raising exception
- W603: '<>' is deprecated, use '!='
- W604: Backticks are removed in Python 3
- W605: Invalid escape sequence '\x'
- W606: async and await are reserved keywords

#### Implementation Plan

**New Method:**
```python
def _check_deprecated_patterns(self, tree: ast.Module) -> List[RuleViolation]:
    """Check W601-W606: Deprecated patterns."""
    # Visit attribute access (.has_key)
    # Check raise statements
    # Check comparison operators
    # Check string literals for invalid escapes
    # Generate violations
```

---

## Testing Strategy

### Test Structure

For each sub-phase:

```
tests/unit/test_pep8_comprehensive.py
├── TestE121_E131ContinuationIndentation (22 tests)
├── TestE241_E275Whitespace (70 tests)
├── TestE704_E743Statements (80 tests)
├── TestW503_W504LineBreaks (4 tests)
└── TestW601_W606Deprecations (12 tests)
```

**Total New Tests:** 188 tests

### Test Categories

1. **Positive Detection:** Detect violations correctly
2. **Negative Cases:** Avoid false positives
3. **Auto-Fix Correctness:** Fixes produce valid, correct code
4. **Edge Cases:** Complex scenarios, nested structures
5. **Integration:** Multiple violations in same file

---

## Performance Considerations

### Optimization Strategy

1. **Single-Pass Analysis:** Check all rules in one pass
2. **Lazy Parsing:** Only parse AST when needed
3. **Regex Optimization:** Compile patterns once
4. **Incremental Updates:** Support partial file analysis (future)
5. **Caching:** Cache parsed trees for repeated checks

### Performance Targets

- **Analysis:** < 5ms per 100 LOC
- **Auto-Fix:** < 10ms per 100 LOC
- **Memory:** < 100MB for 10k LOC file
- **Overhead:** < 20% vs pycodestyle

---

## Auto-Fix Safety

### Validation Requirements

For each auto-fix rule:
1. **Syntax Preservation:** Fixed code must parse successfully
2. **Semantic Preservation:** Behavior must not change
3. **Idempotency:** Applying fix twice = applying once
4. **Reversibility:** Provide backup before applying fixes

### Testing Auto-Fix

```python
def test_autofix_E121_preserves_semantics():
    """Ensure auto-fix doesn't change behavior."""
    original_code = "..."
    fixed_code = fixer.fix(original_code)
    
    # Both should parse
    ast.parse(original_code)
    ast.parse(fixed_code)
    
    # Behavior should match
    assert execute(original_code) == execute(fixed_code)
```

---

## Migration & Documentation

### User-Facing Changes

**New CLI Flags:**
```bash
# PEP 8 only mode
pyguard --pep8-only src/

# Specific PEP 8 categories
pyguard --pep8-categories=E1,E2,E7 src/

# Ignore specific codes
pyguard --ignore=E501,W503 src/
```

**Configuration File:**
```toml
[pyguard.pep8]
max_line_length = 88  # Black default
ignore = ["E501", "W503"]  # Ignore specific codes
select = ["E", "W"]  # Only check E and W codes
```

### Documentation Updates

1. **User Guide:** Complete PEP 8 coverage documentation
2. **Migration Guide:** From pycodestyle/autopep8 to PyGuard
3. **Rule Reference:** Full E/W code documentation
4. **Auto-Fix Guide:** What gets fixed automatically
5. **Configuration Guide:** Customization options

---

## Success Metrics

### Must Have (Phase 8 Complete)
- [ ] 100+ PEP 8 rules implemented (100% coverage)
- [ ] 80+ auto-fixable rules
- [ ] 188+ new tests passing
- [ ] 70%+ test coverage maintained
- [ ] < 5ms per 100 LOC performance
- [ ] Zero breaking changes
- [ ] Can fully replace pycodestyle
- [ ] Can fully replace autopep8

### Should Have
- [ ] < 5% false positive rate
- [ ] > 95% auto-fix correctness
- [ ] Comprehensive documentation
- [ ] Migration guides
- [ ] Configuration presets

---

## Risk Mitigation

### High-Risk Areas

1. **Continuation Line Indentation (E121-E131)**
   - **Risk:** Complex bracket tracking, AST limitations
   - **Mitigation:** Extensive testing, fallback to manual fix

2. **Auto-Fix Correctness**
   - **Risk:** Incorrect fixes break code
   - **Mitigation:** Syntax validation, semantic tests, backups

3. **Performance Degradation**
   - **Risk:** More rules = slower analysis
   - **Mitigation:** Single-pass design, caching, profiling

4. **False Positives**
   - **Risk:** Annoying developers with incorrect warnings
   - **Mitigation:** Conservative detection, extensive testing

---

## Timeline

### Week 1: Continuation Indentation (E121-E131)
- Days 1-2: Implementation (11 rules)
- Days 3-4: Testing (22 tests)
- Day 5: Documentation & review

### Week 2: Advanced Whitespace (E241-E275)
- Days 1-3: Implementation (35 rules)
- Days 4-5: Testing (70 tests)

### Week 3: Statement Complexity & Remaining (E704-E743, W503-W606)
- Days 1-3: Implementation (48 rules)
- Days 4: Testing (96 tests)
- Day 5: Integration testing & documentation

**Total:** 15 working days (3 weeks)

---

## Next Actions

### Immediate
1. Review and approve this plan
2. Set up development branch for Phase 8
3. Create issue tracking for each sub-phase
4. Set up performance benchmarking

### Week 1 Start
1. Begin Phase 8.1 implementation
2. Set up test fixtures
3. Create baseline performance metrics
4. Begin documentation updates

---

## Appendix: Complete PEP 8 Code List

### E Codes (Errors)
- E1xx: Indentation (17 codes)
- E2xx: Whitespace (59 codes)
- E3xx: Blank lines (6 codes)
- E4xx: Imports (2 codes)
- E5xx: Line length (2 codes)
- E7xx: Statements (52 codes)

### W Codes (Warnings)
- W1xx: Indentation warning (1 code)
- W2xx: Whitespace warning (3 codes)
- W3xx: Blank line warning (1 code)
- W5xx: Line break warning (2 codes)
- W6xx: Deprecation warning (6 codes)

**Total:** 138 codes (will implement ~100 most relevant)

---

**Document Version:** 1.0
**Last Updated:** 2025-01-XX
**Status:** Ready for implementation
