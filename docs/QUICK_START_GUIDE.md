# PyGuard Development Quick Start Guide

**For AI Assistants and Developers Starting Work**

---

## 🎯 30-Second Overview

PyGuard is replacing **ALL Python code quality tools** (Ruff, Pylint, mypy, Flake8, Bandit, Black, isort).

**Current State:**
- ✅ 265 unique rules implemented
- ✅ 729 tests passing, 77% coverage
- ✅ Zero errors/warnings
- 🔴 Need 1,271 more rules (30.8% → 100%)

**Target:** 1,536 total rules across 8 major tools

---

## 📊 Where We Stand (Tool by Tool)

| Tool | Have | Need | Coverage | Status |
|------|------|------|----------|--------|
| Ruff | 265 | 667 | 28.4% | 🔴 Needs Work |
| Pylint | 20 | 369 | 5.1% | 🔴 Needs Work |
| Flake8 | 87 | 13 | 87% | ✅ Almost Done |
| Bandit | 55+ | 0 | 100%+ | ✅ Exceeded! |
| mypy | 6 | 44 | 12% | 🔴 Needs Work |

---

## 🚀 Immediate Next Steps (Phase 9A)

**Priority 1: Ruff S Category (Security)**
- 73 rules needed
- Map existing PyGuard security (55+ rules) to Ruff S codes
- Add missing Ruff S patterns
- Duration: 1-2 weeks

**Priority 2: Ruff E Category (PEP8 Errors)**
- 43 rules needed (have 17/60)
- Complete E4xx (imports), E5xx (line length), E7xx (statements)
- Duration: 1 week

**Priority 3: Ruff F Category (Pyflakes)**
- 41 rules needed (have 2/43)
- Import/name/syntax error detection
- Duration: 1 week

---

## 📂 Key Files to Know

### Documentation (READ FIRST!)
- `docs/UPDATE.md` - Current status, progress tracking
- `docs/MISSING_RULES_DETAILED.md` - Complete breakdown of what's missing
- `docs/IMPLEMENTATION_STRATEGY.md` - Full 28-week roadmap
- `docs/TOOL_REPLACEMENT_ANALYSIS.txt` - Tool-by-tool comparison

### Core Implementation
- `pyguard/lib/*.py` - 46 existing modules with 265 rules
- `tests/unit/*.py` - 729 passing tests

### Configuration
- `pyproject.toml` - Python 3.11+ requirement
- `pytest.ini` - Test configuration (70% min coverage)

---

## 🔧 Development Workflow

### Setup
```bash
cd /home/runner/work/PyGuard/PyGuard
pip install -e ".[dev]"  # Install with dev dependencies
```

### Before Making Changes
```bash
pytest tests/ -v --tb=short  # Verify baseline (729 tests pass)
```

### After Making Changes
```bash
pytest tests/ -x -q          # Run all tests (stop on first failure)
pytest tests/ --cov=pyguard  # Check coverage (must be ≥77%)
```

### Quality Gates (Must Pass)
```bash
make format      # Format with Black
make lint        # Run all linters
make test        # Run tests with coverage
make security    # Security scan
```

---

## 📝 How to Add a New Rule

### Step 1: Choose the right file
- **Ruff rules:** Find/create file in `pyguard/lib/`
  - S → `security.py` (or create `ruff/security.py`)
  - E → `pep8_comprehensive.py` (or create `ruff/pep8_errors.py`)
  - F → Create `ruff/pyflakes.py`
  - UP → `modern_python.py` (or create `ruff/pyupgrade.py`)
  - PTH → `pathlib_patterns.py` (or create `ruff/pathlib.py`)
  
- **Pylint rules:** Create new files in `pyguard/lib/pylint/`
  - R → `pylint/refactor.py`
  - C → `pylint/convention.py`
  - W → `pylint/warnings.py`
  - E → `pylint/errors.py`

### Step 2: Implement detection logic
```python
class MyRuleVisitor(ast.NodeVisitor):
    """Detect [pattern description]."""
    
    def __init__(self, file_path: str):
        self.violations: list[RuleViolation] = []
        self.file_path = file_path
    
    def visit_[NodeType](self, node: ast.[NodeType]) -> None:
        """Check for [specific pattern]."""
        if [condition]:
            self.violations.append(
                RuleViolation(
                    rule_id="S101",  # Use appropriate Ruff/Pylint code
                    message="Clear description of the issue",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )
        self.generic_visit(node)
```

### Step 3: Register the rule
```python
RULES = [
    Rule(
        rule_id="S101",
        name="assert-used",
        description="Use of assert detected",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Use of assert detected. Assert statements are removed with -O",
    ),
]
```

### Step 4: Add tests
```python
def test_detect_violation():
    """Test that the rule detects the violation."""
    code = '''
    assert user.is_admin()  # Bad - assert can be disabled
    '''
    issues = checker.check(code)
    assert len(issues) == 1
    assert issues[0].rule_id == "S101"

def test_safe_code_passes():
    """Test that safe code doesn't trigger the rule."""
    code = '''
    if not user.is_admin():
        raise ValueError("Not admin")
    '''
    issues = checker.check(code)
    assert len(issues) == 0
```

### Step 5: Update docs
```bash
# Update docs/UPDATE.md with new rule count
# Add rule to docs/MISSING_RULES_DETAILED.md (remove from missing list)
```

---

## 🎯 Current Rule Count (How to Check)

```bash
# Get accurate rule count
grep -r "rule_id=" pyguard/lib/*.py | grep -v "test" | \
  sed 's/.*rule_id="\([^"]*\)".*/\1/' | sort -u | wc -l

# Get rules by category
grep -r "rule_id=" pyguard/lib/*.py | grep -v "test" | \
  sed 's/.*rule_id="\([^"]*\)".*/\1/' | sort -u | \
  sed 's/[0-9].*$//' | sort | uniq -c | sort -rn
```

---

## 📋 Common Rule Categories

### Ruff Categories
- **S:** Security (Bandit-style) - 73 rules
- **E:** PEP8 Errors - 60 rules
- **F:** Pyflakes - 43 rules
- **B:** Bugbear - 42 rules
- **UP:** pyupgrade - 47 rules
- **PTH:** pathlib - 35 rules
- **PT:** pytest - 31 rules
- **SIM:** Simplify - 30 rules

### Pylint Categories
- **R:** Refactor (design metrics)
- **C:** Convention (style)
- **W:** Warning (logic)
- **E:** Error (bugs)
- **F:** Fatal (crashes)

### Severity Levels
- `CRITICAL` - Security vulnerabilities, certain bugs
- `HIGH` - Errors, bad practices
- `MEDIUM` - Warnings, style issues
- `LOW` - Conventions, minor issues
- `INFO` - Informational

---

## ⚠️ Common Pitfalls

### DON'T:
- ❌ Use `RuleCategory.BEST_PRACTICE` (doesn't exist - use `CONVENTION`)
- ❌ Break existing tests (all 729 must pass)
- ❌ Lower coverage below 77%
- ❌ Add rules without tests
- ❌ Forget to update UPDATE.md

### DO:
- ✅ Follow existing patterns in each file
- ✅ Use AST-based detection (reliable)
- ✅ Add clear, actionable error messages
- ✅ Test thoroughly (unit + integration)
- ✅ Update UPDATE.md after EVERY session
- ✅ Run full test suite before committing

---

## 🎓 Learning Resources

### Official Tool Documentation
- [Ruff Rules](https://docs.astral.sh/ruff/rules/) - All Ruff rules
- [Pylint Messages](https://pylint.pycqa.org/en/latest/user_guide/messages/) - All Pylint checks
- [PEP 8](https://peps.python.org/pep-0008/) - Python style guide
- [mypy](https://mypy.readthedocs.io/) - Type checker docs

### PyGuard Documentation
- `docs/ARCHITECTURE.md` - System design
- `docs/security-rules.md` - Security rules reference
- `docs/best-practices.md` - Code quality patterns
- `.github/copilot-instructions.md` - Copilot guidelines

---

## 📊 Progress Tracking Template

After implementing rules, update `docs/UPDATE.md`:

```markdown
### 2025-XX-XX - [Description of Work]
- ✅ Implemented [N] new rules in [Category]
  - [Rule ID]: [Description]
  - [Rule ID]: [Description]
- ✅ Total rules: [Old count] → [New count] (+N)
- ✅ Coverage: [Old %] → [New %]
- ✅ All tests passing: [New test count] tests
- ✅ Coverage maintained: [Coverage %]
```

---

## 🚦 Success Criteria

### For Each Implementation Session
- [ ] New rules implemented with clear rule IDs
- [ ] Detection logic tested (positive + negative cases)
- [ ] Auto-fix implemented (if applicable)
- [ ] Tests added (minimum 2 per rule)
- [ ] All 729+ tests still pass
- [ ] Coverage maintained ≥77%
- [ ] UPDATE.md updated with accurate counts
- [ ] No new errors from linters

### For Phase Completion
- [ ] All phase rules implemented
- [ ] Target rule count achieved
- [ ] Coverage target met
- [ ] Documentation updated
- [ ] Migration guide written (if applicable)

---

## 🔗 Quick Links

- **Repository:** https://github.com/cboyd0319/PyGuard
- **Issues:** https://github.com/cboyd0319/PyGuard/issues
- **Latest Status:** `docs/UPDATE.md`
- **Missing Rules:** `docs/MISSING_RULES_DETAILED.md`
- **Full Strategy:** `docs/IMPLEMENTATION_STRATEGY.md`

---

## 💡 Pro Tips

1. **Start Small:** Implement 5-10 rules at a time, test thoroughly
2. **Use Ruff as Reference:** `ruff rule S101` shows Ruff's implementation
3. **Check Existing Code:** Many patterns already exist in other modules
4. **Test Edge Cases:** Think about what could break the detection
5. **Auto-fix Carefully:** Only auto-fix when 100% safe
6. **Document Mapping:** When mapping PyGuard → Ruff/Pylint codes, document it

---

**Ready to Start?**

1. Read `docs/MISSING_RULES_DETAILED.md` - Know what's needed
2. Pick a category (Ruff S, E, or F recommended)
3. Implement 5-10 rules with tests
4. Run quality gates
5. Update UPDATE.md
6. Commit and repeat!

**Questions?** Check `.github/copilot-instructions.md` for detailed coding guidelines.

---

**Last Updated:** 2025-10-14  
**Version:** 1.0
