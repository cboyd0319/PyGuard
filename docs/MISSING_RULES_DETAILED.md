# PyGuard Missing Rules - Detailed Breakdown

**Generated:** 2025-10-14  
**Source:** Analysis of Ruff 0.14.0, Pylint 4.0.0, mypy 1.18.2

---

## Executive Summary

**Total Gap:** 1,063+ rules needed to fully replace all tools

**By Tool:**
- Ruff: 667 rules missing (28.4% coverage)
- Pylint: ~369 messages missing (5.1% coverage)
- mypy: 44 rules missing (12% coverage)
- Flake8: 13 rules missing (87% coverage)
- Others: ~20 rules missing

---

## Ruff Missing Rules by Category

### 1. S (Security) - 73 rules missing ⚠️ CRITICAL
**Current:** 0/73 (0%)  
**Priority:** Immediate - These are Bandit-style security checks

Missing rules include SQL injection, command injection, hardcoded secrets, cryptography issues, etc.

**Note:** PyGuard actually has 55+ custom security rules in `security.py`, but they don't map to Ruff S codes. Need to:
1. Map existing PyGuard security rules to Ruff S codes where applicable
2. Add missing Ruff S rules that PyGuard doesn't cover
3. Create compatibility layer for Ruff S rule reporting

### 2. RUF (Ruff-specific) - 62 rules missing
**Current:** 0/62 (0%)  
**Priority:** Medium - Ruff unique patterns

These are Ruff's custom rules that don't exist in other tools.

### 3. PYI (Stub files) - 55 rules missing
**Current:** 0/55 (0%)  
**Priority:** Low-Medium - .pyi type stub validation

Rules for checking type stub files (.pyi) used for type hints.

### 4. D (Docstrings) - 46 rules missing
**Current:** 0/46 (0%)  
**Priority:** Medium - pydocstyle compatibility

Docstring style and completeness checking (pydocstyle rules).

### 5. E (PEP8 Errors) - 43 rules missing
**Current:** 17/60 (28.3%)  
**Priority:** High - Core PEP8 compliance

Missing E rules:
- E4xx: Import issues
- E5xx: Line length and backslash
- E7xx: Statement issues
- E9xx: Runtime errors

### 6. F (Pyflakes) - 41 rules missing
**Current:** 2/43 (4.7%)  
**Priority:** Critical - Error detection

Missing F rules:
- F4xx: Import errors
- F5xx: Name errors
- F6xx: Syntax errors
- F8xx: Undefined/unused names

### 7. PLE (Pylint Errors) - 36 rules missing
**Current:** 2/38 (5.3%)  
**Priority:** High - Probable bugs

Missing PLE rules include invalid syntax, bad reversals, invalid star expressions, etc.

### 8. UP (pyupgrade) - 35 rules missing
**Current:** 12/47 (25.5%)  
**Priority:** High - Modernization

Missing UP rules:
- UP009-030: UTF-8, futures, typing, conversions
- UP033-050: LRU cache, PEP 695 type aliases

### 9. PTH (pathlib) - 34 rules missing
**Current:** 1/35 (2.9%)  
**Priority:** High - pathlib modernization

Missing PTH rules for os.path → pathlib conversions.

### 10. PT (pytest) - 31 rules missing
**Current:** 0/31 (0%)  
**Priority:** Medium - pytest best practices

Rules for pytest style and best practices.

---

## Pylint Missing Messages (389 total, ~20 implemented)

### Convention (C) - ~150 messages missing
**Priority:** High - Code style and conventions

Key missing messages:
- C01xx: Naming conventions
- C02xx: Code style (enumerate, dict.items, etc.)
- C03xx: Lambda and function style
- C04xx: String formatting
- C1xxx: Boolean expressions, comprehensions

### Refactor (R) - ~100 messages missing
**Priority:** High - Design and refactoring

Key missing messages:
- R09xx: Design metrics (too many ancestors, attributes, methods)
- R1xxx: Simplification opportunities
- R2xxx: Code organization

### Warning (W) - ~80 messages missing
**Priority:** Medium - Style and logic warnings

Key missing messages:
- W01xx: Unused variables and imports
- W1xxx: Dangerous patterns
- W2xxx: Style warnings

### Error (E) - ~50 messages missing
**Priority:** Critical - Probable bugs

Key missing messages:
- E01xx: Syntax and semantic errors
- E1xxx: Logic errors
- E2xxx: Import and name errors

### Fatal (F) - ~5 messages missing
**Priority:** Critical - Fatal errors

### Information (I) - ~4 messages missing
**Priority:** Low - Informational

---

## mypy Missing Rules (~44 rules)

**Current:** 6/50 (12%)  
**Priority:** High - Static type checking

Missing capabilities:
1. **Type Inference** - Infer types from usage patterns
2. **Type Narrowing** - Conditional type refinement
3. **Generic Types** - Generic type validation
4. **Protocols** - Structural/duck typing
5. **TypeVar Constraints** - TypeVar bounds and constraints
6. **Advanced Features** - ParamSpec, TypeGuard, Concatenate, etc.

---

## Priority Implementation Order

### Phase 9A (Weeks 1-4) - Immediate Critical
**Target:** +157 rules (265 → 422)

1. **Ruff S (Security)** - 73 rules
   - Map existing PyGuard security to Ruff S codes
   - Add missing Ruff S patterns
   
2. **Ruff E (PEP8 Errors)** - 43 rules
   - Complete E4xx (imports)
   - Complete E5xx (line length)
   - Complete E7xx (statements)
   
3. **Ruff F (Pyflakes)** - 41 rules
   - Import errors (F4xx)
   - Name errors (F5xx, F6xx, F8xx)

### Phase 9B (Weeks 5-8) - Short-term High Priority
**Target:** +136 rules (422 → 558)

1. **Ruff UP (pyupgrade)** - 35 rules
2. **Ruff PTH (pathlib)** - 34 rules
3. **Ruff PLE (Pylint errors)** - 36 rules
4. **Ruff PT (pytest)** - 31 rules

### Phase 10 (Weeks 9-16) - Medium-term
**Target:** +374 rules (558 → 932)

1. **Pylint R messages** - 100 rules
2. **Pylint C messages** - 150 rules
3. **Pylint W messages** - 80 rules
4. **mypy type inference** - 44 rules

### Phase 11-12 (Weeks 17-28) - Long-term
**Target:** Remaining to 1,536+

1. Framework-specific rules
2. Advanced metrics
3. Native formatting
4. Polish and optimization

---

## Auto-Fix Priorities

**Current:** ~150 auto-fixes  
**Target:** ~400 auto-fixes (for applicable rules)

**High Priority Auto-fixes:**
1. All UP (pyupgrade) rules - modernization
2. All PTH (pathlib) rules - path conversions
3. PEP8 E/W rules - formatting
4. Simple refactoring (Pylint R/C)

**Medium Priority Auto-fixes:**
5. Import organization (F, I)
6. Simplification (SIM)
7. Type annotations (ANN, UP)

**Low/No Auto-fix:**
- Security rules (S) - mostly detection
- Complex refactoring - needs human review
- Design metrics - detection only

---

## File Organization Recommendations

Given the massive scale (1,500+ rules), recommend restructuring:

```
pyguard/lib/
├── ruff/                    # NEW: Ruff-specific rules
│   ├── security.py         # S category (73 rules)
│   ├── pyflakes.py         # F category (43 rules)
│   ├── pep8_errors.py      # E category (60 rules)
│   ├── pyupgrade.py        # UP category (47 rules)
│   ├── pathlib.py          # PTH category (35 rules)
│   ├── pytest.py           # PT category (31 rules)
│   ├── bugbear.py          # B category (42 rules)
│   └── ...                 # Other Ruff categories
│
├── pylint/                  # NEW: Pylint-specific
│   ├── errors.py           # E messages (~50)
│   ├── warnings.py         # W messages (~80)
│   ├── refactor.py         # R messages (~100)
│   ├── convention.py       # C messages (~150)
│   └── ...
│
├── mypy/                    # NEW: Type checking
│   ├── type_inference.py
│   ├── type_narrowing.py
│   ├── protocols.py
│   └── generics.py
│
└── ... (existing modules)
```

This organization:
- Keeps rules organized by source tool
- Makes it easy to implement Ruff/Pylint/mypy compatibility
- Allows independent development of categories
- Clear mapping for users migrating from specific tools

---

**End of Document**
