# PyGuard Benchmarks

Performance benchmarks for PyGuard components.

## Running Benchmarks

```bash
# Run all benchmarks
python -m pytest benchmarks/ -v

# Run specific benchmark
python benchmarks/bench_security.py

# With profiling
python -m cProfile -o profile.stats benchmarks/bench_security.py
```

## Benchmark Categories

### Security Analysis (`bench_security.py`)
- Pattern detection performance
- Fix application speed
- Large file handling

### Best Practices (`bench_best_practices.py`)
- AST parsing performance
- Fix recommendation speed
- Complexity analysis

### Formatting (`bench_formatting.py`)
- Black formatting speed
- isort import sorting
- Large file performance

### End-to-End (`bench_e2e.py`)
- Full pipeline performance
- Multi-file projects
- Real-world scenarios

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Single file analysis | < 100ms | TBD |
| 100-file project | < 10s | TBD |
| 1000-file project | < 2min | TBD |

## Contributing

When adding new features:
1. Add corresponding benchmarks
2. Run benchmarks before and after
3. Document performance characteristics
4. Include results in PR description
