# Unit Tests

This directory contains unit tests for the SIEM Agent codebase.

## Test Suites

### `test_sql_transform.py` - SQL Transformation Tests

Comprehensive test suite for HDX JOIN time range bug workaround (`siem_agent/sql_utils.py`).

**Background**: HDX database has a bug where JOIN queries fail with `hdx_query_timerange_required` error even when valid time range filters are present. The workaround automatically wraps the right-side JOIN table in a subquery containing its time filter.

**Test Coverage**:
- ✅ Simple JOIN with both time filters (primary use case)
- ✅ JOIN without AS keyword
- ✅ CDN table as right-side (different time column)
- ✅ Left-side only time filter (no transformation needed)
- ✅ Non-JOIN queries (pass-through)
- ✅ Existing subquery (no double-wrapping)
- ✅ Fully qualified table names
- ✅ Multiline query normalization
- ✅ Additional WHERE conditions preservation
- ✅ GROUP BY / ORDER BY / LIMIT preservation
- ✅ Unknown tables (no transformation)
- ✅ Edge cases (empty SQL, whitespace, case-insensitivity)

**Running Tests**:
```bash
# All SQL transform tests
uv run pytest tests/test_sql_transform.py -v

# Single test
uv run pytest tests/test_sql_transform.py::TestHdxJoinWorkaround::test_simple_join_with_aliases_both_time_filters -v

# With detailed output
uv run pytest tests/test_sql_transform.py -vv
```

**Integration**: The transformation is automatically applied in `execute.py` for all queries (both initial and repaired), so no manual intervention is needed.

## Adding New Tests

1. Create test file: `tests/test_<module>.py`
2. Follow pytest conventions (test functions start with `test_`)
3. Add pytest to dev dependencies if not already present: `uv add --dev pytest`
4. Run tests: `uv run pytest tests/ -v`
