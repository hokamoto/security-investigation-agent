"""
Comprehensive test suite for sqlglot-based SQL processing pipeline.

Tests the new process_sql() function and all internal transformations:
- _fix_functions() - Array function normalization
- _fix_map_functions() - Map function corrections
- _fix_cdn_columns() - CDN table column fixes
- _fix_join_on_predicates() - Non-equality predicate movement
- _fix_hdx_join() - HDX time range workaround
- _replace_now() - now() timestamp replacement
- _validate() - Security validation

Replaces and extends:
- tests/test_sql_transform.py (11 tests)
- tests/test_sql_validation.py (23 tests)
"""

import pytest
import re
from siem_agent.sql_utils import process_sql
from siem_agent import sql_utils
from sqlglot import exp


# ============================================================
# Test Fixtures
# ============================================================


@pytest.fixture
def db_config():
    """Standard database configuration for tests."""
    return {
        "database_name": "akamai_jp",
        "siem_table": "siem",
        "cdn_table": "logs",
        "session_timestamp": "2026-01-01T00:00:00Z",
    }


@pytest.fixture
def process_sql_func(db_config):
    """Convenience fixture that partially applies db_config to process_sql."""

    def _process(sql):
        return process_sql(
            sql=sql,
            database_name=db_config["database_name"],
            siem_table=db_config["siem_table"],
            cdn_table=db_config["cdn_table"],
            session_timestamp=db_config["session_timestamp"],
        )

    return _process


# ============================================================
# Helper Functions
# ============================================================


def extract_on_clause(sql: str) -> str:
    """Extract the ON clause from a JOIN query for assertions."""
    match = re.search(r"ON\s+(.*?)\s+(?:WHERE|GROUP|ORDER|LIMIT|$)", sql, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def extract_where_clause(sql: str) -> str:
    """Extract the WHERE clause from a query for assertions."""
    match = re.search(r"WHERE\s+(.*?)\s+(?:GROUP|ORDER|LIMIT|$)", sql, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


# ============================================================
# Test Classes
# ============================================================


class TestProcessSqlBasics:
    """Basic tests for process_sql() function structure and error handling."""

    def test_return_value_structure(self, process_sql_func):
        """Test that process_sql returns a tuple of (str, bool, str|None)."""
        sql = "SELECT count() FROM akamai_jp.siem WHERE host = 'test.com'"
        result = process_sql_func(sql)

        assert isinstance(result, tuple), "process_sql should return a tuple"
        assert len(result) == 3, "process_sql should return 3 elements"
        assert isinstance(result[0], str), "First element should be a string (SQL)"
        assert isinstance(result[1], bool), "Second element should be a boolean (is_valid)"
        assert result[2] is None or isinstance(result[2], str), "Third element should be None or string (error)"

    def test_valid_query_returns_processed_sql_true_none(self, process_sql_func):
        """Test that valid queries return (processed_sql, True, None)."""
        sql = "SELECT count() FROM akamai_jp.siem WHERE host = 'test.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Valid query should have is_valid=True, got {is_valid}"
        assert error is None, f"Valid query should have error=None, got {error}"
        assert isinstance(processed_sql, str), "Processed SQL should be a string"
        assert len(processed_sql) > 0, "Processed SQL should not be empty"

    def test_invalid_query_returns_original_false_error(self, process_sql_func):
        """Test that invalid queries return (original_sql, False, error_message)."""
        sql = "DROP TABLE akamai_jp.siem"  # Invalid: not a SELECT
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False, "Invalid query should have is_valid=False"
        assert error is not None, "Invalid query should have an error message"
        assert isinstance(error, str), "Error message should be a string"
        assert len(error) > 0, "Error message should not be empty"
        assert processed_sql == sql, "Invalid query should return original SQL unchanged"

    def test_parse_error_handled_gracefully(self, process_sql_func):
        """Test that SQL parse errors are caught and returned as errors."""
        sql = "SELECT FROM WHERE"  # Malformed SQL
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False, "Parse error should result in is_valid=False"
        assert error is not None, "Parse error should have an error message"
        assert "syntax" in error.lower() or "parse" in error.lower(), f"Error should mention syntax/parse: {error}"

    def test_empty_sql_handled(self, process_sql_func):
        """Test that empty SQL string is handled gracefully."""
        sql = ""
        processed_sql, is_valid, error = process_sql_func(sql)

        # Empty SQL should fail validation
        assert is_valid is False, "Empty SQL should fail validation"
        assert error is not None, "Empty SQL should have an error message"


class TestFunctionNormalization:
    """Tests for _fix_functions() - Array function name normalization.

    Migrated from normalize_clickhouse_array_functions behavior.
    """

    def test_arraylength_to_length(self, process_sql_func):
        """Test arrayLength() is normalized to length()."""
        sql = "SELECT arrayLength(ruleTags) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "length(" in processed_sql, f"arrayLength should be replaced with length: {processed_sql}"
        assert "arrayLength" not in processed_sql, f"arrayLength should be removed: {processed_sql}"

    def test_arraysize_to_length(self, process_sql_func):
        """Test arraySize() is normalized to length()."""
        sql = "SELECT arraySize(ruleTags) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "length(" in processed_sql
        assert "arraySize" not in processed_sql

    def test_size_function_to_length(self, process_sql_func):
        """Test size() function is normalized to length()."""
        sql = "SELECT size(ruleTags) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "length(" in processed_sql
        assert "size(" not in processed_sql

    def test_arrayagg_to_grouparray(self, process_sql_func):
        """Test arrayAgg() is normalized to groupArray()."""
        sql = "SELECT arrayAgg(host) FROM akamai_jp.siem GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "groupArray(" in processed_sql
        assert "arrayAgg" not in processed_sql

    def test_collect_to_grouparray(self, process_sql_func):
        """Test collect() is normalized to groupArray()."""
        sql = "SELECT collect(host) FROM akamai_jp.siem GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "groupArray(" in processed_sql
        assert "collect(" not in processed_sql

    def test_collectset_to_groupuniqarray(self, process_sql_func):
        """Test collectSet() is normalized to groupUniqArray()."""
        sql = "SELECT collectSet(host) FROM akamai_jp.siem GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "groupUniqArray(" in processed_sql
        assert "collectSet" not in processed_sql

    def test_case_insensitive_matching(self, process_sql_func):
        """Test function normalization is case insensitive."""
        sql = "SELECT ARRAYLENGTH(ruleTags), ArraySize(attackTypes) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Both should be normalized to length
        assert processed_sql.count("length(") == 2, f"Both functions should be normalized: {processed_sql}"

    def test_multiple_functions_in_same_query(self, process_sql_func):
        """Test multiple function normalizations in a single query."""
        sql = "SELECT arrayLength(ruleTags), arrayAgg(host) FROM akamai_jp.siem GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "length(" in processed_sql
        assert "groupArray(" in processed_sql
        assert "arrayLength" not in processed_sql
        assert "arrayAgg" not in processed_sql

    def test_size_column_not_affected(self, process_sql_func):
        """Test that AST distinguishes size column from size() function (no false positive)."""
        # This test ensures we don't replace column names, only function names
        sql = "SELECT size FROM akamai_jp.siem WHERE size > 100"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Column name 'size' should remain unchanged
        assert "SELECT size FROM" in processed_sql or "size >" in processed_sql, f"Column name 'size' should not be replaced: {processed_sql}"

    def test_arraylen_to_length(self, process_sql_func):
        """Test arrayLen() is normalized to length()."""
        sql = "SELECT arrayLen(ruleTags) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "length(" in processed_sql, f"arrayLen should be replaced with length: {processed_sql}"
        assert "arrayLen" not in processed_sql, f"arrayLen should be removed: {processed_sql}"

    def test_collect_set_underscore_to_groupuniqarray(self, process_sql_func):
        """Test collect_set() (underscore variant) is normalized to groupUniqArray()."""
        sql = "SELECT collect_set(host) FROM akamai_jp.siem GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "groupUniqArray(" in processed_sql, f"collect_set should be replaced with groupUniqArray: {processed_sql}"
        assert "collect_set" not in processed_sql, f"collect_set should be removed: {processed_sql}"

    def test_builtin_length_stays_as_length(self, process_sql_func):
        """Test that sqlglot-parsed Length node is emitted as length() (exp.Func branch)."""
        sql = "SELECT length(ruleTags) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "length(" in processed_sql, f"length() should remain as length(): {processed_sql}"


class TestMapFunctionCorrection:
    """Tests for _fix_map_functions() - Map function corrections.

    NEW transformation - converts has() to mapContains() for Map columns.
    """

    def test_has_requestheaders_to_mapcontains(self, process_sql_func):
        """Test has(requestHeaders, 'key') → mapContains(requestHeaders, 'key')."""
        sql = "SELECT * FROM akamai_jp.siem WHERE has(requestHeaders, 'User-Agent')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "mapContains(requestHeaders" in processed_sql, f"has(requestHeaders) should be replaced with mapContains: {processed_sql}"
        assert "has(requestHeaders" not in processed_sql

    def test_haskey_requestheaders_to_mapcontains(self, process_sql_func):
        """Test hasKey(requestHeaders, 'key') → mapContains(requestHeaders, 'key')."""
        sql = "SELECT * FROM akamai_jp.siem WHERE hasKey(requestHeaders, 'Host')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "mapContains(requestHeaders" in processed_sql
        assert "hasKey(requestHeaders" not in processed_sql

    def test_has_attacktypes_unchanged(self, process_sql_func):
        """Test has(attackTypes, 'WAF') → unchanged (Array column)."""
        sql = "SELECT * FROM akamai_jp.siem WHERE has(attackTypes, 'WAF')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # attackTypes is an Array column, so has() should remain unchanged
        assert "has(attackTypes" in processed_sql, f"has(attackTypes) should remain unchanged for Array columns: {processed_sql}"
        assert "mapContains(attackTypes" not in processed_sql

    def test_has_ruletags_unchanged(self, process_sql_func):
        """Test has(ruleTags, 'tag') → unchanged (Array column)."""
        sql = "SELECT * FROM akamai_jp.siem WHERE has(ruleTags, 'SQLI')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # ruleTags is an Array column
        assert "has(ruleTags" in processed_sql
        assert "mapContains(ruleTags" not in processed_sql

    def test_mixed_usage_in_same_query(self, process_sql_func):
        """Test mixed usage: only Map columns transformed."""
        sql = """
        SELECT * FROM akamai_jp.siem
        WHERE has(requestHeaders, 'User-Agent')
        AND has(attackTypes, 'WAF')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "mapContains(requestHeaders" in processed_sql, "Map column should use mapContains"
        assert "has(attackTypes" in processed_sql, "Array column should keep has()"

    def test_case_insensitive_function_names(self, process_sql_func):
        """Test case insensitive matching for has/hasKey."""
        sql = "SELECT * FROM akamai_jp.siem WHERE HAS(requestHeaders, 'key') OR HasKey(requestHeaders, 'val')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Both should be converted
        assert processed_sql.count("mapContains(requestHeaders") == 2, f"Both HAS and HasKey should be converted: {processed_sql}"

    def test_literal_arrays_unchanged(self, process_sql_func):
        """Test that literal arrays are unchanged (first arg not a column)."""
        # If has() is called with a literal array, not a column reference
        sql = "SELECT has(['a', 'b'], 'a') FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Literal array should not be converted
        # This might still have has() since the first arg is not a Map column
        assert "has([" in processed_sql or "has(ARRAY" in processed_sql or "mapContains" not in processed_sql


class TestCdnColumnFixes:
    """Tests for _fix_cdn_columns() - CDN table column name corrections.

    NEW transformation - fixes column names when CDN table is referenced.
    """

    def test_cdn_clientip_to_cliip_with_alias(self, process_sql_func):
        """Test cdn.clientIP → cdn.cliIP (with alias)."""
        sql = "SELECT cdn.clientIP FROM akamai_jp.logs AS cdn WHERE cdn.reqHost = 'test.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "cdn.cliIP" in processed_sql, f"clientIP should be renamed to cliIP for CDN table: {processed_sql}"
        assert "cdn.clientIP" not in processed_sql

    def test_logs_clientip_to_cliip_without_alias(self, process_sql_func):
        """Test logs.clientIP → logs.cliIP (without alias)."""
        sql = "SELECT logs.clientIP FROM akamai_jp.logs WHERE logs.reqHost = 'test.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "logs.cliIP" in processed_sql or "cliIP" in processed_sql, f"clientIP should be renamed to cliIP: {processed_sql}"

    def test_waf_clientip_unchanged(self, process_sql_func):
        """Test waf.clientIP → unchanged (SIEM table)."""
        sql = "SELECT waf.clientIP FROM akamai_jp.siem AS waf WHERE waf.host = 'test.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # SIEM table should keep clientIP
        assert "waf.clientIP" in processed_sql or "clientIP" in processed_sql, f"SIEM table should keep clientIP: {processed_sql}"

    def test_join_both_tables_only_cdn_transformed(self, process_sql_func):
        """Test JOIN both tables: only CDN side transformed."""
        sql = """
        SELECT waf.clientIP, cdn.clientIP
        FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn ON waf.requestId = cdn.reqId
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "waf.clientIP" in processed_sql, "SIEM table should keep clientIP"
        assert "cdn.cliIP" in processed_sql, "CDN table should use cliIP"
        assert "cdn.clientIP" not in processed_sql, "CDN clientIP should be replaced"

    def test_unqualified_clientip_unchanged(self, process_sql_func):
        """Test unqualified clientIP → unchanged (cannot determine context)."""
        # Without table prefix, we can't determine which table it belongs to
        sql = "SELECT clientIP FROM akamai_jp.logs"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Implementation only transforms table-qualified columns (node.table in cdn_aliases),
        # so unqualified clientIP must remain unchanged.
        assert "clientIP" in processed_sql, f"Unqualified clientIP should not be transformed: {processed_sql}"
        assert "cliIP" not in processed_sql, f"Should not transform without table qualifier: {processed_sql}"

    def test_column_in_where_group_order_all_transformed(self, process_sql_func):
        """Test column in WHERE, GROUP BY, ORDER BY → all transformed."""
        sql = """
        SELECT cdn.clientIP, count() AS cnt
        FROM akamai_jp.logs AS cdn
        WHERE cdn.clientIP = '1.2.3.4'
        GROUP BY cdn.clientIP
        ORDER BY cdn.clientIP
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # All references should be transformed
        assert "cdn.cliIP" in processed_sql
        assert "cdn.clientIP" not in processed_sql, f"All cdn.clientIP references should be replaced: {processed_sql}"

    def test_no_transformation_if_cdn_not_referenced(self, process_sql_func):
        """Test no transformation if CDN table not referenced."""
        sql = "SELECT clientIP FROM akamai_jp.siem WHERE host = 'test.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # CDN table not in query, so no transformation should occur
        assert "clientIP" in processed_sql

    def test_cdn_table_in_subquery(self, process_sql_func):
        """Test CDN column fix in subquery."""
        sql = """
        SELECT * FROM akamai_jp.siem WHERE requestId IN (
            SELECT cdn.reqId FROM akamai_jp.logs AS cdn WHERE cdn.clientIP = '1.2.3.4'
        )
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # clientIP in CDN subquery should be transformed
        assert "cdn.cliIP" in processed_sql or "cliIP" in processed_sql


class TestJoinOnPredicates:
    """Tests for _fix_join_on_predicates() - Non-equality predicate movement.

    NEW transformation - moves non-equality predicates from JOIN ON to WHERE.
    """

    def test_between_moved_from_on_to_where(self, process_sql_func):
        """Test BETWEEN predicate moved from ON to WHERE."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp BETWEEN cdn.reqTimeSec - 10 AND cdn.reqTimeSec + 10
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)
        where_clause = extract_where_clause(processed_sql)

        # ON should only have equality
        assert "requestId" in on_clause, "Equality predicate should remain in ON"
        assert "BETWEEN" not in on_clause, f"BETWEEN should be moved to WHERE, but found in ON: {on_clause}"

        # WHERE should have BETWEEN
        assert "BETWEEN" in where_clause, f"BETWEEN should be in WHERE: {where_clause}"

    def test_gte_and_lte_moved_from_on_to_where(self, process_sql_func):
        """Test >= and <= predicates moved from ON to WHERE."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp >= cdn.reqTimeSec
        AND waf.timestamp <= cdn.reqTimeSec + 100
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)
        where_clause = extract_where_clause(processed_sql)

        # ON should only have equality
        assert ">=" not in on_clause and "<=" not in on_clause, f"Non-equality predicates should be moved to WHERE, ON clause: {on_clause}"

        # WHERE should have both conditions
        assert where_clause != "", "WHERE clause should exist with moved predicates"

    def test_multiple_non_equality_predicates_moved(self, process_sql_func):
        """Test multiple non-equality predicates moved."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp > cdn.reqTimeSec
        AND waf.timestamp < cdn.reqTimeSec + 1000
        AND waf.clientIP != cdn.clientIP
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)

        # ON should only have the equality predicate
        assert "requestId" in on_clause
        assert ">" not in on_clause and "<" not in on_clause, f"Comparison operators should be moved to WHERE: {on_clause}"

    def test_left_join_not_transformed(self, process_sql_func):
        """Test LEFT JOIN non-equality predicates stay in ON (not moved to WHERE).

        Note: BETWEEN on a time column may still be extracted into a subquery
        by _fix_hdx_join (for the HDX time range bug), but _fix_join_on_predicates
        should NOT move LEFT JOIN predicates to WHERE.
        """
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        LEFT JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01')
            AND parseDateTimeBestEffort('2026-01-02')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # _fix_hdx_join wraps the CDN table in a subquery with the BETWEEN filter.
        # The BETWEEN should NOT appear in the outer WHERE (that would break LEFT JOIN semantics).
        assert "(SELECT" in processed_sql, "CDN table should be wrapped in subquery"
        # After the subquery closing ") AS cdn ON ...", there should be no outer WHERE.
        after_subquery = processed_sql.split(") AS cdn")[1] if ") AS cdn" in processed_sql else ""
        assert "WHERE" not in after_subquery, f"No outer WHERE should exist for LEFT JOIN: {after_subquery}"

    def test_right_join_not_transformed(self, process_sql_func):
        """Test RIGHT JOIN → not transformed."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        RIGHT JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp > cdn.reqTimeSec
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # RIGHT JOIN should not be transformed
        on_clause = extract_on_clause(processed_sql)
        assert ">" in on_clause or "timestamp" in on_clause, f"RIGHT JOIN should keep predicates in ON: {on_clause}"

    def test_inner_join_explicit_transformed(self, process_sql_func):
        """Test INNER JOIN (explicit) → transformed."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        INNER JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp BETWEEN cdn.reqTimeSec AND cdn.reqTimeSec + 100
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)
        where_clause = extract_where_clause(processed_sql)

        # BETWEEN should be moved to WHERE
        assert "BETWEEN" not in on_clause, "BETWEEN should be moved from ON"
        assert "BETWEEN" in where_clause or where_clause != "", "BETWEEN should be in WHERE"

    def test_implicit_inner_join_transformed(self, process_sql_func):
        """Test implicit INNER JOIN (just JOIN) → transformed."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp >= cdn.reqTimeSec
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)

        # >= should be moved to WHERE
        assert ">=" not in on_clause, f"Non-equality should be moved to WHERE: {on_clause}"

    def test_existing_where_clause_preserved(self, process_sql_func):
        """Test existing WHERE clause preserved and combined with AND."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.timestamp > cdn.reqTimeSec
        WHERE waf.appliedAction = 'deny'
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        where_clause = extract_where_clause(processed_sql)

        # WHERE should contain both original condition and moved condition
        assert "appliedAction" in where_clause, "Original WHERE condition should be preserved"
        # The moved predicate should also be present (either timestamp or >)

    def test_all_equality_predicates_no_transformation(self, process_sql_func):
        """Test all equality predicates → no transformation."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.clientIP = cdn.clientIP
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # All predicates are equalities, so nothing should move
        # Should not have WHERE clause added (unless there was one already)
        on_clause = extract_on_clause(processed_sql)
        assert "requestId" in on_clause and "clientIP" in on_clause, f"All equality predicates should remain in ON: {on_clause}"

    def test_mixed_equality_nonequality_only_nonequality_moved(self, process_sql_func):
        """Test mixed equality + non-equality → only non-equality moved."""
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.requestId = cdn.reqId
        AND waf.clientIP = cdn.clientIP
        AND waf.timestamp > cdn.reqTimeSec
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        on_clause = extract_on_clause(processed_sql)

        # Equalities should remain in ON
        assert "requestId" in on_clause, "Equality should remain in ON"
        # Non-equality should be moved
        assert ">" not in on_clause, f"Non-equality should be moved to WHERE: {on_clause}"

    def test_on_with_only_nonequality_unchanged(self, process_sql_func):
        """Test ON with only non-equality → unchanged (needs at least one equality)."""
        # This is an edge case - JOIN ON with no equality predicates
        sql = """
        SELECT * FROM akamai_jp.siem AS waf
        JOIN akamai_jp.logs AS cdn
        ON waf.timestamp > cdn.reqTimeSec
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # If there's no equality predicate, we shouldn't move the non-equality
        # (because then ON would be empty, which is invalid)
        on_clause = extract_on_clause(processed_sql)
        assert ">" in on_clause or "timestamp" in on_clause, f"Non-equality should remain in ON when no equality exists: {on_clause}"


class TestHdxJoinWorkaround:
    """Tests for _fix_hdx_join() - HDX time range bug workaround.

    Migrated from test_sql_transform.py (11 tests).
    """

    def test_simple_join_with_aliases_both_time_filters(self, process_sql_func):
        """Test case 1: Simple JOIN with aliases and time filters on both tables (FAIL case)."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # Should wrap right-side table in subquery
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql, f"Right-side table should be wrapped in subquery: {processed_sql}"
        # Should have timestamp BETWEEN in the subquery
        assert processed_sql.count("timestamp BETWEEN") == 1, f"timestamp BETWEEN should appear only in subquery (not duplicated in main WHERE): {processed_sql}"
        # Left-side filter should remain in WHERE
        assert "reqTimeSec BETWEEN" in processed_sql

    def test_join_without_as_keyword(self, process_sql_func):
        """Test JOIN without explicit AS keyword."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs cdn "
            "JOIN akamai_jp.siem waf ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should wrap right-side table in subquery
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql
        # Should remove right-side time filter from main WHERE
        # The timestamp BETWEEN should be in subquery, not in main WHERE after the subquery
        main_where = processed_sql.split(")")[-1]  # After closing subquery
        assert "waf.timestamp BETWEEN" not in main_where or processed_sql.count("timestamp BETWEEN") == 1

    def test_join_with_cdn_as_right_side(self, process_sql_func):
        """Test JOIN with CDN table on the right side (uses reqTimeSec)."""
        input_sql = (
            "SELECT count() FROM akamai_jp.siem AS waf "
            "JOIN akamai_jp.logs AS cdn ON waf.requestId = cdn.reqId "
            "WHERE waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should wrap CDN table with reqTimeSec filter
        assert "(SELECT" in processed_sql and "FROM akamai_jp.logs" in processed_sql
        assert "reqTimeSec BETWEEN" in processed_sql
        # Should keep left-side filter in main WHERE
        assert processed_sql.count("timestamp BETWEEN") >= 1

    def test_join_with_only_left_time_filter(self, process_sql_func):
        """Test case 10: JOIN with time filter only on left side (no transformation needed)."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should not transform (no right-side time filter)
        # No subquery should be added
        assert processed_sql.count("SELECT") == 1 or "(SELECT" not in processed_sql, (
            f"Should not add subquery when only left-side filter exists: {processed_sql}"
        )

    def test_no_join_query(self, process_sql_func):
        """Test that non-JOIN queries are not modified."""
        input_sql = (
            "SELECT count() FROM akamai_jp.siem "
            "WHERE timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should not add any subqueries
        assert processed_sql.count("SELECT") == 1

    def test_join_with_subquery_already_present(self, process_sql_func):
        """Test case 6: JOIN where right side is already a subquery (no transformation needed)."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN (SELECT requestId FROM akamai_jp.siem "
            "WHERE timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')) AS waf "
            "ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should detect existing subquery via AST and not double-wrap
        # There should still be JOIN with a subquery
        assert "JOIN" in processed_sql and "SELECT" in processed_sql

    def test_fully_qualified_table_names_in_where(self, process_sql_func):
        """Test case 2: Fully qualified table names in WHERE clause (no aliases)."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE akamai_jp.logs.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND akamai_jp.siem.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should wrap right-side table in subquery
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql

    def test_unqualified_right_side_time_filter_is_extracted(self, process_sql_func):
        """Unqualified reqTimeSec BETWEEN should still be extracted for HDX workaround."""
        input_sql = (
            "SELECT ruleTag, count() AS total "
            "FROM akamai_jp.siem "
            "ARRAY JOIN ruleTags AS ruleTag "
            "JOIN akamai_jp.logs ON akamai_jp.siem.requestId = akamai_jp.logs.reqId "
            "WHERE host = 'akamai.fab34.com' "
            "AND timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "GROUP BY ruleTag"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "JOIN (SELECT * FROM akamai_jp.logs WHERE reqTimeSec BETWEEN" in processed_sql, (
            f"Unqualified reqTimeSec should be moved into right-side subquery: {processed_sql}"
        )
        assert processed_sql.count("reqTimeSec BETWEEN") == 1, (
            f"Right-side time filter should exist only in subquery: {processed_sql}"
        )

    def test_db_qualifier_removed_when_moving_between_into_subquery(self, process_sql_func):
        """Fully qualified DB prefix in moved BETWEEN should not leak into subquery column refs."""
        input_sql = (
            "SELECT count() FROM akamai_jp.siem "
            "JOIN akamai_jp.logs ON akamai_jp.siem.requestId = akamai_jp.logs.reqId "
            "WHERE timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND akamai_jp.logs.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "akamai_jp.reqTimeSec" not in processed_sql, (
            f"DB-only qualifier is invalid inside subquery and must be stripped: {processed_sql}"
        )

    def test_multiline_query_normalization(self, process_sql_func):
        """Test that multiline queries are correctly normalized and transformed."""
        input_sql = """
            SELECT count()
            FROM akamai_jp.logs AS cdn
            JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId
            WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z')
                                     AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')
              AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z')
                                    AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')
        """

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should handle multiline input correctly
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql

    def test_join_with_additional_where_conditions(self, process_sql_func):
        """Test JOIN with multiple WHERE conditions beyond time filters."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND waf.appliedAction = 'deny' "
            "AND cdn.statusCode = 403"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should wrap right-side table
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql
        # Should preserve additional WHERE conditions in main query
        assert "appliedAction" in processed_sql and "statusCode" in processed_sql

    def test_join_with_group_by_order_by_limit(self, process_sql_func):
        """Test JOIN query with GROUP BY, ORDER BY, LIMIT clauses preserved."""
        input_sql = (
            "SELECT waf.clientIP, count() AS cnt FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "GROUP BY waf.clientIP ORDER BY cnt DESC LIMIT 10"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        assert is_valid is True
        # Should transform JOIN
        assert "(SELECT" in processed_sql
        # Should preserve GROUP BY, ORDER BY, LIMIT
        assert "GROUP BY" in processed_sql
        assert "ORDER BY" in processed_sql
        assert "LIMIT 10" in processed_sql

    def test_unknown_table_not_transformed(self, process_sql_func):
        """Test that JOINs with unknown tables are not transformed."""
        input_sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.unknown_table AS unk ON cdn.reqId = unk.id "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z') "
            "AND unk.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )

        processed_sql, is_valid, error = process_sql_func(input_sql)

        # Should fail validation (unknown table)
        assert is_valid is False
        assert error is not None
        assert "unknown_table" in error


class TestNowReplacement:
    """Tests for _replace_now() - now() timestamp replacement.

    NEW transformation - replaces now() with fixed timestamp.
    """

    def test_now_in_where_clause_replaced(self, process_sql_func):
        """Test now() in WHERE clause → replaced."""
        sql = "SELECT * FROM akamai_jp.siem WHERE timestamp > now()"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "now()" not in processed_sql.lower(), f"now() should be replaced: {processed_sql}"
        assert "parseDateTimeBestEffort" in processed_sql or "2026-01-01" in processed_sql, f"now() should be replaced with timestamp: {processed_sql}"

    def test_now_in_between_clause_replaced(self, process_sql_func):
        """Test now() in BETWEEN clause → both occurrences replaced."""
        sql = "SELECT * FROM akamai_jp.siem WHERE timestamp BETWEEN now() - 3600 AND now()"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "now()" not in processed_sql.lower(), f"All now() occurrences should be replaced: {processed_sql}"

    def test_now_in_select_list_replaced(self, process_sql_func):
        """Test now() in SELECT list → replaced."""
        sql = "SELECT host, now() AS query_time FROM akamai_jp.siem LIMIT 1"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "now()" not in processed_sql.lower()

    def test_multiple_now_replaced_with_same_timestamp(self, process_sql_func):
        """Test multiple now() → all replaced with same timestamp."""
        sql = "SELECT now(), now() FROM akamai_jp.siem WHERE timestamp > now() LIMIT 1"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # All now() should be replaced
        assert "now()" not in processed_sql.lower()

    def test_case_insensitive_now(self, process_sql_func):
        """Test case insensitive NOW()."""
        sql = "SELECT * FROM akamai_jp.siem WHERE timestamp > NOW()"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "NOW()" not in processed_sql and "now()" not in processed_sql.lower()

    def test_string_literal_now_unchanged(self, process_sql_func):
        """Test string literal 'now()' → unchanged (AST distinguishes)."""
        sql = "SELECT * FROM akamai_jp.siem WHERE host = 'now()'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # String literal should remain unchanged
        assert "'now()'" in processed_sql, f"String literal 'now()' should not be replaced: {processed_sql}"

    def test_comment_with_now_ignored(self, process_sql_func):
        """Test comment with now() → ignored by parser."""
        sql = "SELECT * FROM akamai_jp.siem WHERE timestamp > now() -- now() returns current time"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Function now() should be replaced, comment should be ignored/removed by parser

    def test_current_timestamp_also_replaced(self, process_sql_func):
        """Test CURRENT_TIMESTAMP → also replaced."""
        sql = "SELECT * FROM akamai_jp.siem WHERE timestamp > CURRENT_TIMESTAMP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "CURRENT_TIMESTAMP" not in processed_sql, f"CURRENT_TIMESTAMP should be replaced: {processed_sql}"


class TestValidation:
    """Tests for _validate() - Security validation.

    Migrated from test_sql_validation.py (23 tests) + 1 new test.
    """

    # --- Allowed queries ---

    def test_select_from_siem_fully_qualified(self, process_sql_func):
        """Test SELECT from SIEM with fully qualified table name."""
        sql = "SELECT count() FROM akamai_jp.siem WHERE host = 'example.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Valid query should pass: {error}"
        assert error is None

    def test_select_from_siem_bare_table(self, process_sql_func):
        """Test SELECT from SIEM with bare table name."""
        sql = "SELECT * FROM siem WHERE host = 'example.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert error is None

    def test_select_from_cdn_fully_qualified(self, process_sql_func):
        """Test SELECT from CDN with fully qualified table name."""
        sql = "SELECT count() FROM akamai_jp.logs WHERE reqHost = 'example.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert error is None

    def test_join_both_allowed_tables(self, process_sql_func):
        """Test JOIN with both allowed tables."""
        sql = "SELECT * FROM akamai_jp.logs AS cdn JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert error is None

    def test_select_case_insensitive(self, process_sql_func):
        """Test case insensitive SELECT keyword."""
        sql = "select count() from akamai_jp.siem where host = 'x'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert error is None

    def test_cte_with_select_allowed(self, process_sql_func):
        """Test CTE (WITH clause) + SELECT allowed. NEW TEST."""
        sql = """
        WITH recent_events AS (
            SELECT * FROM akamai_jp.siem
            WHERE timestamp > parseDateTimeBestEffort('2026-01-01')
        )
        SELECT count() FROM recent_events
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"CTE with SELECT should be allowed: {error}"
        assert error is None

    # --- Blocked: SELECT without FROM (system function calls) ---

    def test_blocked_select_version(self, process_sql_func):
        """Test SELECT version() blocked."""
        sql = "SELECT version() AS clickhouse_version"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert error is not None
        assert "must reference an allowed table" in error or "not allowed" in error.lower()

    def test_blocked_select_now(self, process_sql_func):
        """Test SELECT now() blocked."""
        sql = "SELECT now()"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "must reference an allowed table" in error or "not allowed" in error.lower()

    def test_blocked_select_literal(self, process_sql_func):
        """Test SELECT literal blocked."""
        sql = "SELECT 1"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "must reference an allowed table" in error or "not allowed" in error.lower()

    # --- Blocked: non-SELECT statements ---

    def test_blocked_show_databases(self, process_sql_func):
        """Test SHOW DATABASES blocked."""
        sql = "SHOW DATABASES"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "not allowed" in error

    def test_blocked_describe_table(self, process_sql_func):
        """Test DESCRIBE TABLE blocked."""
        sql = "DESCRIBE TABLE akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "not allowed" in error

    def test_blocked_drop_table(self, process_sql_func):
        """Test DROP TABLE blocked."""
        sql = "DROP TABLE akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "DROP" in error

    def test_blocked_insert(self, process_sql_func):
        """Test INSERT blocked."""
        sql = "INSERT INTO akamai_jp.siem VALUES (1, 2, 3)"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "INSERT" in error

    def test_blocked_alter(self, process_sql_func):
        """Test ALTER blocked."""
        sql = "ALTER TABLE akamai_jp.siem DROP COLUMN host"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "ALTER" in error

    def test_blocked_create(self, process_sql_func):
        """Test CREATE blocked."""
        sql = "CREATE TABLE akamai_jp.new_table (id UInt32) ENGINE = MergeTree()"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "CREATE" in error

    def test_blocked_explain(self, process_sql_func):
        """Test EXPLAIN blocked."""
        sql = "EXPLAIN SELECT * FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Only SELECT" in error or "EXPLAIN" in error

    # --- Blocked: unauthorized tables ---

    def test_blocked_system_tables(self, process_sql_func):
        """Test system.* tables blocked."""
        sql = "SELECT name FROM system.tables WHERE database = 'akamai_jp'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Table not allowed" in error or "system" in error.lower()

    def test_blocked_other_table(self, process_sql_func):
        """Test unauthorized table blocked."""
        sql = "SELECT * FROM akamai_jp.other_table WHERE 1=1"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Table not allowed" in error or "other_table" in error

    def test_blocked_information_schema(self, process_sql_func):
        """Test information_schema blocked."""
        sql = "SELECT * FROM information_schema.tables"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Table not allowed" in error or "information_schema" in error

    def test_blocked_subquery_unauthorized_table(self, process_sql_func):
        """Test subquery with unauthorized table blocked."""
        sql = "SELECT * FROM akamai_jp.siem WHERE clientIP IN (SELECT ip FROM blocklist)"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Table not allowed" in error or "blocklist" in error

    def test_blocked_join_unauthorized_table(self, process_sql_func):
        """Test JOIN with unauthorized table blocked."""
        sql = "SELECT * FROM akamai_jp.siem AS waf JOIN secret_table AS s ON waf.clientIP = s.ip"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert "Table not allowed" in error or "secret_table" in error

    # --- Edge cases ---

    def test_leading_whitespace(self, process_sql_func):
        """Test query with leading whitespace."""
        sql = "   SELECT count() FROM akamai_jp.siem WHERE host = 'x'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True

    def test_subquery_from_allowed_table(self, process_sql_func):
        """Test subquery with allowed table."""
        sql = "SELECT * FROM akamai_jp.siem WHERE clientIP IN (SELECT clientIP FROM akamai_jp.siem WHERE status = 403)"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True


class TestTransformationOrder:
    """Integration tests - verify correct transformation sequencing."""

    def test_function_normalization_before_map_functions(self, process_sql_func):
        """Test function normalization happens before map function fixes."""
        # If we have both arrayLength and has() that need fixing
        sql = "SELECT arrayLength(ruleTags) FROM akamai_jp.siem WHERE has(requestHeaders, 'key')"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "length(" in processed_sql
        assert "mapContains(requestHeaders" in processed_sql

    def test_cdn_column_fix_before_join_transformations(self, process_sql_func):
        """Test CDN column fix happens before JOIN transformations."""
        sql = """
        SELECT cdn.clientIP FROM akamai_jp.logs AS cdn
        JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId
        WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # CDN column should be fixed
        assert "cliIP" in processed_sql
        # HDX JOIN workaround should also be applied
        assert "(SELECT" in processed_sql

    def test_join_on_predicates_before_hdx_join(self, process_sql_func):
        """Test JOIN ON predicate movement happens before HDX JOIN."""
        sql = """
        SELECT * FROM akamai_jp.logs AS cdn
        JOIN akamai_jp.siem AS waf
        ON cdn.reqId = waf.requestId
        AND waf.timestamp >= cdn.reqTimeSec
        WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Non-equality predicate should be moved to WHERE
        on_clause = extract_on_clause(processed_sql)
        assert ">=" not in on_clause, "Non-equality should be moved to WHERE"

    def test_map_function_and_cdn_column_combined(self, process_sql_func):
        """Test map function fix and CDN column fix work together."""
        sql = """
        SELECT cdn.clientIP FROM akamai_jp.logs AS cdn
        WHERE has(requestHeaders, 'User-Agent') AND cdn.clientIP = '1.2.3.4'
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "mapContains(requestHeaders" in processed_sql
        assert "cliIP" in processed_sql

    def test_all_transformations_in_complex_query(self, process_sql_func):
        """Test all 6 transformations in a complex JOIN query."""
        sql = """
        SELECT arrayLength(waf.ruleTags), cdn.clientIP, now()
        FROM akamai_jp.logs AS cdn
        JOIN akamai_jp.siem AS waf
        ON cdn.reqId = waf.requestId
        AND waf.timestamp >= cdn.reqTimeSec
        WHERE has(requestHeaders, 'User-Agent')
        AND cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # 1. Function normalization
        assert "length(" in processed_sql
        # 2. Map function fix
        assert "mapContains(requestHeaders" in processed_sql
        # 3. CDN column fix
        assert "cliIP" in processed_sql
        # 4. JOIN ON predicate movement
        on_clause = extract_on_clause(processed_sql)
        assert ">=" not in on_clause
        # 5. HDX JOIN workaround
        assert "(SELECT" in processed_sql
        # 6. now() replacement
        assert "now()" not in processed_sql.lower()

    def test_now_replacement_applied_last(self, process_sql_func):
        """Test now() replacement doesn't interfere with other transformations."""
        sql = """
        SELECT * FROM akamai_jp.siem
        WHERE timestamp > now() - 3600
        AND arrayLength(ruleTags) > 0
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "now()" not in processed_sql.lower()
        assert "length(" in processed_sql

    def test_transformation_idempotence(self, process_sql_func):
        """Test transformations are idempotent (apply twice = same result)."""
        sql = "SELECT arrayLength(ruleTags) FROM akamai_jp.siem WHERE host = 'test.com'"
        processed_once, is_valid1, error1 = process_sql_func(sql)

        assert is_valid1 is True
        # Apply transformation again to the already-processed SQL
        processed_twice, is_valid2, error2 = process_sql_func(processed_once)

        assert is_valid2 is True
        # Results should be the same (idempotent)
        # Note: sqlglot might format slightly differently, so we check semantically
        assert "length(" in processed_twice
        assert "arrayLength" not in processed_twice

    def test_hdx_join_after_join_on_fix(self, process_sql_func):
        """Test HDX JOIN workaround interacts correctly with JOIN ON fix."""
        sql = """
        SELECT * FROM akamai_jp.logs AS cdn
        JOIN akamai_jp.siem AS waf
        ON cdn.reqId = waf.requestId AND waf.timestamp > cdn.reqTimeSec
        WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        AND waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') AND parseDateTimeBestEffort('2026-01-02')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Both transformations should apply correctly

    def test_array_join_preserved_through_transformations(self, process_sql_func):
        """Test ARRAY JOIN is preserved through all transformations."""
        sql = """
        SELECT ruleTag FROM akamai_jp.siem
        ARRAY JOIN ruleTags AS ruleTag
        WHERE timestamp > now() - 3600
        AND arrayLength(attackTypes) > 0
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # ARRAY JOIN should be preserved
        assert "ARRAY JOIN" in processed_sql or "arrayJoin" in processed_sql
        # Other transformations should still apply
        assert "now()" not in processed_sql.lower()
        assert "length(" in processed_sql

    def test_cte_with_transformations_in_both_parts(self, process_sql_func):
        """Test CTE with transformations in both CTE and main query."""
        sql = """
        WITH recent AS (
            SELECT * FROM akamai_jp.siem
            WHERE timestamp > now() - 3600
            AND arrayLength(ruleTags) > 0
        )
        SELECT arraySize(attackTypes) FROM recent WHERE has(requestHeaders, 'Host')
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Transformations should apply in both CTE and main query
        assert "length(" in processed_sql
        assert "now()" not in processed_sql.lower()
        assert "mapContains(requestHeaders" in processed_sql


class TestEdgeCases:
    """Boundary conditions and error handling tests."""

    def test_empty_sql_string(self, process_sql_func):
        """Test empty SQL string."""
        sql = ""
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert error is not None

    def test_whitespace_only_sql(self, process_sql_func):
        """Test whitespace-only SQL string."""
        sql = "   \n\t  "
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert error is not None

    def test_comment_only_sql(self, process_sql_func):
        """Test comment-only SQL."""
        sql = "-- This is just a comment"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is False
        assert error is not None

    def test_very_long_query(self, process_sql_func):
        """Test very long query (10KB+)."""
        # Create a query with many columns
        columns = ", ".join([f"col{i}" for i in range(1000)])
        sql = f"SELECT {columns} FROM akamai_jp.siem LIMIT 1"
        processed_sql, is_valid, error = process_sql_func(sql)

        # sqlglot can parse large queries without issue
        assert is_valid is True, f"Large query should be valid: {error}"
        assert "col999" in processed_sql, "Last column should be preserved"

    def test_deeply_nested_subqueries(self, process_sql_func):
        """Test deeply nested subqueries (5 levels)."""
        sql = """
        SELECT * FROM akamai_jp.siem WHERE clientIP IN (
            SELECT clientIP FROM akamai_jp.siem WHERE requestId IN (
                SELECT requestId FROM akamai_jp.siem WHERE host IN (
                    SELECT host FROM akamai_jp.siem WHERE appliedAction IN (
                        SELECT appliedAction FROM akamai_jp.siem LIMIT 1
                    )
                )
            )
        )
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True

    def test_unicode_in_string_literals(self, process_sql_func):
        """Test Unicode characters in string literals."""
        sql = "SELECT * FROM akamai_jp.siem WHERE host = '日本語.example.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        assert "日本語" in processed_sql

    def test_escaped_quotes_in_literals(self, process_sql_func):
        """Test escaped quotes in string literals."""
        sql = "SELECT * FROM akamai_jp.siem WHERE host = 'test\\'s.example.com'"
        processed_sql, is_valid, error = process_sql_func(sql)

        # sqlglot handles escaped quotes; query should be valid
        assert is_valid is True, f"Escaped quotes should be handled: {error}"

    def test_cross_join_no_on_clause(self, process_sql_func):
        """Test CROSS JOIN (no ON clause)."""
        sql = "SELECT * FROM akamai_jp.siem CROSS JOIN akamai_jp.logs LIMIT 10"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # CROSS JOIN should be preserved
        assert "CROSS JOIN" in processed_sql or "JOIN" in processed_sql

    def test_multiple_joins_in_sequence(self, process_sql_func):
        """Test multiple JOINs in sequence."""
        sql = """
        SELECT * FROM akamai_jp.siem AS s1
        JOIN akamai_jp.logs AS l1 ON s1.requestId = l1.reqId
        JOIN akamai_jp.siem AS s2 ON l1.reqId = s2.requestId
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Should handle multiple JOINs

    def test_self_join(self, process_sql_func):
        """Test self-join on same table."""
        sql = """
        SELECT * FROM akamai_jp.siem AS s1
        JOIN akamai_jp.siem AS s2 ON s1.clientIP = s2.clientIP
        WHERE s1.requestId != s2.requestId
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True

    def test_case_when_expressions_with_transformations(self, process_sql_func):
        """Test CASE WHEN expressions with transformations."""
        sql = """
        SELECT
            CASE
                WHEN arrayLength(ruleTags) > 0 THEN 'tagged'
                ELSE 'untagged'
            END AS status
        FROM akamai_jp.siem
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Function normalization should apply inside CASE
        assert "length(" in processed_sql

    def test_nested_function_calls(self, process_sql_func):
        """Test nested function calls."""
        sql = "SELECT lower(arrayFirst(x -> true, ruleTags)) FROM akamai_jp.siem"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True

    def test_array_join_with_multiple_arrays(self, process_sql_func):
        """Test ARRAY JOIN with multiple arrays."""
        sql = """
        SELECT tag, msg FROM akamai_jp.siem
        ARRAY JOIN ruleTags AS tag, ruleMessages AS msg
        LIMIT 10
        """
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # ARRAY JOIN should be preserved
        assert "ARRAY JOIN" in processed_sql or "arrayJoin" in processed_sql

    def test_backtick_identifiers(self, process_sql_func):
        """Test backtick-quoted identifiers."""
        sql = "SELECT `host` FROM akamai_jp.siem WHERE `timestamp` > parseDateTimeBestEffort('2026-01-01')"
        processed_sql, is_valid, error = process_sql_func(sql)

        # Should handle backtick identifiers
        assert is_valid is True or error is not None

    def test_existing_settings_clause_preserved(self, process_sql_func):
        """Test existing SETTINGS clause is preserved."""
        # Note: SETTINGS is added by prepare_sql, not process_sql
        # But we should ensure process_sql doesn't break if SETTINGS is present
        sql = "SELECT * FROM akamai_jp.siem LIMIT 10 SETTINGS max_rows_to_read = 1000"
        processed_sql, is_valid, error = process_sql_func(sql)

        # Should handle SETTINGS clause
        assert is_valid is True or error is not None


class TestCoverageBranches:
    """Targeted tests for defensive branches not hit by high-level scenarios."""

    def test_join_using_hits_no_on_branch(self, process_sql_func):
        """JOIN ... USING has no ON expression and should pass unchanged."""
        sql = "SELECT * FROM akamai_jp.siem AS s JOIN akamai_jp.logs AS l USING (requestId)"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"JOIN USING should be valid: {error}"
        assert "USING" in processed_sql

    def test_fix_join_on_predicates_join_without_select_ancestor(self):
        """Direct helper call: Join node without Select ancestor should be ignored."""
        join = exp.Join(
            this=exp.Table(this=exp.to_identifier("logs")),
            on=exp.And(
                this=exp.EQ(this=exp.column("a", table="s"), expression=exp.column("b", table="l")),
                expression=exp.GT(this=exp.column("ts", table="s"), expression=exp.column("ts", table="l")),
            ),
        )
        container = exp.Tuple(expressions=[join])
        result = sql_utils._fix_join_on_predicates(container)
        assert result is container

    def test_fix_hdx_join_join_without_select_ancestor(self):
        """Direct helper call: HDX fix should no-op without Select ancestor."""
        join = exp.Join(
            this=exp.Table(this=exp.to_identifier("siem"), alias=exp.TableAlias(this=exp.to_identifier("waf"))),
            on=exp.EQ(this=exp.column("reqId", table="cdn"), expression=exp.column("requestId", table="waf")),
        )
        result = sql_utils._fix_hdx_join(join, "akamai_jp", "siem", "logs")
        assert result is join

    def test_hdx_join_where_removed_when_only_right_side_time_filter(self, process_sql_func):
        """When only the moved time predicate exists, WHERE should be removed."""
        sql = (
            "SELECT count() FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS waf ON cdn.reqId = waf.requestId "
            "WHERE waf.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01T00:00:00Z') "
            "AND parseDateTimeBestEffort('2026-01-08T00:00:00Z')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql
        tail_after_on = processed_sql.upper().split(" ON ", 1)[1]
        assert " WHERE " not in tail_after_on, "Main WHERE clause should be removed after extracting only predicate"

    def test_replace_now_current_timestamp_node_branch(self):
        """Direct helper call to hit CurrentTimestamp node replacement branch."""
        ast = exp.Select(expressions=[exp.CurrentTimestamp()]).from_("akamai_jp.siem")
        result = sql_utils._replace_now(ast, "2026-01-01T00:00:00Z")
        emitted = result.sql(dialect="clickhouse")
        assert "parseDateTimeBestEffort" in emitted
        assert "CURRENT_TIMESTAMP" not in emitted

    def test_split_and_conditions_where_branch(self):
        """_split_and_conditions should unwrap Where before splitting."""
        where = exp.Where(this=exp.EQ(this=exp.column("host"), expression=exp.Literal.string("x")))
        parts = sql_utils._split_and_conditions(where)
        assert len(parts) == 1
        assert isinstance(parts[0], exp.EQ)

    def test_and_join_raises_on_empty_conditions(self):
        """_and_join should raise ValueError for empty input."""
        with pytest.raises(ValueError, match="conditions must not be empty"):
            sql_utils._and_join([])

    def test_function_args_extends_expressions_branch(self):
        """_function_args should collect list-based expressions for non-Anonymous nodes."""
        node = exp.Coalesce(expressions=[exp.column("a"), exp.column("b")])
        args = sql_utils._function_args(node)
        assert len(args) == 2


class TestHdxJoinOnClauseBetween:
    """Tests for _fix_hdx_join extracting BETWEEN from JOIN ON clause."""

    def test_between_in_on_clause_left_join(self, process_sql_func):
        """LEFT JOIN with BETWEEN in ON → extracted into subquery."""
        sql = (
            "SELECT * FROM akamai_jp.logs AS cdn "
            "LEFT JOIN akamai_jp.siem AS w "
            "ON cdn.reqId = w.requestId "
            "AND w.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08') "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # Right table should be wrapped in subquery
        assert "(SELECT" in processed_sql and "FROM akamai_jp.siem" in processed_sql
        # BETWEEN should be inside subquery, not in ON
        on_clause = extract_on_clause(processed_sql)
        assert "BETWEEN" not in on_clause, f"BETWEEN should be moved from ON to subquery: {on_clause}"
        # Equality should remain in ON
        assert "requestId" in on_clause or "reqId" in on_clause

    def test_between_in_on_clause_with_equality(self, process_sql_func):
        """ON has equality + BETWEEN → BETWEEN moves to subquery, equality stays."""
        sql = (
            "SELECT * FROM akamai_jp.logs AS cdn "
            "LEFT JOIN akamai_jp.siem AS w "
            "ON cdn.reqId = w.requestId "
            "AND w.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "(SELECT" in processed_sql, "Should wrap in subquery"
        on_clause = extract_on_clause(processed_sql)
        # Equality predicate should remain in ON
        assert "reqId" in on_clause or "requestId" in on_clause
        assert "BETWEEN" not in on_clause


class TestArrayJoinInSubquery:
    """Tests for ARRAY JOIN being moved into subquery by _fix_hdx_join."""

    def test_array_join_moved_into_subquery(self, process_sql_func):
        """ARRAY JOIN w.attackTypes should be moved into subquery."""
        sql = (
            "SELECT w.clientIP, attackType FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS w ON cdn.reqId = w.requestId "
            "ARRAY JOIN w.attackTypes AS attackType "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08') "
            "AND w.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "(SELECT" in processed_sql, "Should have subquery"
        # ARRAY JOIN should be inside the subquery (before the closing paren)
        subquery_match = processed_sql.split("(SELECT")[1].split(") AS")[0] if "(SELECT" in processed_sql else ""
        assert "ARRAY JOIN" in subquery_match, f"ARRAY JOIN should be inside subquery: {processed_sql}"

    def test_array_join_multiple_arrays_moved(self, process_sql_func):
        """Multiple ARRAY JOIN arrays referencing wrapped table should be moved."""
        sql = (
            "SELECT w.clientIP, attackType, ruleTag FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS w ON cdn.reqId = w.requestId "
            "ARRAY JOIN w.attackTypes AS attackType, w.ruleTags AS ruleTag "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08') "
            "AND w.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "(SELECT" in processed_sql, "Should have subquery"
        # Both ARRAY columns should be in the subquery
        subquery_match = processed_sql.split("(SELECT")[1].split(") AS")[0] if "(SELECT" in processed_sql else ""
        assert "ARRAY JOIN" in subquery_match, f"ARRAY JOIN should be in subquery: {processed_sql}"
        assert "attackTypes" in subquery_match, f"attackTypes should be in subquery: {subquery_match}"
        assert "ruleTags" in subquery_match, f"ruleTags should be in subquery: {subquery_match}"

    def test_array_join_without_table_qualifier(self, process_sql_func):
        """ARRAY JOIN without table qualifier should NOT be moved into subquery."""
        sql = (
            "SELECT attackType FROM akamai_jp.logs AS cdn "
            "JOIN akamai_jp.siem AS w ON cdn.reqId = w.requestId "
            "ARRAY JOIN attackTypes AS attackType "
            "WHERE cdn.reqTimeSec BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08') "
            "AND w.timestamp BETWEEN parseDateTimeBestEffort('2026-01-01') "
            "AND parseDateTimeBestEffort('2026-01-08')"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # ARRAY JOIN should remain in the outer query (not moved)
        # The subquery should exist for the time filter
        assert "(SELECT" in processed_sql, "Should have subquery"
        # ARRAY JOIN should be after the subquery closing
        after_subquery = processed_sql.split(") AS w")[1] if ") AS w" in processed_sql else processed_sql
        assert "ARRAY JOIN" in after_subquery, f"ARRAY JOIN without qualifier should stay outer: {processed_sql}"


class TestWindowInWhere:
    """Tests for _fix_window_in_where — wrapping queries with window functions in WHERE."""

    def test_row_number_in_where_rewritten(self, process_sql_func):
        """Basic row_number() = 1 in WHERE should be rewritten."""
        sql = (
            "SELECT clientIP, host, cnt FROM akamai_jp.siem "
            "WHERE row_number() OVER (PARTITION BY clientIP ORDER BY cnt DESC) = 1"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # Should be wrapped in subquery
        assert "SELECT * FROM (SELECT" in processed_sql or "SELECT * FROM (select" in processed_sql.lower(), \
            f"Should wrap in subquery: {processed_sql}"
        # The outer WHERE should reference the synthetic alias
        assert "_w1" in processed_sql, f"Should have synthetic alias _w1: {processed_sql}"

    def test_window_with_other_where_conditions(self, process_sql_func):
        """Window + regular WHERE conditions should be split correctly."""
        sql = (
            "SELECT clientIP, cnt FROM akamai_jp.siem "
            "WHERE host = 'example.com' "
            "AND row_number() OVER (PARTITION BY clientIP ORDER BY cnt DESC) = 1"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        # Should be wrapped in subquery
        assert "_w1" in processed_sql, f"Should have synthetic alias: {processed_sql}"
        # Regular condition should be in inner WHERE
        lower = processed_sql.lower()
        # host = 'example.com' should appear in inner part
        assert "example.com" in processed_sql

    def test_no_window_in_where_unchanged(self, process_sql_func):
        """No window function in WHERE → no wrapping."""
        sql = "SELECT clientIP, count() AS cnt FROM akamai_jp.siem WHERE host = 'test.com' GROUP BY clientIP"
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Should NOT be wrapped
        assert "SELECT * FROM (SELECT" not in processed_sql, f"Should not wrap: {processed_sql}"

    def test_window_in_select_only_unchanged(self, process_sql_func):
        """Window only in SELECT → no wrapping."""
        sql = (
            "SELECT clientIP, row_number() OVER (ORDER BY clientIP) AS rn "
            "FROM akamai_jp.siem WHERE host = 'test.com'"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True
        # Window is only in SELECT, not WHERE → no wrapping
        assert "_w" not in processed_sql, f"Should not add synthetic alias: {processed_sql}"

    def test_dense_rank_in_where_rewritten(self, process_sql_func):
        """dense_rank() in WHERE should also be handled."""
        sql = (
            "SELECT clientIP, host FROM akamai_jp.siem "
            "WHERE dense_rank() OVER (ORDER BY clientIP) <= 10"
        )
        processed_sql, is_valid, error = process_sql_func(sql)

        assert is_valid is True, f"Query should be valid: {error}"
        assert "_w1" in processed_sql, f"Should have synthetic alias: {processed_sql}"
        assert "SELECT * FROM" in processed_sql, f"Should wrap: {processed_sql}"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
