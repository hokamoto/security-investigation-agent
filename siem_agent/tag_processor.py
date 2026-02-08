"""Tag processor module for <fact> and <calc> tag handling.

This module provides functions to:
1. Evaluate <calc> tags (mathematical expressions) and replace them with <fact> tags
2. Resolve <fact> tags to their values for final display
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class CalcResult:
    """Result of a successful calc tag evaluation."""

    original_tag: str
    formula: str
    expr: str
    precision: int
    result: float
    fact_tag: str


@dataclass
class CalcError:
    """Error during calc tag evaluation."""

    original_tag: str
    error_message: str


# Pattern for <calc> tags - uses lookahead to match attributes in any order
# Matches: <calc formula="..." expr="..." precision="N" /> or <calc ... >
CALC_TAG_PATTERN = re.compile(
    r"<calc\s+"
    r"(?=.*?\bformula=\"(?P<formula>[^\"]*)\")?"
    r"(?=.*?\bexpr=\"(?P<expr>[^\"]*)\")"
    r"(?=.*?\bprecision=\"(?P<precision>\d+)\")"
    r"[^>]*"
    r"/?>",  # Match both /> and >
    re.DOTALL,
)

# Pattern for <fact> tags - uses lookahead to match attributes in any order
# Matches: <fact source="..." val="..." /> or <fact ... >
FACT_TAG_PATTERN = re.compile(
    r"<fact\s+"
    r"(?=.*?\bsource=\"(?P<source>[^\"]*)\")"
    r"(?=.*?\bval=\"(?P<val>[^\"]*)\")"
    r"[^>]*"
    r"/?>",  # Match both /> and >
    re.DOTALL,
)


def _safe_eval(expr: str) -> float:
    """Evaluate mathematical expression.

    Args:
        expr: Expression string (e.g., "15234 / 892301 * 100")

    Returns:
        Computed result as float

    Raises:
        ValueError: If expression contains invalid characters
        Exception: From eval() if computation fails
    """
    # Replace ^ with ** for exponentiation
    expr = expr.replace("^", "**")

    # Validate: only allow digits, operators, parentheses, decimal points, spaces
    allowed_pattern = r"^[\d\s\+\-\*/\(\)\.\*]+$"
    if not re.match(allowed_pattern, expr):
        raise ValueError(f"Expression contains invalid characters: {expr}")

    # Evaluate
    return float(eval(expr))


def evaluate_calc_tags(
    text: str,
) -> Tuple[str, List[CalcResult], List[CalcError]]:
    """Parse and evaluate all <calc> tags in the text.

    Replaces <calc> tags with equivalent <fact> tags that preserve
    the formula for traceability.

    Args:
        text: Input text containing <calc> tags

    Returns:
        Tuple of:
        - Processed text with <calc> tags replaced by <fact> tags
        - List of successful CalcResult objects
        - List of CalcError objects for failed evaluations

    Example:
        Input:  <calc formula="[attacks] / [total]" expr="15234 / 892301 * 100" precision="2" />
        Output: <fact source="calculated: [attacks] / [total]" val="1.71" />
    """
    results: List[CalcResult] = []
    errors: List[CalcError] = []

    def replace_calc(match: re.Match) -> str:
        original_tag = match.group(0)
        formula = match.group("formula") or ""
        expr = match.group("expr")
        precision_str = match.group("precision")

        if not expr or not precision_str:
            errors.append(
                CalcError(
                    original_tag=original_tag,
                    error_message="Missing required attributes (expr or precision)",
                )
            )
            return f"{original_tag}<!-- CALC_ERROR: Missing required attributes -->"

        precision = int(precision_str)

        try:
            computed = _safe_eval(expr)
            rounded = round(computed, precision)

            # Format value: remove trailing zeros for cleaner output
            if precision == 0:
                val_str = str(int(rounded))
            else:
                val_str = f"{rounded:.{precision}f}"

            # Create replacement <fact> tag with formula in source
            if formula:
                source = f"calculated: {formula}"
            else:
                source = "calculation"
            fact_tag = f'<fact source="{source}" val="{val_str}" />'

            results.append(
                CalcResult(
                    original_tag=original_tag,
                    formula=formula,
                    expr=expr,
                    precision=precision,
                    result=rounded,
                    fact_tag=fact_tag,
                )
            )

            return fact_tag

        except Exception as e:
            errors.append(CalcError(original_tag=original_tag, error_message=str(e)))
            return f"{original_tag}<!-- CALC_ERROR: {e} -->"

    processed = CALC_TAG_PATTERN.sub(replace_calc, text)
    return processed, results, errors


def resolve_fact_tags(text: str) -> str:
    """Resolve all <fact> tags to their values.

    This is the final step before displaying output to users.
    Replaces each <fact> tag with just its val attribute.

    Args:
        text: Input text containing <fact> tags

    Returns:
        Text with <fact> tags replaced by their values

    Example:
        Input:  The attack count was <fact source="query 1" val="15234" />.
        Output: The attack count was 15234.
    """

    def replace_fact(match: re.Match) -> str:
        return match.group("val")

    return FACT_TAG_PATTERN.sub(replace_fact, text)


def process_output_tags(text: str) -> str:
    """Complete tag processing pipeline.

    Performs in order:
    1. Evaluate <calc> tags -> <fact> tags
    2. Resolve <fact> tags -> values

    This is the main entry point for tag processing.

    Args:
        text: Raw LLM output with <calc> and <fact> tags

    Returns:
        Processed text ready for display to user
    """
    # Step 1: Evaluate <calc> tags to <fact> tags
    text, calc_results, calc_errors = evaluate_calc_tags(text)

    # Log any calculation errors
    if calc_errors:
        for error in calc_errors:
            print(f"[WARNING] Calc evaluation failed: {error.error_message}")

    # Step 2: Resolve <fact> tags to values
    text = resolve_fact_tags(text)

    return text
