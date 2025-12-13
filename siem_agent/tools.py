"""LangChain tools for the SIEM agent."""

from langchain_core.tools import tool


@tool
def calculator(expression: str, decimal_places: int = 2) -> str:
    """Evaluate a mathematical expression.

    Args:
        expression: Math expression (e.g., "211 / 712 * 100")
        decimal_places: Rounding precision (default: 2)

    Returns:
        String representation of the calculated result
    """
    # Replace ^ with ** for exponentiation (LLM may use ^ but Python uses **)
    expression = expression.replace("^", "**")

    # Evaluate with empty __builtins__ for security (same as evaluate_calculations)
    result = eval(expression, {"__builtins__": {}}, {})

    if decimal_places == 0:
        return str(int(round(result)))
    return f"{result:.{decimal_places}f}"
