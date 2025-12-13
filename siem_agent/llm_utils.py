"""
LLM utilities: invocation, structured outputs, and result processing for SIEM Agent
"""

import re
import json
import time
from typing import Any, Type, TypeVar, Dict
from pydantic import BaseModel
from langchain_core.messages import HumanMessage, ToolMessage
from . import config

T = TypeVar('T', bound=BaseModel)


def _extract_reasoning_text(message_content: Any) -> str:
    """Extract reasoning text from an AIMessage content payload."""
    reasoning_parts: list[str] = []

    if isinstance(message_content, list):
        for item in message_content:
            if isinstance(item, dict):
                item_type = item.get('type')
                if item_type in ('reasoning', 'reasoning_text'):
                    if 'text' in item:
                        reasoning_parts.append(item['text'])
                    elif 'content' in item and isinstance(item['content'], list):
                        for content_item in item['content']:
                            if isinstance(content_item, dict) and content_item.get('type') == 'reasoning_text':
                                reasoning_parts.append(content_item.get('text', ''))
    elif isinstance(message_content, str):
        reasoning_parts.append(message_content)

    return "\n\n".join(reasoning_parts) if reasoning_parts else ""



def evaluate_num_tags(text: str) -> str:
    """
    Find and extract <num source="..." val="..." /> tags in text.
    Replace tags with their numeric values while logging source provenance.

    Args:
        text: Input text containing <num> tags

    Returns:
        Text with <num> tags replaced by their val attributes

    Example:
        Input: "<num source=\"query result row 1\" val=\"14\" /> events flagged"
        Output: "14 events flagged"
    """
    # Match <num ... /> tags with both source and val attributes (any order)
    pattern = r'<\s*num\s+(?=[^>]*source="[^"]*")(?=[^>]*val="[^"]*")[^>]*/>'
    matches = list(re.finditer(pattern, text))

    if not matches:
        return text

    # Collect all extraction results
    extractions = []
    replacements = {}  # Map original tag to replacement text

    for match in matches:
        original_tag = match.group(0)
        try:
            # Extract source and val attributes
            source_match = re.search(r'source="([^"]*)"', original_tag)
            val_match = re.search(r'val="([^"]*)"', original_tag)

            if not source_match or not val_match:
                # Missing required attributes, keep original
                extractions.append({
                    "status": "warning",
                    "original_tag": original_tag,
                    "has_source": source_match is not None,
                    "has_val": val_match is not None
                })
                replacements[original_tag] = original_tag
                continue

            source = source_match.group(1)
            val = val_match.group(1).strip()

            # Format number with comma separators for readability
            formatted_val = val
            try:
                # Check if it's a numeric value (not an IP address or other string)
                # IP addresses have 3+ dots, so skip those
                if '.' in val and val.count('.') >= 3:
                    # Likely an IP address, don't format
                    formatted_val = val
                elif val.replace('.', '').replace('-', '').replace(',', '').isdigit():
                    # Remove any existing commas first
                    clean_val = val.replace(',', '')

                    # Check if it's a decimal number
                    if '.' in clean_val:
                        integer_part, decimal_part = clean_val.split('.', 1)
                        # Format integer part with commas
                        formatted_integer = f"{int(integer_part):,}"
                        formatted_val = f"{formatted_integer}.{decimal_part}"
                    else:
                        # Format as integer with commas
                        formatted_val = f"{int(clean_val):,}"
            except (ValueError, AttributeError):
                # If formatting fails, use original value
                formatted_val = val

            extractions.append({
                "status": "success",
                "original_tag": original_tag,
                "source": source,
                "value": val,
                "formatted_value": formatted_val
            })
            replacements[original_tag] = formatted_val

        except Exception as e:
            # Log error and keep original tag
            extractions.append({
                "status": "error",
                "original_tag": original_tag,
                "error": str(e)
            })
            replacements[original_tag] = original_tag

    # Log all extractions in a single batch
    if extractions:
        # Separate by status for better logging
        successful = [e for e in extractions if e["status"] == "success"]
        warnings = [e for e in extractions if e["status"] == "warning"]
        errors = [e for e in extractions if e["status"] == "error"]

        if successful:
            config.session_logger.log(
                level="DEBUG",
                component="num_annotation",
                event="num_tag_extracted",
                data={
                    "count": len(successful),
                    "extractions": successful
                }
            )

        if warnings:
            config.session_logger.log(
                level="WARNING",
                component="num_annotation",
                event="num_tag_missing_attributes",
                data={
                    "count": len(warnings),
                    "warnings": warnings
                }
            )

        if errors:
            config.session_logger.log(
                level="ERROR",
                component="num_annotation",
                event="num_tag_extraction_failed",
                data={
                    "count": len(errors),
                    "errors": errors
                }
            )

    # Perform replacements
    result_text = text
    for original, replacement in replacements.items():
        result_text = result_text.replace(original, replacement, 1)

    return result_text



def _format_system_prompt(
    available_hosts: list | None = None,
    available_rule_tags: list | None = None,
    database_name: str | None = None,
    siem_log_table_name: str | None = None,
    cdn_log_table_name: str | None = None,
) -> str:
    """Format system prompt with dynamic context"""
    system_prompt = config.PROMPTS.get('system_prompt', '').strip()
    if not system_prompt:
        return ""

    # Format available_hosts as markdown bullet list
    if available_hosts is not None and available_hosts:
        hosts_str = "\n".join(f"- {host}" for host in available_hosts)
    else:
        hosts_str = "- (No hosts enumerated)"

    if available_rule_tags is not None and available_rule_tags:
        rule_tags_str = "\n".join(f"- {tag}" for tag in available_rule_tags)
    else:
        rule_tags_str = "- (No ruleTags enumerated)"

    db_name = database_name or config.CONFIG['clickhouse']['database']
    siem_table = siem_log_table_name or config.CONFIG['clickhouse']['siem_log_table_name']
    cdn_table = cdn_log_table_name or config.CONFIG['clickhouse'].get('cdn_log_table_name', '(not configured)')

    return system_prompt.format(
        available_hosts=hosts_str,
        available_rule_tags=rule_tags_str,
        database_name=db_name,
        siem_log_table_name=siem_table,
        cdn_log_table_name=cdn_table
    )



def _try_parse_from_content(response: Any, response_model: Type[T]) -> T | None:
    """
    Attempt to extract and parse structured output from response.content when tool_calls is missing.

    This function handles cases where small LLMs return JSON in response.content instead of
    properly formatted tool calls. It tries multiple parsing strategies:
    1. Parse mcp_call or tool_call structures from list content
    2. Parse plain JSON text from string content
    3. Parse JSON from text fields within list content

    Args:
        response: The LLM response message
        response_model: Pydantic model class to parse into

    Returns:
        Parsed Pydantic model instance if successful, None otherwise
    """
    if not hasattr(response, 'content') or response.content is None:
        return None

    content = response.content

    # Strategy 1: Parse from list content with mcp_call or tool_call structure
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue

            item_type = item.get('type')
            item_name = item.get('name')

            # Check if this is a tool call structure
            if item_type in ('mcp_call', 'tool_call') and item_name == response_model.__name__:
                arguments = item.get('arguments')

                if arguments is None:
                    continue

                try:
                    # If arguments is a string, parse as JSON
                    if isinstance(arguments, str):
                        args_dict = json.loads(arguments)
                    elif isinstance(arguments, dict):
                        args_dict = arguments
                    else:
                        continue

                    # Validate and parse with Pydantic model
                    parsed = response_model(**args_dict)

                    config.session_logger.log(
                        level="INFO",
                        component="llm",
                        event="fallback_parse_success_mcp_call",
                        data={
                            "response_model": response_model.__name__,
                            "item_type": item_type,
                            "parsed_fields": list(args_dict.keys())
                        }
                    )

                    return parsed

                except (json.JSONDecodeError, TypeError, ValueError) as e:
                    config.session_logger.log(
                        level="DEBUG",
                        component="llm",
                        event="fallback_parse_failed_mcp_call",
                        data={
                            "response_model": response_model.__name__,
                            "item_type": item_type,
                            "error": str(e),
                            "arguments_preview": str(arguments)[:200]
                        }
                    )
                    continue

    # Strategy 2: Parse from string content (plain JSON text)
    if isinstance(content, str):
        # Try to find JSON object in the string
        try:
            # First try parsing the entire string as JSON
            args_dict = json.loads(content)

            if isinstance(args_dict, dict):
                parsed = response_model(**args_dict)

                config.session_logger.log(
                    level="INFO",
                    component="llm",
                    event="fallback_parse_success_plain_json",
                    data={
                        "response_model": response_model.__name__,
                        "parsed_fields": list(args_dict.keys())
                    }
                )

                return parsed

        except (json.JSONDecodeError, TypeError, ValueError) as e:
            config.session_logger.log(
                level="DEBUG",
                component="llm",
                event="fallback_parse_failed_plain_json",
                data={
                    "response_model": response_model.__name__,
                    "error": str(e),
                    "content_preview": content[:200]
                }
            )

        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        if json_match:
            try:
                args_dict = json.loads(json_match.group(1))
                parsed = response_model(**args_dict)

                config.session_logger.log(
                    level="INFO",
                    component="llm",
                    event="fallback_parse_success_markdown_json",
                    data={
                        "response_model": response_model.__name__,
                        "parsed_fields": list(args_dict.keys())
                    }
                )

                return parsed

            except (json.JSONDecodeError, TypeError, ValueError) as e:
                config.session_logger.log(
                    level="DEBUG",
                    component="llm",
                    event="fallback_parse_failed_markdown_json",
                    data={
                        "response_model": response_model.__name__,
                        "error": str(e)
                    }
                )

    # Strategy 3: Parse from text fields within list content
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                text = item.get('text', '')
                if not text:
                    continue

                try:
                    args_dict = json.loads(text)
                    if isinstance(args_dict, dict):
                        parsed = response_model(**args_dict)

                        config.session_logger.log(
                            level="INFO",
                            component="llm",
                            event="fallback_parse_success_text_field",
                            data={
                                "response_model": response_model.__name__,
                                "parsed_fields": list(args_dict.keys())
                            }
                        )

                        return parsed

                except (json.JSONDecodeError, TypeError, ValueError):
                    continue

    # All strategies failed
    config.session_logger.log(
        level="DEBUG",
        component="llm",
        event="fallback_parse_all_strategies_failed",
        data={
            "response_model": response_model.__name__,
            "content_type": type(content).__name__,
            "is_list": isinstance(content, list),
            "is_string": isinstance(content, str)
        }
    )

    return None


def _process_num_tags_in_model(model: BaseModel) -> BaseModel:
    """
    Process <num> tags in all string fields of a Pydantic model recursively.

    Args:
        model: Pydantic model instance

    Returns:
        Modified Pydantic model instance with <num> tags processed
    """
    model_dict = model.model_dump()

    def process_value(value):
        """Recursively process values to find and replace <num> tags in strings."""
        if isinstance(value, str):
            return evaluate_num_tags(value)
        elif isinstance(value, dict):
            return {k: process_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [process_value(item) for item in value]
        else:
            return value

    # Process all fields recursively
    processed_dict = {k: process_value(v) for k, v in model_dict.items()}

    # Reconstruct the model with processed values
    return type(model)(**processed_dict)


def llm_invoke_structured(
    prompt: str,
    response_model: Type[T],
    available_hosts: list = None,
    available_rule_tags: list = None,
    database_name: str | None = None,
    siem_log_table_name: str | None = None,
    cdn_log_table_name: str | None = None,
    state: Dict[str, Any] | None = None,
    max_iterations: int = 10
) -> T:
    """
    Invoke LLM with structured output using tool calling.

    The LLM can call the calculator tool during reasoning, and must eventually
    return the structured response using the response_model as a tool.

    Args:
        prompt: The user prompt to send to the LLM
        response_model: Pydantic model class defining expected response structure
        available_hosts: Optional list of available hosts for system prompt
        state: Optional agent state dict for token tracking
        max_iterations: Maximum tool calling iterations (default: 10)

    Returns:
        Parsed Pydantic model instance with structured response
    """
    from .tools import calculator

    start_time = time.time()

    # Prepend system prompt if defined
    system_prompt = _format_system_prompt(
        available_hosts,
        available_rule_tags,
        database_name,
        siem_log_table_name,
        cdn_log_table_name
    )
    full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

    # CRITICAL: Append explicit tool calling instruction at the end
    # This ensures vLLM with reasoning parser uses tool calls instead of plain JSON output
    full_prompt = f"{full_prompt}\n\nIMPORTANT: You MUST use the {response_model.__name__} tool to provide your output. Do NOT output plain JSON text."

    # Log the prompt
    config.session_logger.log(
        level="DEBUG",
        component="llm",
        event="llm_invoke_structured_start",
        data={
            "prompt": full_prompt,
            "response_model": response_model.__name__
        }
    )

    # Bind calculator and Pydantic model as tools
    llm_with_tools = config.llm.bind_tools([calculator, response_model])

    # Initialize message list
    messages = [HumanMessage(content=full_prompt)]

    iteration = 0
    while iteration < max_iterations:
        iteration += 1

        # LLM invocation with retry logic for transient response errors
        max_retries = 3
        response = None
        last_error = None

        for retry_attempt in range(max_retries):
            try:
                # Invoke LLM
                response = llm_with_tools.invoke(messages)

                # Track token usage
                if state is not None and hasattr(response, 'usage_metadata') and response.usage_metadata:
                    input_tokens = response.usage_metadata.get('input_tokens', 0)
                    output_tokens = response.usage_metadata.get('output_tokens', 0)
                    total_tokens = response.usage_metadata.get('total_tokens', 0)

                    # Accumulate in state
                    state['total_input_tokens'] = state.get('total_input_tokens', 0) + input_tokens
                    state['total_output_tokens'] = state.get('total_output_tokens', 0) + output_tokens
                    state['llm_call_count'] = state.get('llm_call_count', 0) + 1

                    # Log token usage
                    config.session_logger.log(
                        level="DEBUG",
                        component="llm",
                        event="token_usage",
                        data={
                            "input_tokens": input_tokens,
                            "output_tokens": output_tokens,
                            "total_tokens": total_tokens,
                            "cumulative_input": state['total_input_tokens'],
                            "cumulative_output": state['total_output_tokens'],
                            "cumulative_calls": state['llm_call_count'],
                            "iteration": iteration
                        }
                    )

                # Success - break retry loop
                break

            except Exception as e:
                last_error = e
                elapsed = time.time() - start_time

                # Retry on transient errors (especially LLM response format issues)
                if retry_attempt < max_retries - 1:
                    config.session_logger.log(
                        level="WARNING",
                        component="llm",
                        event="llm_invoke_retry",
                        data={
                            "error": str(e),
                            "error_type": type(e).__name__,
                            "response_model": response_model.__name__,
                            "iteration": iteration,
                            "retry_attempt": retry_attempt + 1,
                            "max_retries": max_retries,
                            "prompt_length": len(full_prompt)
                        },
                        elapsed_time=elapsed
                    )
                    # Wait briefly before retry
                    time.sleep(0.5)
                    continue
                else:
                    # Final retry failed - log and raise
                    config.session_logger.log(
                        level="ERROR",
                        component="llm",
                        event="llm_invoke_structured_failed",
                        data={
                            "error": str(e),
                            "error_type": type(e).__name__,
                            "response_model": response_model.__name__,
                            "iteration": iteration,
                            "total_retry_attempts": max_retries,
                            "prompt_length": len(full_prompt)
                        },
                        elapsed_time=elapsed
                    )
                    raise

        # If response is still None after retries, raise the last error
        if response is None:
            raise last_error or RuntimeError("LLM invocation failed without exception")

        # Check for tool calls
        if not hasattr(response, 'tool_calls') or not response.tool_calls:
            # No tool calls - try to extract JSON from response.content before retrying
            elapsed = time.time() - start_time
            content_preview = str(response.content) if hasattr(response, 'content') else "No content"

            # Attempt to parse structured output from response.content
            parsed_from_content = _try_parse_from_content(response, response_model)

            if parsed_from_content is not None:
                # Successfully parsed - process num tags and return
                parsed_from_content = _process_num_tags_in_model(parsed_from_content)

                # Extract reasoning text from response if present
                reasoning_text = _extract_reasoning_text(response.content)

                # Log successful fallback parsing
                # Use 'final_output' key to ensure full logging without truncation
                log_data = {
                    "final_output": json.dumps(parsed_from_content.model_dump(), indent=2, ensure_ascii=False),
                    "response_model": response_model.__name__,
                    "total_iterations": iteration,
                    "parsed_from": "content_fallback"
                }
                if reasoning_text:
                    log_data["reasoning"] = reasoning_text

                config.session_logger.log(
                    level="INFO",
                    component="llm",
                    event="llm_invoke_structured_complete_fallback",
                    data=log_data,
                    elapsed_time=elapsed
                )

                return parsed_from_content

            # Fallback parsing failed - log and retry
            config.session_logger.log(
                level="WARNING",
                component="llm",
                event="no_tool_calls_retrying",
                data={
                    "response_model": response_model.__name__,
                    "iteration": iteration,
                    "response_type": type(response).__name__,
                    "content_preview": content_preview,
                    "remaining_iterations": max_iterations - iteration,
                    "fallback_parse_attempted": True
                },
                elapsed_time=elapsed
            )

            # If not at max iterations, retry without adding messages
            if iteration < max_iterations:
                continue  # Retry LLM invocation

            # Only raise if max iterations exhausted
            raise ValueError(
                f"Expected tool calls but got none after {max_iterations} iterations. "
                f"Response type: {type(response).__name__}. "
                f"Content preview: {content_preview}. "
                f"This may indicate vLLM tool calling is not properly configured."
            )

        # Append response to messages
        messages.append(response)

        # Process each tool call
        for tool_call in response.tool_calls:
            tool_name = tool_call.get("name")
            tool_args = tool_call.get("args", {})
            tool_id = tool_call.get("id")

            if tool_name == "calculator":
                # Execute calculator tool
                try:
                    result = calculator.invoke(tool_args)
                    config.session_logger.log(
                        level="INFO",
                        component="llm",
                        event="calculator_invoked",
                        data={
                            "expression": tool_args.get('expression'),
                            "decimal_places": tool_args.get('decimal_places', 2),
                            "result": result,
                            "iteration": iteration
                        }
                    )
                    # vLLM Responses API requires the recipient name on tool responses
                    messages.append(ToolMessage(content=result, tool_call_id=tool_id, name="calculator"))
                except Exception as calc_error:
                    error_msg = f"Calculator error: {str(calc_error)}"
                    config.session_logger.log(
                        level="ERROR",
                        component="llm",
                        event="calculator_error",
                        data={
                            "expression": tool_args.get('expression'),
                            "error": str(calc_error),
                            "iteration": iteration
                        }
                    )
                    messages.append(ToolMessage(content=error_msg, tool_call_id=tool_id, name=response_model.__name__))

            elif tool_name == response_model.__name__:
                # Structured output received - attempt validation
                elapsed = time.time() - start_time

                # Extract reasoning text from response for logging
                reasoning_text = _extract_reasoning_text(response.content)

                # Log the structured output received event with full reasoning and output
                log_data = {
                    "response_model": response_model.__name__,
                    "iteration": iteration,
                    "final_output": json.dumps(tool_args, indent=2, ensure_ascii=False)
                }
                if reasoning_text:
                    log_data["reasoning"] = reasoning_text

                config.session_logger.log(
                    level="INFO",
                    component="llm",
                    event="structured_output_received",
                    data=log_data,
                    elapsed_time=elapsed
                )

                # Parse the tool args into Pydantic model
                try:
                    parsed = response_model(**tool_args)
                except Exception as parse_error:
                    # Validation failed - send error back to LLM to retry
                    error_msg = f"Validation error: {str(parse_error)}\n\nPlease provide all required fields for {response_model.__name__}."

                    config.session_logger.log(
                        level="WARNING",
                        component="llm",
                        event="structured_output_validation_failed_retrying",
                        data={
                            "response_model": response_model.__name__,
                            "error": str(parse_error),
                            "tool_args_preview": str(tool_args)[:500],
                            "iteration": iteration,
                            "remaining_iterations": max_iterations - iteration
                        },
                        elapsed_time=elapsed
                    )

                    # Append error message and retry
                    messages.append(ToolMessage(content=error_msg, tool_call_id=tool_id, name=response_model.__name__))

                    # If not at max iterations, continue to retry
                    if iteration < max_iterations:
                        break  # Break tool_call loop to retry LLM invocation
                    else:
                        # Max iterations exhausted - raise original error
                        config.session_logger.log(
                            level="ERROR",
                            component="llm",
                            event="structured_output_parse_failed_max_iterations",
                            data={
                                "response_model": response_model.__name__,
                                "error": str(parse_error),
                                "tool_args_preview": str(tool_args)[:500],
                                "max_iterations": max_iterations
                            },
                            elapsed_time=elapsed
                        )
                        raise

                # Validation succeeded
                # Process <num> tags in the model
                parsed = _process_num_tags_in_model(parsed)

                # Extract reasoning text from response if present
                reasoning_text = _extract_reasoning_text(response.content)

                # Log the final response with reasoning if available
                # Use 'final_output' key to ensure full logging without truncation
                log_data = {
                    "final_output": json.dumps(parsed.model_dump(), indent=2, ensure_ascii=False),
                    "response_model": response_model.__name__,
                    "total_iterations": iteration
                }
                if reasoning_text:
                    log_data["reasoning"] = reasoning_text

                config.session_logger.log(
                    level="DEBUG",
                    component="llm",
                    event="llm_invoke_structured_complete",
                    data=log_data,
                    elapsed_time=elapsed
                )

                return parsed

            else:
                # Unknown tool - log warning
                config.session_logger.log(
                    level="WARNING",
                    component="llm",
                    event="unknown_tool_call",
                    data={
                        "tool_name": tool_name,
                        "expected_tools": ["calculator", response_model.__name__],
                        "iteration": iteration
                    }
                )

    # Max iterations reached without structured output
    elapsed = time.time() - start_time
    config.session_logger.log(
        level="ERROR",
        component="llm",
        event="max_iterations_reached",
        data={
            "max_iterations": max_iterations,
            "response_model": response_model.__name__
        },
        elapsed_time=elapsed
    )
    raise RuntimeError(f"Max iterations ({max_iterations}) reached without structured output")


def retry_sql_with_repair(
    sql_query: str,
    error: Exception,
    repair_prompt_template: str,
    prompt_context: Dict[str, Any],
    available_hosts: list,
    available_rule_tags: list,
    state: Dict[str, Any]
) -> str | None:
    """
    Ask LLM to repair a failed SQL query using structured output.

    This function abstracts the common retry pattern for SQL validation
    and execution failures. It formats the repair prompt, invokes the LLM
    with SQLRepairResponse model, and returns the repaired SQL.

    Args:
        sql_query: The original SQL query that failed
        error: The exception that occurred
        repair_prompt_template: Prompt template string with placeholders
        prompt_context: Dict containing values for prompt template formatting
        available_hosts: List of available hosts for system prompt context
        state: Agent state dict for token tracking

    Returns:
        Repaired SQL string if LLM repair succeeded, None if repair invocation failed

    Note:
        This function only requests repair from LLM - it does NOT re-validate
        or re-execute the repaired SQL. The caller is responsible for validation
        and execution after receiving the repaired SQL.
    """
    # Build repair prompt by formatting template with context
    repair_prompt = repair_prompt_template.format(**prompt_context)

    try:
        # Import SQLRepairResponse here to avoid circular import
        from .config import SQLRepairResponse

        # Invoke LLM with structured output for SQL repair
        repair_response = llm_invoke_structured(
            repair_prompt,
            SQLRepairResponse,
            available_hosts,
            available_rule_tags,
            state.get("database_name") if state else None,
            state.get("siem_log_table_name") if state else None,
            state.get("cdn_log_table_name") if state else None,
            state
        )

        # Extract repaired SQL from structured response
        repaired_sql = repair_response.sql

        config.session_logger.log(
            level="INFO",
            component="sql_repair",
            event="repair_llm_success",
            data={
                "original_sql": sql_query,
                "repaired_sql": repaired_sql,
                "original_error": str(error)
            }
        )

        return repaired_sql

    except Exception as repair_error:
        # Log repair failure
        config.session_logger.log(
            level="ERROR",
            component="sql_repair",
            event="repair_llm_failed",
            data={
                "original_sql": sql_query,
                "original_error": str(error),
                "repair_error": str(repair_error)
            }
        )
        return None
