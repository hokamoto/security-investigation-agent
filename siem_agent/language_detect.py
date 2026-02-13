"""Language detection heuristic for the SIEM Agent."""


def is_english(text: str) -> bool:
    """Heuristic: a question is likely English if most alpha chars are ASCII Latin letters."""
    alpha_chars = [c for c in text if c.isalpha()]
    if not alpha_chars:
        return True  # No alphabetic chars (e.g., all numbers/symbols) → treat as English
    ascii_alpha = sum(1 for c in alpha_chars if c.isascii())
    return (ascii_alpha / len(alpha_chars)) > 0.5
