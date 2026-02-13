from siem_agent.tag_processor import resolve_fact_tags


def test_resolve_fact_tags_rounds_decimal_with_3plus_fractional_digits():
    text = 'deny rate: <fact source="final answer, deny rate" val="94.04761904761905" />'
    assert resolve_fact_tags(text) == "deny rate: 94.0"


def test_resolve_fact_tags_keeps_decimal_with_2_fractional_digits():
    text = 'ratio: <fact source="query 1" val="12.34" />'
    assert resolve_fact_tags(text) == "ratio: 12.34"


def test_resolve_fact_tags_keeps_ip_address():
    text = 'attacker IP: <fact source="query 2" val="62.60.131.73" />'
    assert resolve_fact_tags(text) == "attacker IP: 62.60.131.73"
