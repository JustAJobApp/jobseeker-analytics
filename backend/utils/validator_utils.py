import re
from typing import Optional


def sanitize_csv_field(field_value: str) -> str:
    """Prevents CSV Injection (Formula Injection)"""
    if not field_value:
        return field_value
    
    value_str = str(field_value)
    # If the field starts with a formula trigger character, 
    # prepend a single quote (') to treat as literal
    if value_str.startswith(('=', '+', '-', '@', '\t', '\r')):
        return f"'{value_str}"
    
    return value_str


def reject_html_svg(value: Optional[str]) -> Optional[str]:
    if value and re.search(r'<\s*[a-zA-Z/!]', value):
        raise ValueError("HTML and SVG content is not permitted")
    return value