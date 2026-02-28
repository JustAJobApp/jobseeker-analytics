import re
from typing import Optional


def sanitize_csv_field(field_value: object) -> str:
    """Prevents CSV Injection (Formula Injection)"""
    if field_value is None:
        return ""
    
    value_str = str(field_value)
    # Check for trigger characters, including those preceded by whitespace
    if value_str.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')):
        return f"'{value_str}"
    
    return value_str


def reject_html_svg(value: Optional[str]) -> Optional[str]:
    if value and re.search(r'<\s*[a-zA-Z/!]', value):
        raise ValueError("HTML and SVG content is not permitted")
    return value