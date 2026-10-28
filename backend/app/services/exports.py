"""Spreadsheet-safe values for CSV and Excel exports (CSV/formula injection, OWASP).

A text cell starting with = + - @ (or a tab / carriage return) is run as a formula by spreadsheet programs, so a
ticket titled "=HYPERLINK(...)" could execute when a supervisor opens the report. Such text gets a leading
apostrophe in CSV and is stored as a literal string in Excel. Numbers are left untouched.
"""
from app.services.audit import clean_text

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value):
    if value is None: return ""
    if isinstance(value, (bool, int, float)): return value
    text = clean_text(value)
    return "'" + text if text.lstrip(" ").startswith(FORMULA_START) else text


def safe_row(values) -> list:
    return [safe_cell(v) for v in values]


def append_xlsx_row(sheet, values) -> None:
    """Append a row where every text value is a literal string (openpyxl turns text starting with "=" into a formula)."""
    sheet.append([None if isinstance(v, str) else v for v in values])
    for cell, value in zip(sheet[sheet.max_row], values, strict=False):
        if isinstance(value, str):
            cell.value = clean_text(value)
            cell.data_type = "s"
