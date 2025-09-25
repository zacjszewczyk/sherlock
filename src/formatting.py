from pathlib import Path
from typing import Dict, Optional

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter

def _pixels_to_width(pixels: int) -> float:
    """
    Approximate conversion from pixels to openpyxl's character width unit.
    """
    return pixels / 7.0

def export_simple_excel(df: pd.DataFrame, path: Path, column_widths_pixels: Optional[Dict[str, int]] = None):
    """
    Exports a DataFrame to a standard Excel file with custom formatting.
    - Applies word wrap to all cells.
    - Sets column widths based on pixel approximation or auto-sizing.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "ASOM"
    cols = list(df.columns)

    # Styles
    header_font = Font(bold=True)
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    cell_alignment = Alignment(vertical="top", wrap_text=True)

    # Write Header
    for c_idx, col_name in enumerate(cols, start=1):
        cell = ws.cell(row=1, column=c_idx, value=col_name)
        cell.font = header_font
        cell.alignment = header_alignment

    # Write Data
    for r_idx, row in enumerate(df.itertuples(index=False), start=2):
        for c_idx, value in enumerate(row, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value="" if pd.isna(value) else value)
            cell.alignment = cell_alignment

    # Set column widths
    for c_idx, col_name in enumerate(cols, start=1):
        col_letter = get_column_letter(c_idx)
        if column_widths_pixels and col_name in column_widths_pixels:
            ws.column_dimensions[col_letter].width = _pixels_to_width(column_widths_pixels[col_name])
        else:
            max_len = df[col_name].astype(str).map(len).max()
            max_len = max(len(col_name), max_len if pd.notna(max_len) else 0)
            ws.column_dimensions[col_letter].width = min(max_len + 2, 60)

    wb.save(path)


def _compute_hierarchical_spans(df: pd.DataFrame, span_columns):
    spans = {col: [1] * len(df) for col in span_columns}
    parent_ranges = [(0, len(df))]

    for col in span_columns:
        col_spans = [1] * len(df)
        new_parent_ranges = []
        for (start, end) in parent_ranges:
            i = start
            while i < end:
                val = df.iat[i, df.columns.get_loc(col)]
                j = i + 1
                while j < end and df.iat[j, df.columns.get_loc(col)] == val:
                    j += 1
                run_len = j - i
                if run_len > 1:
                    col_spans[i] = run_len
                    for r in range(i + 1, j):
                        col_spans[r] = 0
                new_parent_ranges.append((i, j))
                i = j
        spans[col] = col_spans
        parent_ranges = new_parent_ranges
    return spans

def export_with_merged_cells(df: pd.DataFrame, path: Path, column_widths_pixels: Optional[Dict[str, int]] = None):
    # This list defines which columns are candidates for merging.
    all_possible_span_columns = [
        "CCIR Index", "CCIR", "Tactic ID", "Tactic Name",
        "Indicator Index", "Indicator", "Technique ID", "Technique Name"
    ]
    # Filter the list to only include columns that actually exist in the DataFrame.
    span_columns = [c for c in all_possible_span_columns if c in df.columns]

    df = df.copy()
    spans = _compute_hierarchical_spans(df, span_columns)

    wb = Workbook()
    ws = wb.active
    ws.title = "ASOM"
    cols = list(df.columns)

    # Styles
    header_font = Font(bold=True)
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    # This alignment will be applied to all data cells.
    default_cell_alignment = Alignment(vertical="top", wrap_text=True)

    # Write Header
    for c_idx, col in enumerate(cols, start=1):
        cell = ws.cell(row=1, column=c_idx, value=col)
        cell.font = header_font
        cell.alignment = header_alignment

    # Write Data and apply default alignment
    for r_idx, (_, row) in enumerate(df.iterrows(), start=2):
        for c_idx, col in enumerate(cols, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value="" if pd.isna(row[col]) else row[col])
            cell.alignment = default_cell_alignment

    # Apply Merges (the alignment is already set, so we just merge)
    for col in span_columns:
        c_idx = cols.index(col) + 1
        r = 0
        while r < len(df):
            span_len = spans[col][r]
            excel_row_start = r + 2
            if span_len > 1:
                ws.merge_cells(
                    start_row=excel_row_start,
                    start_column=c_idx,
                    end_row=excel_row_start + span_len - 1,
                    end_column=c_idx
                )
            r += max(span_len, 1)
    
    # Set column widths
    for c_idx, col_name in enumerate(cols, start=1):
        col_letter = get_column_letter(c_idx)
        if column_widths_pixels and col_name in column_widths_pixels:
            ws.column_dimensions[col_letter].width = _pixels_to_width(column_widths_pixels[col_name])
        else:
            max_len = df[col_name].astype(str).map(len).max()
            max_len = max(len(col_name), max_len if pd.notna(max_len) else 0)
            ws.column_dimensions[col_letter].width = min(max_len + 2, 60)

    wb.save(path)