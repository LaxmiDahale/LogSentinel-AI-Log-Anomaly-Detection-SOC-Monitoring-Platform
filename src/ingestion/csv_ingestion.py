import io
import pandas as pd
from typing import List, Dict, Any
from src.parsers.normalizer import normalize_event

def parse_csv_content(content: str, log_source: str = "csv_upload") -> List[Dict[str, Any]]:
    """
    Parses CSV content into normalized event dictionaries.
    """
    if not content or not content.strip():
        return []

    try:
        df = pd.read_csv(io.StringIO(content))
        # Fill NaN values with None
        df = df.where(pd.notnull(df), None)
        records = df.to_dict(orient="records")
        return [normalize_event(rec, log_source=log_source) for rec in records]
    except Exception as e:
        return []
