from typing import List, Dict, Any
from src.parsers.json_parser import parse_json_content

def parse_json_file_content(content: str, log_source: str = "json_file") -> List[Dict[str, Any]]:
    return parse_json_content(content, log_source=log_source)
