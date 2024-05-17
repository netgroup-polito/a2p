from dataclasses import dataclass
from typing import Optional


@dataclass
class LogContext:
    ids: str
    version: str
    alert_mode: str
    min_priority: Optional[int]
    alert_file_path: str
    auto_confirm: bool
    firewall_type: str
