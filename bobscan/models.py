from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Vulnerability:
    plugin_name: str
    severity: Severity
    title: str
    description: str
    remedy: str
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None  # Snippet of the HTTP response or explanation
    request_method: str = "GET"

@dataclass
class CrawledPage:
    url: str
    method: str
    params: Dict[str, str] = field(default_factory=dict)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: int = 0

@dataclass
class ScanConfig:
    target_url: str
    concurrency_limit: int = 10
    timeout: int = 10
    user_agent: str = "BobScan/1.0 (Educational Vulnerability Scanner)"
    exclude_paths: List[str] = field(default_factory=list)
    active_scanning: bool = True
