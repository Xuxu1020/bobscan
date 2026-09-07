import aiohttp
from typing import List, Dict, Any
from .base import BasePlugin
from ..models import CrawledPage, Vulnerability, Severity

class LFIPlugin(BasePlugin):
    name = "Local File Inclusion & Path Traversal Scanner"
    description = "Tests input parameters and form fields for Path Traversal/LFI vulnerabilities."

    PAYLOADS = [
        # Linux targets
        ("../../../../etc/passwd", r"root:.*:0:0:"),
        ("/etc/passwd", r"root:.*:0:0:"),
        # Windows targets
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]|\[mci elevated\]"),
        ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]|\[mci elevated\]"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]|\[mci elevated\]")
    ]

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        findings = []

        # Test query parameters (GET)
        for page in pages:
            if not page.params:
                continue

            for param_name in page.params.keys():
                for payload, pattern in self.PAYLOADS:
                    import re
                    
                    headers = {"User-Agent": self.config.user_agent}
                    test_params = page.params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        async with session.get(page.url, params=test_params, headers=headers, timeout=self.config.timeout) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and re.search(pattern, body, re.IGNORECASE):
                                findings.append(Vulnerability(
                                    plugin_name=self.name,
                                    severity=Severity.HIGH,
                                    title=f"Path Traversal / Local File Inclusion in Parameter: '{param_name}'",
                                    description=(
                                        f"The application appears to suffer from a Path Traversal or LFI vulnerability. "
                                        f"By supplying '{payload}' to the '{param_name}' parameter, we were able to read "
                                        "sensitive system configuration files."
                                    ),
                                    remedy="Avoid passing user-controlled file paths or names directly to file system operations. If necessary, use a hardcoded whitelist of allowed files, or resolve the canonical path and verify it remains within the intended directory.",
                                    url=page.url,
                                    parameter=param_name,
                                    evidence=body[:150].strip().replace("\n", " ") + "...",
                                    request_method="GET"
                                ))
                                break  # Stop testing other payloads for this parameter if we found one
                    except Exception:
                        pass

        # Test Forms (GET & POST)
        for page in pages:
            for form in page.forms:
                for inp in form["inputs"]:
                    if inp["type"] not in ["text", "search", "url", "textarea"]:
                        continue

                    field_name = inp["name"]
                    action_url = form["action"]
                    method = form["method"]

                    for payload, pattern in self.PAYLOADS:
                        import re
                        data = {}
                        for f in form["inputs"]:
                            data[f["name"]] = payload if f["name"] == field_name else f["value"]

                        headers = {"User-Agent": self.config.user_agent}
                        try:
                            if method == "post":
                                req_coro = session.post(action_url, data=data, headers=headers, timeout=self.config.timeout)
                            else:
                                req_coro = session.get(action_url, params=data, headers=headers, timeout=self.config.timeout)

                            async with req_coro as resp:
                                body = await resp.text(errors="ignore")
                                if resp.status == 200 and re.search(pattern, body, re.IGNORECASE):
                                    findings.append(Vulnerability(
                                        plugin_name=self.name,
                                        severity=Severity.HIGH,
                                        title=f"Path Traversal / LFI in Form Field: '{field_name}'",
                                        description=(
                                            f"The form field '{field_name}' submitting to '{action_url}' is vulnerable "
                                            f"to Path Traversal. Injected payload '{payload}' returned a system file."
                                        ),
                                        remedy="Validate and sanitize user input. Resolve paths absolute and verify they lie within the allowed storage directory.",
                                        url=action_url,
                                        parameter=field_name,
                                        evidence=body[:150].strip().replace("\n", " ") + "...",
                                        request_method=method.upper()
                                    ))
                                    break
                        except Exception:
                            pass

        return findings
