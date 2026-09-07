import aiohttp
import asyncio
import html
from typing import List, Dict, Any
from .base import BasePlugin
from ..models import CrawledPage, Vulnerability, Severity

class XSSPlugin(BasePlugin):
    name = "Reflected XSS Scanner"
    description = "Tests input parameters and form fields for Reflected Cross-Site Scripting (XSS)."

    PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "';alert(1);//",
        "<svg/onload=alert(1)>",
        "\"><svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>"
    ]

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        findings = []
        
        # Test query parameters (GET)
        for page in pages:
            if not page.params:
                continue
                
            for param_name in page.params.keys():
                for payload in self.PAYLOADS:
                    # Define check function
                    async def check_func(status: int, body: str, response: aiohttp.ClientResponse) -> bool:
                        # Make sure payload is in body, and specifically not HTML-escaped.
                        # For example, if we sent `<script>`, it shouldn't show up as `&lt;script&gt;`
                        escaped_payload = html.escape(payload)
                        if payload in body:
                            # Verify it was not escaped by comparing index of raw vs escaped
                            # if raw is present, it's vulnerable.
                            return True
                        return False

                    is_vulnerable = await self._test_param(
                        session, page.url, param_name, page.params, payload, check_func
                    )
                    
                    if is_vulnerable:
                        findings.append(Vulnerability(
                            plugin_name=self.name,
                            severity=Severity.HIGH,
                            title=f"Reflected Cross-Site Scripting (XSS) in Parameter: '{param_name}'",
                            description=(
                                f"The application reflects input from the '{param_name}' parameter without proper HTML encoding. "
                                "An attacker could leverage this to execute arbitrary JavaScript in the victim's browser context."
                            ),
                            remedy="HTML-escape all user-controlled input reflected in responses. Use content-aware encoding or modern templates that escape HTML by default.",
                            url=page.url,
                            parameter=param_name,
                            evidence=f"Reflected payload in response: {payload}",
                            request_method="GET"
                        ))
                        break  # Stop testing other payloads for this parameter if we found one vulnerable

        # Test Forms (GET & POST)
        for page in pages:
            for form in page.forms:
                for inp in form["inputs"]:
                    # Skip submit/button inputs that generally aren't fuzzable text fields
                    if inp["type"] not in ["text", "search", "url", "textarea"]:
                        continue
                        
                    field_name = inp["name"]
                    for payload in self.PAYLOADS:
                        async def check_func(status: int, body: str, response: aiohttp.ClientResponse) -> bool:
                            return payload in body

                        is_vulnerable = await self._test_form(
                            session, form, field_name, payload, check_func
                        )

                        if is_vulnerable:
                            findings.append(Vulnerability(
                                plugin_name=self.name,
                                severity=Severity.HIGH,
                                title=f"Form Field Vulnerable to XSS: '{field_name}'",
                                description=(
                                    f"The form field '{field_name}' submitting to '{form['action']}' "
                                    "reflects input directly into the response without encoding."
                                ),
                                remedy="Context-aware output escaping / sanitization of input before rendering it in the HTML body.",
                                url=form["action"],
                                parameter=field_name,
                                evidence=f"Reflected payload in form response: {payload}",
                                request_method=form["method"].upper()
                            ))
                            break

        return findings
