import aiohttp
from typing import List
from .base import BasePlugin
from ..models import CrawledPage, Vulnerability, Severity

class HeadersPlugin(BasePlugin):
    name = "Security Headers Checker"
    description = "Checks response headers for missing or misconfigured security headers."

    # Map of header -> description
    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": ("HSTS", "Enforces HTTPS connections."),
        "Content-Security-Policy": ("CSP", "Controls resources the user agent is allowed to load."),
        "X-Frame-Options": ("X-Frame-Options", "Prevents clickjacking attacks."),
        "X-Content-Type-Options": ("X-Content-Type-Options", "Prevents MIME-sniffing."),
        "Referrer-Policy": ("Referrer-Policy", "Controls how much referrer information is shared.")
    }

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        findings = []
        if not pages:
            return findings

        # Check target homepage
        target_page = pages[0]
        headers = {"User-Agent": self.config.user_agent}
        
        try:
            async with session.get(target_page.url, headers=headers, timeout=self.config.timeout) as response:
                resp_headers = response.headers
                
                # Check server header disclosure
                server = resp_headers.get("Server")
                if server:
                    findings.append(Vulnerability(
                        plugin_name=self.name,
                        severity=Severity.INFO,
                        title="Web Server Header Information Disclosure",
                        description=f"The Server header discloses software/version details: '{server}'",
                        remedy="Disable or obfuscate the 'Server' header in your web server configuration.",
                        url=target_page.url,
                        evidence=f"Server: {server}"
                    ))
                
                # Check missing security headers
                for h_name, (h_title, h_desc) in self.RECOMMENDED_HEADERS.items():
                    if h_name not in resp_headers:
                        findings.append(Vulnerability(
                            plugin_name=self.name,
                            severity=Severity.LOW,
                            title=f"Missing {h_title} Header",
                            description=f"The HTTP response header '{h_name}' is not set. {h_desc}",
                            remedy=f"Configure your web server to include the '{h_name}' header with appropriate security policies.",
                            url=target_page.url,
                            evidence=f"Missing header: {h_name}"
                        ))
        except Exception as e:
            pass

        return findings
