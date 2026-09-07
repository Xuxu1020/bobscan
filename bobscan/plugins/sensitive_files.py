import aiohttp
import asyncio
from typing import List, Dict
from urllib.parse import urljoin
from .base import BasePlugin
from ..models import CrawledPage, Vulnerability, Severity

class SensitiveFilesPlugin(BasePlugin):
    name = "Sensitive Files & Directory Finder"
    description = "Searches for common sensitive files and backup/config files exposed on the server."

    PROBES = {
        ".git/config": ("[core]", "Git configuration file containing repository details and possibly credentials."),
        ".env": ("DB_", "Environment configuration file that often contains API keys, database credentials, and secrets."),
        "config.php.bak": ("<?php", "Backup of php configuration file, which might leak database configuration details."),
        "db.sql": ("CREATE TABLE", "Exposed SQL database dump, risking complete database disclosure."),
        "robots.txt": ("User-agent:", "Exposed robots.txt. Useful for maps/endpoints, though low severity by itself."),
        "composer.json": ("require", "PHP composer dependency description file, disclosing dependency version vulnerabilities."),
        "package.json": ("dependencies", "NodeJS packages description file, disclosing dependency version vulnerabilities.")
    }

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        findings = []
        if not pages:
            return findings

        # Get base URL (target root)
        base_url = self.config.target_url
        if not base_url.endswith("/"):
            # If target is e.g. http://localhost/index.php, strip index.php
            import posixpath
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            path = parsed.path
            if path and not path.endswith("/"):
                dir_path = posixpath.dirname(path)
                if not dir_path.endswith("/"):
                    dir_path += "/"
                base_url = parsed._replace(path=dir_path, query="", fragment="").geturl()
            else:
                base_url += "/"

        # 1. Baseline check to detect wildcard/custom 404 returning HTTP 200
        headers = {"User-Agent": self.config.user_agent}
        wildcard_url = urljoin(base_url, "nonexistent_file_check_bobscan_xyz.html")
        wildcard_status = 0
        wildcard_len = 0
        try:
            async with session.get(wildcard_url, headers=headers, timeout=self.config.timeout) as resp:
                wildcard_status = resp.status
                wildcard_len = len(await resp.text())
        except Exception:
            pass

        # If server returns 200 for nonexistent files, we must be careful
        has_wildcard_200 = (wildcard_status == 200)

        # 2. Probe path concurrently
        async def check_path(path: str, keyword: str, desc: str):
            probe_url = urljoin(base_url, path)
            try:
                async with session.get(probe_url, headers=headers, timeout=self.config.timeout) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        
                        # If server has wildcard 200, check if this page is different from the wildcard
                        if has_wildcard_200 and len(body) == wildcard_len:
                            return
                            
                        # If a keyword is required, check if it's in the response
                        if keyword and keyword not in body:
                            return

                        # We found a match!
                        severity = Severity.HIGH
                        if path in ["robots.txt", "composer.json", "package.json"]:
                            severity = Severity.LOW
                        elif path in [".git/config", ".env", "db.sql"]:
                            severity = Severity.HIGH

                        findings.append(Vulnerability(
                            plugin_name=self.name,
                            severity=severity,
                            title=f"Exposed Sensitive File: /{path}",
                            description=f"A sensitive file was discovered publicly accessible: {desc}",
                            remedy=f"Restrict access to /{path} in your server configuration or delete the file from the web root.",
                            url=probe_url,
                            evidence=body[:100].replace("\n", " ") + "..." if body else "HTTP 200 OK",
                            request_method="GET"
                        ))
            except Exception:
                pass

        tasks = [check_path(path, keyword, desc) for path, (keyword, desc) in self.PROBES.items()]
        await asyncio.gather(*tasks)

        return findings
