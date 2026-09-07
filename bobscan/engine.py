import asyncio
import time
import aiohttp
import logging
from typing import List, Dict, Any, Callable
from .models import ScanConfig, Vulnerability, CrawledPage, Severity
from .crawler import Crawler

# Import plugins
from .plugins.headers import HeadersPlugin
from .plugins.sensitive_files import SensitiveFilesPlugin
from .plugins.xss import XSSPlugin
from .plugins.sqli import SQLIPlugin
from .plugins.lfi import LFIPlugin

logger = logging.getLogger("BobScan.Engine")

class ScanEngine:
    def __init__(self, config: ScanConfig, status_callback: Callable[[str], None] = None):
        self.config = config
        self.status_callback = status_callback or (lambda msg: None)
        self.vulnerabilities: List[Vulnerability] = []
        self.crawled_pages: List[CrawledPage] = []
        self.duration = 0.0

        # Register plugins
        self.plugins = [
            HeadersPlugin(config),
            SensitiveFilesPlugin(config),
            XSSPlugin(config),
            SQLIPlugin(config),
            LFIPlugin(config)
        ]

    def _log_status(self, msg: str):
        logger.info(msg)
        self.status_callback(msg)

    async def run_scan(self) -> Dict[str, Any]:
        start_time = time.time()
        self._log_status("Initializing crawler...")
        
        # 1. Run Crawl phase
        crawler = Crawler(self.config)
        self.crawled_pages = await crawler.crawl()
        
        self._log_status(f"Crawl phase complete. Discovered {len(self.crawled_pages)} pages/endpoints.")

        if not self.crawled_pages:
            self._log_status("No pages could be crawled/resolved. Aborting active scan.")
            self.duration = time.time() - start_time
            return self.get_summary()

        # 2. Run Vulnerability Plugins
        self._log_status("Starting vulnerability assessment phase...")
        async with aiohttp.ClientSession() as session:
            for plugin in self.plugins:
                # If plugin is an active plugin and user disabled active scanning, skip (except headers/sensitive)
                if not self.config.active_scanning and plugin.name not in ["Security Headers Checker", "Sensitive Files & Directory Finder"]:
                    self._log_status(f"Skipping active plugin: {plugin.name}")
                    continue
                    
                self._log_status(f"Running plugin: {plugin.name}...")
                try:
                    findings = await plugin.run(session, self.crawled_pages)
                    self.vulnerabilities.extend(findings)
                    self._log_status(f"Plugin {plugin.name} found {len(findings)} issues.")
                except Exception as e:
                    logger.error(f"Error running plugin {plugin.name}: {e}", exc_info=True)
                    self._log_status(f"Error running plugin {plugin.name}: {e}")

        self.duration = time.time() - start_time
        self._log_status("Scan completed successfully.")
        return self.get_summary()

    def get_summary(self) -> Dict[str, Any]:
        severity_counts = {sev: 0 for sev in Severity}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1
            
        return {
            "target": self.config.target_url,
            "crawled_pages_count": len(self.crawled_pages),
            "vulnerabilities_count": len(self.vulnerabilities),
            "severity_counts": severity_counts,
            "duration_seconds": round(self.duration, 2),
            "vulnerabilities": self.vulnerabilities,
            "pages": self.crawled_pages
        }
