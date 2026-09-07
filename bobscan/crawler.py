import asyncio
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import aiohttp
from typing import Set, List, Dict, Any
from .models import CrawledPage, ScanConfig

logger = logging.getLogger("BobScan.Crawler")

class Crawler:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_url = config.target_url
        self.parsed_target = urlparse(config.target_url)
        self.target_domain = self.parsed_target.netloc
        self.target_scheme = self.parsed_target.scheme
        
        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[CrawledPage] = []
        self.semaphore = asyncio.Semaphore(config.concurrency_limit)
        
    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            # Must match the target domain and target scheme (or at least same domain)
            if parsed.netloc != self.target_domain:
                return False
            
            # Check exclusions
            path = parsed.path
            for exclude in self.config.exclude_paths:
                if exclude in path:
                    return False
            return True
        except Exception:
            return False

    def _normalize_url(self, url: str) -> str:
        # Strip fragments
        parsed = urlparse(url)
        normalized = parsed._replace(fragment="").geturl()
        return normalized

    async def _fetch_and_parse(self, session: aiohttp.ClientSession, url: str) -> tuple[int, str, List[str], List[Dict[str, Any]]]:
        headers = {"User-Agent": self.config.user_agent}
        try:
            async with self.semaphore:
                async with session.get(url, headers=headers, timeout=self.config.timeout, allow_redirects=True) as response:
                    status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    
                    if "text/html" not in content_type:
                        return status, "", [], []
                        
                    html = await response.text(errors="ignore")
                    
                    # Parse HTML
                    soup = BeautifulSoup(html, "html.parser")
                    
                    # Extract links
                    links = []
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        links.append(self._normalize_url(full_url))
                        
                    # Extract forms
                    forms = []
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        method = form.get("method", "get").lower()
                        form_url = urljoin(url, action)
                        
                        inputs = []
                        for input_tag in form.find_all(["input", "textarea", "select"]):
                            name = input_tag.get("name")
                            if name:
                                inputs.append({
                                    "name": name,
                                    "type": input_tag.get("type", "text"),
                                    "value": input_tag.get("value", "")
                                })
                        forms.append({
                            "action": form_url,
                            "method": method,
                            "inputs": inputs
                        })
                        
                    return status, html, links, forms
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return 0, "", [], []

    async def crawl(self) -> List[CrawledPage]:
        logger.info(f"Starting async crawl on: {self.target_url}")
        
        async with aiohttp.ClientSession() as session:
            queue = [self._normalize_url(self.target_url)]
            self.visited_urls.add(self._normalize_url(self.target_url))
            
            while queue:
                # Process URLs in chunks up to concurrency limit
                chunk = queue[:self.config.concurrency_limit]
                queue = queue[self.config.concurrency_limit:]
                
                tasks = [self._fetch_and_parse(session, url) for url in chunk]
                results = await asyncio.gather(*tasks)
                
                for url, (status, html, links, forms) in zip(chunk, results):
                    if status == 0:
                        continue
                    
                    # Parse URL parameters
                    parsed = urlparse(url)
                    params = {}
                    if parsed.query:
                        for item in parsed.query.split("&"):
                            if "=" in item:
                                k, v = item.split("=", 1)
                                params[k] = v
                    
                    page = CrawledPage(
                        url=url,
                        method="GET",
                        params=params,
                        forms=forms,
                        status_code=status
                    )
                    self.crawled_pages.append(page)
                    
                    # Add newly discovered links to the queue
                    for link in links:
                        if link not in self.visited_urls and self._is_in_scope(link):
                            self.visited_urls.add(link)
                            queue.append(link)
                            
        logger.info(f"Crawl completed. Discovered {len(self.crawled_pages)} pages.")
        return self.crawled_pages
