import aiohttp
from typing import List, Dict, Any, Callable, Coroutine
from ..models import CrawledPage, Vulnerability, Severity, ScanConfig

class BasePlugin:
    name: str = "Base Plugin"
    description: str = "Base class for all scanner plugins"
    
    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        """
        Runs the vulnerability checks against the crawled pages.
        Returns a list of Vulnerability findings.
        """
        raise NotImplementedError("Plugins must implement run()")

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict[str, str],
        payload: str,
        check_func: Callable[[int, str, aiohttp.ClientResponse], Coroutine[Any, Any, bool]]
    ) -> bool:
        """
        Helper to inject payload into a specific query parameter and test the response.
        """
        test_params = params.copy()
        test_params[param_name] = payload
        
        headers = {"User-Agent": self.config.user_agent}
        try:
            async with session.get(url, params=test_params, headers=headers, timeout=self.config.timeout) as response:
                body = await response.text(errors="ignore")
                return await check_func(response.status, body, response)
        except Exception:
            return False

    async def _test_form(
        self,
        session: aiohttp.ClientSession,
        form: Dict[str, Any],
        field_name: str,
        payload: str,
        check_func: Callable[[int, str, aiohttp.ClientResponse], Coroutine[Any, Any, bool]]
    ) -> bool:
        """
        Helper to inject payload into a specific form field and test the response.
        """
        action_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        
        data = {}
        for inp in inputs:
            name = inp["name"]
            val = inp["value"]
            if name == field_name:
                data[name] = payload
            else:
                data[name] = val
                
        headers = {"User-Agent": self.config.user_agent}
        try:
            if method == "post":
                async with session.post(action_url, data=data, headers=headers, timeout=self.config.timeout) as response:
                    body = await response.text(errors="ignore")
                    return await check_func(response.status, body, response)
            else:  # GET
                async with session.get(action_url, params=data, headers=headers, timeout=self.config.timeout) as response:
                    body = await response.text(errors="ignore")
                    return await check_func(response.status, body, response)
        except Exception:
            return False
