import aiohttp
import re
from typing import List, Dict, Any
from .base import BasePlugin
from ..models import CrawledPage, Vulnerability, Severity

class SQLIPlugin(BasePlugin):
    name = "SQL Injection Scanner"
    description = "Tests input parameters and form fields for Error-based SQL Injection."

    PAYLOADS = [
        "'",
        "\"",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "1 UNION SELECT NULL--"
    ]

    # Common SQL Error Signatures
    ERROR_SIGNATURES = {
        "MySQL": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\."
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"invalid input syntax for integer",
            r"Severity: ERROR.*postgres"
        ],
        "Microsoft SQL Server": [
            r"Driver.*SQL Server",
            r"OLE DB Provider for SQL Server",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"System\.Data\.SqlClient\.SqlException"
        ],
        "Oracle": [
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"OracleException"
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"OperationalError: near"
        ]
    }

    async def run(self, session: aiohttp.ClientSession, pages: List[CrawledPage]) -> List[Vulnerability]:
        findings = []

        # Test query parameters (GET)
        for page in pages:
            if not page.params:
                continue

            for param_name in page.params.keys():
                for payload in self.PAYLOADS:
                    
                    async def check_func(status: int, body: str, response: aiohttp.ClientResponse) -> bool:
                        # Scan body for SQL error signatures
                        for db_name, regexes in self.ERROR_SIGNATURES.items():
                            for regex in regexes:
                                if re.search(regex, body, re.IGNORECASE):
                                    # Save metadata in closure or class
                                    response.db_found = db_name
                                    response.err_sig = regex
                                    return True
                        return False

                    response_obj = None
                    # We want to capture the response object to read the attached attributes
                    # Our _test_param doesn't return the response directly, but we can access it inside check_func or wrap it.
                    # Let's adjust how we test parameters or we can do it directly.
                    
                    test_params = page.params.copy()
                    test_params[param_name] = payload
                    
                    headers = {"User-Agent": self.config.user_agent}
                    try:
                        async with session.get(page.url, params=test_params, headers=headers, timeout=self.config.timeout) as resp:
                            body = await resp.text(errors="ignore")
                            for db_name, regexes in self.ERROR_SIGNATURES.items():
                                for regex in regexes:
                                    if re.search(regex, body, re.IGNORECASE):
                                        findings.append(Vulnerability(
                                            plugin_name=self.name,
                                            severity=Severity.HIGH,
                                            title=f"SQL Injection in Parameter: '{param_name}'",
                                            description=(
                                                f"An error-based SQL Injection vulnerability was detected. "
                                                f"Injecting the payload '{payload}' triggered a database error message indicating "
                                                f"the server is running {db_name}."
                                            ),
                                            remedy="Use parameterized queries / prepared statements (e.g., using PDO in PHP, PreparedStatement in Java, or ORMs) for all database operations. Never concatenate input strings directly into SQL queries.",
                                            url=page.url,
                                            parameter=param_name,
                                            evidence=f"Matched error regex '{regex}' for database {db_name}.",
                                            request_method="GET"
                                        ))
                                        break
                            else:
                                continue
                            break  # Break inner payload loop if vuln found
                    except Exception:
                        pass

        # Test Forms (GET & POST)
        for page in pages:
            for form in page.forms:
                for inp in form["inputs"]:
                    if inp["type"] not in ["text", "search", "url", "textarea", "password"]:
                        continue
                        
                    field_name = inp["name"]
                    action_url = form["action"]
                    method = form["method"]
                    
                    for payload in self.PAYLOADS:
                        # Prepare data payload
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
                                for db_name, regexes in self.ERROR_SIGNATURES.items():
                                    for regex in regexes:
                                        if re.search(regex, body, re.IGNORECASE):
                                            findings.append(Vulnerability(
                                                plugin_name=self.name,
                                                severity=Severity.HIGH,
                                                title=f"SQL Injection in Form Field: '{field_name}'",
                                                description=(
                                                    f"An error-based SQL Injection vulnerability was detected in form field '{field_name}' "
                                                    f"submitting to '{action_url}'. Injected payload '{payload}' triggered a database error."
                                                ),
                                                remedy="Implement parameterized queries / prepared statements. Use ORMs where possible and sanitize all user input before passing it to database queries.",
                                                url=action_url,
                                                parameter=field_name,
                                                evidence=f"Matched SQL error pattern for {db_name}: {regex}",
                                                request_method=method.upper()
                                            ))
                                            break
                                    else:
                                        continue
                                    break
                        except Exception:
                            pass

        return findings
