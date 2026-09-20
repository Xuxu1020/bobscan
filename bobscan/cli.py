import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme
from rich.logging import RichHandler

from .models import ScanConfig, Severity
from .engine import ScanEngine

# Setup beautiful Rich CLI themes
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "critical": "bold red blink",
    "high": "bold red",
    "medium": "orange3",
    "low": "yellow",
    "info_sev": "blue",
})

console = Console(theme=custom_theme)

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)]
    )

def print_banner():
    banner = """
    ===========================================
        BobScan - Web Vulnerability Scanner  
    ===========================================
    """
    try:
        console.print(banner)
    except Exception:
        # Fallback to plain print
        print("BobScan - Modular Web Vulnerability Scanner")
    console.print("[dim]Built with Python[/dim]\n")


def export_json(summary: Dict[str, Any], file_path: str):
    # Convert Enum / objects to dict/string for json serialization
    serializable = {
        "target": summary["target"],
        "crawled_pages_count": summary["crawled_pages_count"],
        "vulnerabilities_count": summary["vulnerabilities_count"],
        "severity_counts": summary["severity_counts"],
        "duration_seconds": summary["duration_seconds"],
        "vulnerabilities": [
            {
                "plugin_name": v.plugin_name,
                "severity": v.severity.value,
                "title": v.title,
                "description": v.description,
                "remedy": v.remedy,
                "url": v.url,
                "parameter": v.parameter,
                "evidence": v.evidence,
                "request_method": v.request_method
            }
            for v in summary["vulnerabilities"]
        ],
        "pages": [
            {
                "url": p.url,
                "method": p.method,
                "status_code": p.status_code
            }
            for p in summary["pages"]
        ]
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=4)
    console.print(f"[success][+][/success] JSON Report exported to: [cyan]{file_path}[/cyan]")

def export_html(summary: Dict[str, Any], file_path: str):
    # Generates a premium dark-themed HTML report dashboard
    vulns_json = json.dumps([
        {
            "plugin_name": v.plugin_name,
            "severity": v.severity.value,
            "title": v.title,
            "description": v.description,
            "remedy": v.remedy,
            "url": v.url,
            "parameter": v.parameter or "N/A",
            "evidence": html_escape(v.evidence or ""),
            "request_method": v.request_method
        }
        for v in summary["vulnerabilities"]
    ])
    
    severity_counts = summary["severity_counts"]
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BobScan Security Assessment Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --panel-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-muted: #8b949e;
            --primary: #58a6ff;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #f0883e;
            --low: #d29922;
            --info: #388bfd;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 24px;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        h1 {{ margin: 0; color: #fff; font-size: 24px; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
        }}
        .badge-CRITICAL {{ background: rgba(248, 81, 73, 0.15); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-HIGH {{ background: rgba(255, 123, 114, 0.15); color: var(--high); border: 1px solid var(--high); }}
        .badge-MEDIUM {{ background: rgba(240, 136, 62, 0.15); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-LOW {{ background: rgba(210, 153, 34, 0.15); color: var(--low); border: 1px solid var(--low); }}
        .badge-INFO {{ background: rgba(56, 139, 253, 0.15); color: var(--info); border: 1px solid var(--info); }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}
        .metric-val {{ font-size: 32px; font-weight: bold; margin-top: 8px; }}
        .metric-card.critical .metric-val {{ color: var(--critical); }}
        .metric-card.high .metric-val {{ color: var(--high); }}
        .metric-card.medium .metric-val {{ color: var(--medium); }}
        .metric-card.low .metric-val {{ color: var(--low); }}
        
        .vuln-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}
        .vuln-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            overflow: hidden;
        }}
        .vuln-header {{
            padding: 16px;
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .vuln-header-left {{ display: flex; align-items: center; gap: 12px; }}
        .vuln-title {{ font-size: 16px; font-weight: bold; color: #fff; }}
        .vuln-body {{
            padding: 16px;
        }}
        .vuln-meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            font-size: 13px;
            background: rgba(0, 0, 0, 0.2);
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
        }}
        .vuln-meta span {{ color: var(--text-muted); }}
        .vuln-meta strong {{ color: var(--text-color); }}
        .evidence-box {{
            background: #000;
            color: #39ff14;
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            white-space: pre-wrap;
            border: 1px solid var(--border-color);
            margin-top: 10px;
        }}
        .section-title {{
            font-size: 18px;
            margin-bottom: 16px;
            color: #fff;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>BobScan Security Assessment Report</h1>
            <div style="color: var(--text-muted); margin-top: 6px;">Target: <strong>{summary["target"]}</strong></div>
        </div>
        <div>
            <span class="badge" style="background: #238636; color: #fff;">Scan Complete</span>
        </div>
    </header>

    <div class="metrics-grid">
        <div class="metric-card">
            <div style="color: var(--text-muted);">Pages Crawled</div>
            <div class="metric-val" style="color: var(--primary);">{summary["crawled_pages_count"]}</div>
        </div>
        <div class="metric-card critical">
            <div>Critical Issues</div>
            <div class="metric-val">{severity_counts.get(Severity.CRITICAL, 0)}</div>
        </div>
        <div class="metric-card high">
            <div>High Issues</div>
            <div class="metric-val">{severity_counts.get(Severity.HIGH, 0)}</div>
        </div>
        <div class="metric-card medium">
            <div>Medium Issues</div>
            <div class="metric-val">{severity_counts.get(Severity.MEDIUM, 0)}</div>
        </div>
        <div class="metric-card low">
            <div>Low/Info Issues</div>
            <div class="metric-val">{severity_counts.get(Severity.LOW, 0) + severity_counts.get(Severity.INFO, 0)}</div>
        </div>
    </div>

    <div class="section-title">Discovered Vulnerabilities ({summary["vulnerabilities_count"]})</div>
    
    <div class="vuln-list" id="vuln-container"></div>

    <script>
        const vulns = {vulns_json};
        const container = document.getElementById('vuln-container');
        
        if (vulns.length === 0) {{
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">No vulnerabilities detected during assessment. Good job!</div>';
        }} else {{
            vulns.forEach((v, idx) => {{
                const card = document.createElement('div');
                card.className = 'vuln-card';
                card.innerHTML = `
                    <div class="vuln-header">
                        <div class="vuln-header-left">
                            <span class="badge badge-${{v.severity}}">${{v.severity}}</span>
                            <span class="vuln-title">${{v.title}}</span>
                        </div>
                        <div style="color: var(--text-muted); font-size: 13px;">${{v.plugin_name}}</div>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-meta">
                            <div><span>URL:</span> <strong>${{v.url}}</strong></div>
                            <div><span>Parameter:</span> <strong>${{v.parameter}}</strong></div>
                            <div><span>Method:</span> <strong>${{v.request_method}}</strong></div>
                            <div><span>Severity:</span> <strong style="color: var(--${{v.severity.toLowerCase()}})">${{v.severity}}</strong></div>
                        </div>
                        <div>
                            <strong>Description:</strong>
                            <p style="margin-top: 6px; margin-bottom: 16px;">${{v.description}}</p>
                        </div>
                        <div>
                            <strong>Remedy / Mitigation:</strong>
                            <p style="margin-top: 6px; margin-bottom: 16px; color: #58a6ff;">${{v.remedy}}</p>
                        </div>
                        ${{v.evidence ? `
                            <div>
                                <strong>Evidence:</strong>
                                <div class="evidence-box">${{v.evidence}}</div>
                            </div>
                        ` : ''}}
                    </div>
                `;
                container.appendChild(card);
            }});
        }}
    </script>
</body>
</html>
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    console.print(f"[success][+][/success] HTML Report dashboard exported to: [cyan]{file_path}[/cyan]")

def html_escape(text: str) -> str:
    import html
    return html.escape(text)

def main():
    parser = argparse.ArgumentParser(description="BobScan - Modular Web Vulnerability Scanner")
    parser.add_argument("target", help="Target URL to scan (e.g. http://localhost:5000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrency / request rate limit")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP Request timeout in seconds")
    parser.add_argument("--exclude", nargs="*", default=[], help="Exclude paths containing these substrings")
    parser.add_argument("--no-active", action="store_true", help="Disable active vulnerability testing (perform passive/crawling only)")
    parser.add_argument("-o", "--output", help="Path to write scan output report (JSON or HTML format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose debugging logs")
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    print_banner()
    
    # Setup config
    config = ScanConfig(
        target_url=args.target,
        concurrency_limit=args.threads,
        timeout=args.timeout,
        exclude_paths=args.exclude,
        active_scanning=not args.no_active
    )
    
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{config.target_url}[/cyan]\n"
        f"[bold white]Concurrency Limit:[/bold white] [yellow]{config.concurrency_limit}[/yellow]\n"
        f"[bold white]Active Scanning:[/bold white] [{'green' if config.active_scanning else 'red'}]{config.active_scanning}[/]\n"
        f"[bold white]Scope:[/bold white] In-domain pages only",
        title="[bold green]Scan Parameters[/bold green]",
        border_style="green"
    ))
    
    def on_status_update(msg: str):
        console.print(f"[info][*][/info] {msg}")
        
    engine = ScanEngine(config, status_callback=on_status_update)
    
    try:
        summary = asyncio.run(engine.run_scan())
    except KeyboardInterrupt:
        console.print("\n[danger]Scan cancelled by user.[/danger]")
        sys.exit(1)
        
    # Render final report table
    console.print("\n" + "="*80)
    console.print("[bold white]SCAN SUMMARY REPORT[/bold white]")
    console.print("="*80)
    console.print(f"Elapsed Time: {summary['duration_seconds']} seconds")
    console.print(f"Total Crawled: {summary['crawled_pages_count']} links")
    console.print(f"Total Findings: {summary['vulnerabilities_count']} vulnerabilities")
    
    # Severity breakdown table
    table = Table(title="Vulnerabilities by Severity", title_style="bold", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")
    
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = summary["severity_counts"].get(sev, 0)
        style = sev.lower()
        table.add_row(f"[{style}]{sev}[/{style}]", str(count))
        
    console.print(table)
    
    # Print individual vulnerability details
    if summary["vulnerabilities"]:
        console.print("\n[bold red]Detailed Findings:[/bold red]")
        for idx, vuln in enumerate(summary["vulnerabilities"], 1):
            sev_style = vuln.severity.value.lower()
            console.print(Panel(
                f"[bold white]Description:[/bold white] {vuln.description}\n"
                f"[bold white]URL:[/bold white] [cyan]{vuln.url}[/cyan]\n"
                f"[bold white]Method:[/bold white] {vuln.request_method}" + 
                (f"  |  [bold white]Parameter:[/bold white] [yellow]{vuln.parameter}[/yellow]" if vuln.parameter else "") + "\n"
                f"[bold white]Evidence:[/bold white] [info]{vuln.evidence or 'N/A'}[/info]\n"
                f"[bold white]Remedy:[/bold white] [success]{vuln.remedy}[/success]",
                title=f"[bold {sev_style}]{idx}. [{vuln.severity}] {vuln.title}[/]",
                border_style=sev_style
            ))
            
    # Handle output files
    if args.output:
        out_path = args.output
        if out_path.endswith(".json"):
            export_json(summary, out_path)
        elif out_path.endswith(".html"):
            export_html(summary, out_path)
        else:
            # Default to JSON
            export_json(summary, out_path + ".json")

if __name__ == "__main__":
    main()
