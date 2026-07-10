#!/usr/bin/env python3
"""
Subspy - Lightweight passive subdomain enumeration tool
Author: Security Researcher
Purpose: Educational recon tool for authorized testing only
"""

import argparse
import concurrent.futures
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Set

import dns.resolver
import httpx
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ==========================================
# CONFIGURATION
# ==========================================

MAX_WORKERS = 20
HTTP_TIMEOUT = 10
DNS_TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ==========================================
# LOGGING SETUP
# ==========================================

# Disable httpx logging to reduce clutter
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
console = Console()

# ==========================================
# MAIN ENUMERATOR CLASS
# ==========================================

class Subspy:
    """Main class for passive subdomain enumeration"""

    def __init__(self, domain: str, debug: bool = False):
        """Initialize the enumerator"""
        self.domain = domain.lower().strip()
        self.subdomains: Set[str] = set()
        self.results: List[Dict] = []
        self.sources_used: Set[str] = set()
        self.total_sources = 0
        self.start_time = time.time()

        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger("httpx").setLevel(logging.DEBUG)

        logger.info(f"Target: {self.domain}")

    # ------------------------------------------
    # Helper Methods
    # ------------------------------------------

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain or not subdomain.endswith(self.domain):
            return False
        if "*" in subdomain or ".." in subdomain:
            return False
        if len(subdomain) > 255:
            return False
        
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
        return bool(re.match(pattern, subdomain))

    # ------------------------------------------
    # Phase 1: Passive Enumeration Sources
    # ------------------------------------------

    def _source_crtsh(self) -> Set[str]:
        """Query crt.sh certificate transparency logs"""
        subdomains = set()
        try:
            # Fixed: URL encoding for the domain
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    # Handle multiple domains in one entry
                    for domain in name.split("\n"):
                        domain = domain.strip()
                        if domain and self._is_valid_subdomain(domain):
                            subdomains.add(domain)
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        self.sources_used.add("crt.sh")
        return subdomains

    def _source_certspotter(self) -> Set[str]:
        """Query CertSpotter API"""
        subdomains = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            for cert in response.json():
                for dns_name in cert.get("dns_names", []):
                    if self._is_valid_subdomain(dns_name):
                        subdomains.add(dns_name)
        except Exception as e:
            logger.debug(f"CertSpotter error: {e}")
        
        self.sources_used.add("CertSpotter")
        return subdomains

    def _source_alienvault(self) -> Set[str]:
        """Query AlienVault OTX"""
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            for record in response.json().get("passive_dns", []):
                hostname = record.get("hostname", "")
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except Exception as e:
            logger.debug(f"AlienVault error: {e}")
        
        self.sources_used.add("AlienVault")
        return subdomains

    def _source_hackertarget(self) -> Set[str]:
        """Query Hackertarget API"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            for line in response.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 1:
                    hostname = parts[0].strip()
                    if self._is_valid_subdomain(hostname):
                        subdomains.add(hostname)
        except Exception as e:
            logger.debug(f"Hackertarget error: {e}")
        
        self.sources_used.add("Hackertarget")
        return subdomains

    def _source_rapiddns(self) -> Set[str]:
        """Query RapidDNS"""
        subdomains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find("table")
            if table:
                for row in table.find_all("tr")[1:]:
                    cols = row.find_all("td")
                    if len(cols) >= 1:
                        hostname = cols[0].text.strip()
                        if self._is_valid_subdomain(hostname):
                            subdomains.add(hostname)
        except Exception as e:
            logger.debug(f"RapidDNS error: {e}")
        
        self.sources_used.add("RapidDNS")
        return subdomains

    def _source_wayback(self) -> Set[str]:
        """Query Wayback Machine CDX API"""
        subdomains = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            data = response.json()
            for entry in data[1:]:  # Skip header
                if isinstance(entry, list) and len(entry) > 0:
                    match = re.search(r"https?://([^/]+)", entry[0])
                    if match and self._is_valid_subdomain(match.group(1)):
                        subdomains.add(match.group(1))
        except Exception as e:
            logger.debug(f"Wayback error: {e}")
        
        self.sources_used.add("Wayback Machine")
        return subdomains

    def _source_subfinder(self) -> Set[str]:
        """Execute Subfinder via subprocess"""
        subdomains = set()
        
        if not shutil.which("subfinder"):
            logger.warning("Subfinder not installed")
            return subdomains

        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and self._is_valid_subdomain(line):
                        subdomains.add(line)
        except Exception as e:
            logger.debug(f"Subfinder error: {e}")
        
        self.sources_used.add("Subfinder")
        return subdomains

    def _source_assetfinder(self) -> Set[str]:
        """Execute Assetfinder via subprocess"""
        subdomains = set()
        
        if not shutil.which("assetfinder"):
            logger.warning("Assetfinder not installed")
            return subdomains

        try:
            result = subprocess.run(
                ["assetfinder", "--subs-only", self.domain],
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and self._is_valid_subdomain(line):
                        subdomains.add(line)
        except Exception as e:
            logger.debug(f"Assetfinder error: {e}")
        
        self.sources_used.add("Assetfinder")
        return subdomains

    def _run_passive_enumeration(self) -> None:
        """Execute all passive enumeration sources"""
        sources = [
            ("crt.sh", self._source_crtsh),
            ("CertSpotter", self._source_certspotter),
            ("AlienVault", self._source_alienvault),
            ("Hackertarget", self._source_hackertarget),
            ("RapidDNS", self._source_rapiddns),
            ("Wayback", self._source_wayback),
            ("Subfinder", self._source_subfinder),
            ("Assetfinder", self._source_assetfinder),
        ]
        
        self.total_sources = len(sources)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Enumerating subdomains...", total=len(sources))
            
            for name, func in sources:
                progress.update(task, description=f"[cyan]Querying {name}...")
                try:
                    self.subdomains.update(func())
                except Exception as e:
                    logger.error(f"{name} error: {e}")
                progress.advance(task)

    # ------------------------------------------
    # Phase 2: DNS Resolution
    # ------------------------------------------

    def _resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Resolve a single subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            ip_addresses = []
            cname = None

            # Get A records
            try:
                answers = resolver.resolve(subdomain, "A")
                ip_addresses = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass

            # Get CNAME
            try:
                answers = resolver.resolve(subdomain, "CNAME")
                cname = str(answers[0].target).rstrip(".")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass

            if ip_addresses or cname:
                return {
                    "subdomain": subdomain,
                    "ip": ip_addresses[0] if ip_addresses else "",
                    "ip_list": ip_addresses,
                    "cname": cname,
                }

            return None

        except Exception as e:
            logger.debug(f"Resolution failed for {subdomain}: {e}")
            return None

    def _resolve_subdomains(self, subdomains: Set[str]) -> List[Dict]:
        """Resolve all subdomains in parallel"""
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[yellow]Resolving subdomains...", total=len(subdomains))

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(self._resolve_subdomain, subdomain): subdomain
                    for subdomain in subdomains
                }

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.debug(f"Resolution error: {e}")
                    progress.advance(task)

        return results

    # ------------------------------------------
    # Phase 3: HTTP Probing
    # ------------------------------------------

    def _probe_http(self, subdomain: str) -> Optional[Dict]:
        """Probe a subdomain for HTTP/HTTPS"""
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{subdomain}"
                with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                    response = client.get(url, headers={"User-Agent": USER_AGENT})

                    # Consider any 2xx or 3xx as "alive" but only 200 as "live"
                    if response.status_code == 200:
                        title = ""
                        try:
                            soup = BeautifulSoup(response.text, "html.parser")
                            title_tag = soup.find("title")
                            if title_tag:
                                title = title_tag.text.strip()[:100]
                        except Exception:
                            pass

                        return {
                            "subdomain": subdomain,
                            "status": response.status_code,
                            "title": title,
                            "server": response.headers.get("server", ""),
                            "url": url,
                        }
                    # If we get any response, consider it alive but not 200
                    elif response.status_code < 500:
                        return {
                            "subdomain": subdomain,
                            "status": response.status_code,
                            "title": "",
                            "server": response.headers.get("server", ""),
                            "url": url,
                        }

            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                continue

        return None

    def _probe_subdomains(self, resolved_results: List[Dict]) -> List[Dict]:
        """Probe resolved subdomains for HTTP/HTTPS"""
        probe_results = []
        subdomains = [r["subdomain"] for r in resolved_results]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Probing HTTP...", total=len(subdomains))

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(self._probe_http, subdomain): subdomain
                    for subdomain in subdomains
                }

                for future in concurrent.futures.as_completed(futures):
                    subdomain = futures[future]
                    try:
                        result = future.result()
                        if result:
                            # Merge with resolution data
                            for resolved in resolved_results:
                                if resolved["subdomain"] == subdomain:
                                    result["ip"] = resolved.get("ip", "")
                                    result["cname"] = resolved.get("cname", "")
                                    break
                            probe_results.append(result)
                        else:
                            # Not alive, mark as DEAD
                            for resolved in resolved_results:
                                if resolved["subdomain"] == subdomain:
                                    probe_results.append({
                                        "subdomain": subdomain,
                                        "ip": resolved.get("ip", ""),
                                        "cname": resolved.get("cname", ""),
                                        "status": "DEAD",
                                        "title": "",
                                        "server": "",
                                    })
                                    break
                    except Exception as e:
                        logger.debug(f"Probe error: {e}")
                    progress.advance(task)

        return probe_results

    # ------------------------------------------
    # Output & Results
    # ------------------------------------------

    def _display_results(self, results: List[Dict]) -> None:
        """Display results in a Rich table"""
        table = Table(title="Subdomain Enumeration Results", show_lines=True)
        table.add_column("Subdomain", style="cyan", no_wrap=True)
        table.add_column("IP", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Server", style="blue")
        table.add_column("Title", style="magenta")

        # Sort: 200 first, then other statuses, then DEAD
        live_hosts = [r for r in results if r.get("status") == 200]
        other_hosts = [r for r in results if r.get("status") not in [200, "DEAD"]]
        dead_hosts = [r for r in results if r.get("status") == "DEAD"]

        for result in live_hosts + other_hosts + dead_hosts:
            status = str(result.get("status", ""))
            if status == "200":
                status_display = Text("200", style="green bold")
            elif status == "DEAD":
                status_display = Text("DEAD", style="red bold")
            else:
                status_display = Text(status, style="yellow")

            table.add_row(
                result.get("subdomain", ""),
                result.get("ip", ""),
                status_display,
                result.get("server", ""),
                result.get("title", "")[:50],
            )

        console.print(table)

        # Summary
        execution_time = time.time() - self.start_time
        resolved_count = len([r for r in results if r.get("ip")])
        live_count = len([r for r in results if r.get("status") == 200])

        console.print()
        console.print("[bold]Summary[/bold]")
        console.print(f"  • Sources Queried: {self.total_sources}")
        console.print(f"  • Unique Subdomains Found: {len(self.subdomains)}")
        console.print(f"  • Resolved Hosts: {resolved_count}")
        console.print(f"  • Live Hosts (HTTP 200): {live_count}")
        console.print(f"  • Execution Time: {execution_time:.2f}s")

    def _save_results(self, results: List[Dict]) -> None:
        """Save results to JSON and TXT files"""
        # JSON output
        json_file = f"{self.domain}_results.json"
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {json_file}")

        # TXT output
        txt_file = f"{self.domain}_results.txt"
        with open(txt_file, "w") as f:
            f.write(f"Subdomain Enumeration Results for {self.domain}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 80 + "\n\n")
            
            f.write(f"{'Subdomain':<40} {'IP':<20} {'Status':<10} {'Server':<20}\n")
            f.write("-" * 90 + "\n")
            
            for result in results:
                status = str(result.get("status", ""))
                f.write(
                    f"{result.get('subdomain', ''):<40} "
                    f"{result.get('ip', ''):<20} "
                    f"{status:<10} "
                    f"{result.get('server', ''):<20}\n"
                )
            
            f.write("\n" + "-" * 80 + "\n")
            f.write("SUMMARY\n")
            f.write(f"Total Sources Queried: {self.total_sources}\n")
            f.write(f"Unique Subdomains: {len(self.subdomains)}\n")
            f.write(f"Resolved Hosts: {len([r for r in results if r.get('ip')])}\n")
            f.write(f"Live Hosts: {len([r for r in results if r.get('status') == 200])}\n")
            f.write(f"Execution Time: {time.time() - self.start_time:.2f}s\n")

        logger.info(f"Results saved to {txt_file}")

    # ------------------------------------------
    # Main Execution
    # ------------------------------------------

    def run(self) -> None:
        """Main execution flow"""
        try:
            console.print(f"[bold cyan]Target:[/bold cyan] {self.domain}\n")
            
            # Phase 1: Passive enumeration
            self._run_passive_enumeration()
            
            if not self.subdomains:
                console.print("[red]No subdomains found. Exiting.[/red]")
                return

            # Phase 2: DNS Resolution
            resolved_results = self._resolve_subdomains(self.subdomains)
            
            if not resolved_results:
                console.print("[red]No subdomains resolved. Exiting.[/red]")
                return

            # Phase 3: HTTP Probing
            probe_results = self._probe_subdomains(resolved_results)

            # Display results
            self._display_results(probe_results)
            
            # Save results
            self._save_results(probe_results)

        except KeyboardInterrupt:
            console.print("\n[red]Interrupted by user[/red]")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.exit(1)

# ==========================================
# ENTRY POINT
# ==========================================

def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Subspy - Passive subdomain enumeration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subspy.py -d example.com
  python3 subspy.py --domain example.com
        """,
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain (e.g., example.com)",
        type=str,
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Validate domain
    domain_pattern = r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
    if not re.match(domain_pattern, args.domain):
        console.print("[red]Invalid domain format[/red]")
        sys.exit(1)

    # Run Subspy
    subspy = Subspy(args.domain, args.debug)
    subspy.run()

if __name__ == "__main__":
    main()
