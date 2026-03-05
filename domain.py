#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Domain - Advanced Domain Reconnaissance Tool
Author: SayerLinux
Email: SayerLinux@gmail.com
GitHub: https://github.com/SaudiLinux/Domain
'''

import os
import sys
import argparse
import time
import json
import threading
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich.text import Text
from rich import print as rprint
import logging
from pathlib import Path
import hashlib
import pickle

# Import modules
from modules.banner import display_banner
from modules.info_gatherer import DomainInfo
from modules.subdomain_enum import SubdomainEnumerator
from modules.url_discovery import URLDiscovery
from modules.admin_finder import AdminFinder
from modules.attack_surface import AttackSurfaceMapper
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.report_generator import ReportGenerator
from modules.utils import check_requirements, is_valid_domain, setup_logging
from modules.advanced_ui import RealTimeDashboard, InteractiveMenu, SecurityVisualizer
from modules.advanced_report import AdvancedReportGenerator

# Initialize console
console = Console()

# Global variables for performance tracking
scan_stats = {
    'start_time': None,
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0,
    'modules_completed': 0,
    'total_modules': 0,
    'current_module': 'Initializing',
    'errors': []
}

# Cache system
class ScanCache:
    """Advanced caching system for scan results"""
    def __init__(self, cache_dir='cache'):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    def _get_cache_key(self, domain, module, params=None):
        """Generate cache key based on domain and parameters"""
        key_data = f"{domain}_{module}_{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, domain, module, params=None):
        """Get cached results"""
        cache_key = self._get_cache_key(domain, module, params)
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'rb') as f:
                    cached_data = pickle.load(f)
                    # Check if cache is less than 24 hours old
                    if time.time() - cached_data['timestamp'] < 86400:
                        return cached_data['data']
            except Exception:
                pass
        return None
    
    def set(self, domain, module, data, params=None):
        """Cache results"""
        cache_key = self._get_cache_key(domain, module, params)
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        
        cache_data = {
            'timestamp': time.time(),
            'data': data,
            'domain': domain,
            'module': module
        }
        
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            logging.warning(f"Failed to cache data: {e}")

# Advanced progress display
class AdvancedProgress:
    """Enhanced progress display with real-time statistics"""
    def __init__(self):
        self.layout = Layout()
        self.setup_layout()
        
    def setup_layout(self):
        """Setup the layout for progress display"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="stats", size=5)
        )
        
        self.layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="log", ratio=1)
        )
    
    def create_header(self, domain):
        """Create header with domain info"""
        header_text = Text(f"Domain Reconnaissance: {domain}", style="bold cyan")
        return Panel(Align.center(header_text), border_style="cyan")
    
    def create_stats_panel(self):
        """Create statistics panel"""
        stats_table = Table(show_header=False, box=None, padding=0)
        stats_table.add_column(style="bold")
        stats_table.add_column()
        
        duration = time.time() - (scan_stats['start_time'] or time.time())
        success_rate = (scan_stats['successful_requests'] / max(scan_stats['total_requests'], 1)) * 100
        
        stats_table.add_row("Duration:", f"{duration:.1f}s")
        stats_table.add_row("Requests:", f"{scan_stats['total_requests']} ({success_rate:.1f}% success)")
        stats_table.add_row("Modules:", f"{scan_stats['modules_completed']}/{scan_stats['total_modules']}")
        stats_table.add_row("Current:", scan_stats['current_module'])
        
        return Panel(stats_table, title="Statistics", border_style="green")
    
    def update_display(self, domain):
        """Update the display"""
        self.layout["header"].update(self.create_header(domain))
        self.layout["stats"].update(self.create_stats_panel())

# Enhanced error handling
class ScanError(Exception):
    """Custom exception for scan errors"""
    pass

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    console.print("\n[yellow]Scan interrupted by user. Saving results...[/yellow]")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def parse_arguments():
    """Enhanced argument parser with advanced options"""
    parser = argparse.ArgumentParser(
        description='Domain - Advanced Domain Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com --full                    # Run all modules
  %(prog)s -d example.com --info --subdomains        # Run specific modules
  %(prog)s -d example.com --full --threads 20       # Increase thread count
  %(prog)s -d example.com --full --output results/  # Custom output directory
  %(prog)s -d example.com --full --no-cache         # Force refresh cache
        """
    )
    
    # Main arguments
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--full', action='store_true', help='Run all scan modules')
    
    # Module selection
    parser.add_argument('--info', action='store_true', help='Gather basic domain information (DNS, WHOIS, etc.)')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains using multiple techniques')
    parser.add_argument('--urls', action='store_true', help='Discover hidden URLs and directories')
    parser.add_argument('--admin-finder', action='store_true', help='Find admin/login pages')
    parser.add_argument('--attack-surface', action='store_true', help='Map attack surface and technologies')
    parser.add_argument('--vulns', action='store_true', help='Scan for common vulnerabilities')
    
    # Performance options
    performance_group = parser.add_argument_group('Performance Options')
    performance_group.add_argument('--threads', type=int, default=10, help='Number of threads to use (default: 10)')
    performance_group.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds (default: 30)')
    performance_group.add_argument('--delay', type=str, default='0', help='Delay between requests. Can be a fixed number (e.g., 2) or a range (e.g., 1-3)')
    performance_group.add_argument('--max-retries', type=int, default=3, help='Maximum retries for failed requests (default: 3)')
    
    # Request options
    request_group = parser.add_argument_group('Request Options')
    request_group.add_argument('--user-agent', help='Custom User-Agent string')
    request_group.add_argument('--headers', action='append', help='Custom headers (format: "Key: Value")')
    request_group.add_argument('--proxy', help='Proxy URL (http://host:port)')
    request_group.add_argument('--follow-redirects', action='store_true', help='Follow redirects (default: True)')
    request_group.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    
    # Wordlist options
    wordlist_group = parser.add_argument_group('Wordlist Options')
    wordlist_group.add_argument('--wordlist', help='Custom wordlist for brute forcing')
    wordlist_group.add_argument('--subdomains-wordlist', help='Custom subdomain wordlist')
    wordlist_group.add_argument('--dirs-wordlist', help='Custom directory wordlist')
    wordlist_group.add_argument('--admin-wordlist', help='Custom admin finder wordlist')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--format', choices=['json', 'html', 'txt', 'xml'], default='json', help='Output format (default: json)')
    output_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    output_group.add_argument('--quiet', '-q', action='store_true', help='Quiet mode (minimal output)')
    output_group.add_argument('--report-template', help='Custom HTML report template')
    
    # Cache options
    cache_group = parser.add_argument_group('Cache Options')
    cache_group.add_argument('--no-cache', action='store_true', help='Disable caching of results')
    cache_group.add_argument('--cache-dir', default='cache', help='Cache directory (default: cache)')
    cache_group.add_argument('--cache-ttl', type=int, default=86400, help='Cache TTL in seconds (default: 86400 = 24h)')
    cache_group.add_argument('--clear-cache', action='store_true', help='Clear cache before scanning')
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--headless', action='store_true', help='Use a headless browser for scanning (slower but more effective)')
    advanced_group.add_argument('--rate-limit', type=int, default=0, help='Requests per second limit (default: 0 = unlimited)')
    advanced_group.add_argument('--shuffle', action='store_true', help='Shuffle wordlists for better distribution')
    advanced_group.add_argument('--exclude-extensions', help='Exclude file extensions (comma-separated)')
    advanced_group.add_argument('--include-extensions', help='Include only these extensions (comma-separated)')
    advanced_group.add_argument('--min-response-size', type=int, help='Minimum response size to consider')
    advanced_group.add_argument('--max-response-size', type=int, help='Maximum response size to consider')
    
    # Debugging options
    debug_group = parser.add_argument_group('Debugging Options')
    debug_group.add_argument('--debug', action='store_true', help='Enable debug mode')
    debug_group.add_argument('--save-raw', action='store_true', help='Save raw HTTP responses')
    debug_group.add_argument('--log-file', help='Log file path')
    debug_group.add_argument('--profile', action='store_true', help='Enable performance profiling')
    
    return parser.parse_args()

def run_module_with_cache(module_name, module_func, domain, cache, logger, *args, **kwargs):
    """Run a module with caching and error handling"""
    try:
        scan_stats['current_module'] = module_name
        
        # Check cache first
        cached_result = cache.get(domain, module_name, kwargs)
        if cached_result and not kwargs.get('force_refresh', False):
            logger.info(f"Using cached results for {module_name}")
            scan_stats['modules_completed'] += 1
            return cached_result
        
        # Run the module
        result = module_func(*args, **kwargs)
        
        # Cache the result
        cache.set(domain, module_name, result, kwargs)
        
        scan_stats['modules_completed'] += 1
        return result
        
    except Exception as e:
        error_msg = f"Error in {module_name}: {str(e)}"
        logger.error(error_msg)
        scan_stats['errors'].append(error_msg)
        scan_stats['failed_requests'] += 1
        return None

def create_enhanced_progress():
    """Create enhanced progress display with multiple columns"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("•"),
        TextColumn("Elapsed: {task.elapsed:.1f}s"),
        console=console,
        transient=True
    )

def display_realtime_stats():
    """Display real-time statistics during scan"""
    stats_table = Table(title="Scan Statistics", show_header=True, header_style="bold magenta")
    stats_table.add_column("Metric", style="cyan", no_wrap=True)
    stats_table.add_column("Value", style="green")
    
    duration = time.time() - (scan_stats['start_time'] or time.time())
    success_rate = (scan_stats['successful_requests'] / max(scan_stats['total_requests'], 1)) * 100
    
    stats_table.add_row("Duration", f"{duration:.1f} seconds")
    stats_table.add_row("Total Requests", str(scan_stats['total_requests']))
    stats_table.add_row("Success Rate", f"{success_rate:.1f}%")
    stats_table.add_row("Modules Completed", f"{scan_stats['modules_completed']}/{scan_stats['total_modules']}")
    stats_table.add_row("Current Module", scan_stats['current_module'])
    stats_table.add_row("Errors", str(len(scan_stats['errors'])))
    
    return stats_table

def main():
    """Enhanced main function with advanced features"""
    # Display banner
    display_banner()
    
    # Check requirements
    if not check_requirements():
        console.print("[bold red]Error: Missing required dependencies. Please run 'pip install -r requirements.txt'[/bold red]")
        sys.exit(1)
    
    # Parse arguments
    args = parse_arguments()
    
    # Check if domain is provided
    if not args.domain:
        console.print("[bold red]Error: Target domain is required. Use -d or --domain to specify a target.[/bold red]")
        sys.exit(1)
    
    # Validate domain
    if not is_valid_domain(args.domain):
        console.print(f"[bold red]Error: '{args.domain}' is not a valid domain name.[/bold red]")
        sys.exit(1)
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    # Initialize cache system
    cache = ScanCache()
    
    # Create output directory if not exists
    output_dir = Path('results')
    output_dir.mkdir(exist_ok=True)
    
    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = output_dir / f"{args.domain.replace('.', '_')}_{timestamp}.json"
    else:
        args.output = Path(args.output)
    
    # Initialize advanced UI
    if not args.quiet:
        dashboard = RealTimeDashboard(args.domain)
        interactive_menu = InteractiveMenu()
        visualizer = SecurityVisualizer()
    
    # Initialize advanced report generator
    advanced_report_gen = AdvancedReportGenerator(args.domain)
    
    # Initialize modules
    domain_info = DomainInfo(args.domain, args.timeout, args.user_agent, args.delay, args.proxy)
    subdomain_enum = SubdomainEnumerator(args.domain, args.threads, args.timeout, args.wordlist, args.delay, args.proxy)
    url_discovery = URLDiscovery(args.domain, args.threads, args.timeout, args.wordlist, args.delay, args.proxy, args.headless)
    admin_finder = AdminFinder(args.domain, args.threads, args.timeout, args.wordlist, args.delay, args.proxy)
    attack_surface = AttackSurfaceMapper(args.domain, args.threads, args.timeout)
    vuln_scanner = VulnerabilityScanner(args.domain, args.threads, args.timeout, args.delay, args.proxy)
    report_gen = ReportGenerator(args.domain, str(args.output))
    
    # Start scan
    scan_stats['start_time'] = time.time()
    scan_start_time = datetime.now()
    
    console.print(Panel.fit(f"[bold green]Starting advanced scan on {args.domain}[/bold green]", 
                           title="Enhanced Domain Scanner", border_style="green"))
    
    # Determine which modules to run
    run_info = args.info or args.full
    run_subdomains = args.subdomains or args.full
    run_urls = args.urls or args.full
    run_admin = args.admin_finder or args.full
    run_attack = args.attack_surface or args.full
    run_vulns = args.vulns or args.full
    
    # If no specific module is selected, run basic info gathering
    if not any([run_info, run_subdomains, run_urls, run_admin, run_attack, run_vulns]):
        run_info = True
    
    # Set total modules
    scan_stats['total_modules'] = sum([run_info, run_subdomains, run_urls, run_admin, run_attack, run_vulns])
    
    # Initialize results dictionary
    results = {
        'scan_info': {
            'domain': args.domain,
            'start_time': scan_start_time.isoformat(),
            'modules': [],
            'total_modules': scan_stats['total_modules']
        },
        'results': {}
    }
    
    # Create enhanced progress display
    with create_enhanced_progress() as progress:
        # Create main progress task
        main_task = progress.add_task(
            f"[cyan]Scanning {args.domain}", 
            total=scan_stats['total_modules']
        )
        
        # Domain Information
        if run_info:
            task = progress.add_task("[green]Gathering Domain Information", total=1)
            results['results']['domain_info'] = run_module_with_cache(
                "Domain Information",
                domain_info.gather_info,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('domain_info')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
        
        # Subdomain Enumeration
        if run_subdomains:
            task = progress.add_task("[green]Enumerating Subdomains", total=1)
            results['results']['subdomains'] = run_module_with_cache(
                "Subdomain Enumeration",
                subdomain_enum.enumerate,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('subdomains')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
        
        # URL Discovery
        if run_urls:
            task = progress.add_task("[green]Discovering Hidden URLs", total=1)
            results['results']['urls'] = run_module_with_cache(
                "URL Discovery",
                url_discovery.discover,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('urls')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
        
        # Admin Finder
        if run_admin:
            task = progress.add_task("[green]Finding Admin Pages", total=1)
            results['results']['admin_pages'] = run_module_with_cache(
                "Admin Finder",
                admin_finder.find,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('admin_pages')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
        
        # Attack Surface Mapping
        if run_attack:
            task = progress.add_task("[green]Mapping Attack Surface", total=1)
            results['results']['attack_surface'] = run_module_with_cache(
                "Attack Surface Mapping",
                attack_surface.map,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('attack_surface')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
        
        # Vulnerability Scanning
        if run_vulns:
            task = progress.add_task("[green]Scanning for Vulnerabilities", total=1)
            results['results']['vulnerabilities'] = run_module_with_cache(
                "Vulnerability Scanner",
                vuln_scanner.scan,
                args.domain,
                cache,
                logger
            )
            results['scan_info']['modules'].append('vulnerabilities')
            progress.update(task, advance=1)
            progress.update(main_task, advance=1)
    
    # Calculate scan duration
    scan_end_time = datetime.now()
    duration = time.time() - scan_stats['start_time']
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    # Add scan statistics to results
    results['scan_info']['end_time'] = scan_end_time.isoformat()
    results['scan_info']['duration_seconds'] = duration
    results['scan_info']['statistics'] = {
        'total_requests': scan_stats['total_requests'],
        'successful_requests': scan_stats['successful_requests'],
        'failed_requests': scan_stats['failed_requests'],
        'errors': scan_stats['errors'],
        'success_rate': (scan_stats['successful_requests'] / max(scan_stats['total_requests'], 1)) * 100
    }
    
    # Generate enhanced reports
    try:
        # Generate JSON report
        json_file = advanced_report_gen.generate_json_report(results, args.output)
        
        # Generate HTML report
        html_file = advanced_report_gen.generate_html_report(results, args.output.with_suffix('.html'))
        
        # Generate XML report if requested
        if args.format == 'xml' or args.full:
            xml_file = advanced_report_gen.generate_xml_report(results, args.output.with_suffix('.xml'))
        
        # Generate Markdown report if requested
        if args.format == 'md' or args.full:
            md_file = advanced_report_gen.generate_markdown_report(results, args.output.with_suffix('.md'))
        
        console.print(f"[green]✓[/green] Reports generated successfully!")
        
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        console.print(f"[red]Error saving report: {e}[/red]")
    
    # Display enhanced scan summary
    summary_table = Table(title="Scan Summary", show_header=False, box=None)
    summary_table.add_column(style="bold cyan")
    summary_table.add_column(style="green")
    
    summary_table.add_row("Target:", args.domain)
    summary_table.add_row("Duration:", f"{int(hours)}h {int(minutes)}m {int(seconds)}s")
    summary_table.add_row("Modules Completed:", f"{scan_stats['modules_completed']}/{scan_stats['total_modules']}")
    summary_table.add_row("Success Rate:", f"{(scan_stats['successful_requests'] / max(scan_stats['total_requests'], 1)) * 100:.1f}%")
    summary_table.add_row("Total Requests:", str(scan_stats['total_requests']))
    summary_table.add_row("Errors:", str(len(scan_stats['errors'])))
    
    # Add security score to summary
    if 'security_score' in results:
        summary_table.add_row("Security Score:", f"{results['security_score']}/100")
    
    console.print(Panel(summary_table, title="[bold green]Scan Completed Successfully![/bold green]", 
                       border_style="green"))
    
    # Show security radar chart if UI is enabled
    if not args.quiet and 'security_metrics' in results:
        radar_panel = visualizer.create_radar_chart(results['security_metrics'])
        console.print(radar_panel)
    
    # Show any errors that occurred
    if scan_stats['errors']:
        console.print("\n[yellow]Warnings/Errors during scan:[/yellow]")
        for error in scan_stats['errors'][-5:]:  # Show last 5 errors
            console.print(f"  • {error}")
        if len(scan_stats['errors']) > 5:
            console.print(f"  ... and {len(scan_stats['errors']) - 5} more errors")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)