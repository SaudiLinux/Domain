#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Domain - Advanced Domain Reconnaissance Tool
Author: SayerLinux
Email: SayerLinux@gmail.com
'''

import os
import sys
import argparse
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich import print as rprint

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

# Initialize console
console = Console()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Domain - Advanced Domain Reconnaissance Tool')
    
    # Main arguments
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--full', action='store_true', help='Run all scan modules')
    
    # Module selection
    parser.add_argument('--info', action='store_true', help='Gather basic domain information')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains')
    parser.add_argument('--urls', action='store_true', help='Discover hidden URLs')
    parser.add_argument('--admin-finder', action='store_true', help='Find admin pages')
    parser.add_argument('--attack-surface', action='store_true', help='Map attack surface')
    parser.add_argument('--vulns', action='store_true', help='Scan for vulnerabilities')
    
    # Advanced options
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--wordlist', help='Custom wordlist for brute forcing')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests in seconds')
    
    return parser.parse_args()

def main():
    """Main function"""
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
    
    # Create output directory if not exists
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join(output_dir, f"{args.domain.replace('.', '_')}_{timestamp}.txt")
    
    # Initialize modules
    domain_info = DomainInfo(args.domain, args.timeout, args.user_agent)
    subdomain_enum = SubdomainEnumerator(args.domain, args.threads, args.timeout, args.wordlist, args.delay)
    url_discovery = URLDiscovery(args.domain, args.threads, args.timeout, args.wordlist, args.delay)
    admin_finder = AdminFinder(args.domain, args.threads, args.timeout, args.wordlist, args.delay)
    attack_surface = AttackSurfaceMapper(args.domain, args.threads, args.timeout)
    vuln_scanner = VulnerabilityScanner(args.domain, args.threads, args.timeout)
    report_gen = ReportGenerator(args.domain, args.output)
    
    # Start scan
    start_time = time.time()
    console.print(Panel.fit(f"[bold green]Starting scan on {args.domain}[/bold green]", 
                           title="Domain Scanner", border_style="green"))
    
    # Run selected modules
    results = {}
    
    with Progress() as progress:
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
        
        # Create progress tasks
        total_tasks = sum([run_info, run_subdomains, run_urls, run_admin, run_attack, run_vulns])
        overall_progress = progress.add_task("[cyan]Overall Progress", total=total_tasks)
        current_task = None
        
        # Domain Information
        if run_info:
            current_task = progress.add_task("[green]Gathering Domain Information", total=1)
            results['domain_info'] = domain_info.gather_info()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
        
        # Subdomain Enumeration
        if run_subdomains:
            current_task = progress.add_task("[green]Enumerating Subdomains", total=1)
            results['subdomains'] = subdomain_enum.enumerate()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
        
        # URL Discovery
        if run_urls:
            current_task = progress.add_task("[green]Discovering Hidden URLs", total=1)
            results['urls'] = url_discovery.discover()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
        
        # Admin Finder
        if run_admin:
            current_task = progress.add_task("[green]Finding Admin Pages", total=1)
            results['admin_pages'] = admin_finder.find()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
        
        # Attack Surface Mapping
        if run_attack:
            current_task = progress.add_task("[green]Mapping Attack Surface", total=1)
            results['attack_surface'] = attack_surface.map()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
        
        # Vulnerability Scanning
        if run_vulns:
            current_task = progress.add_task("[green]Scanning for Vulnerabilities", total=1)
            results['vulnerabilities'] = vuln_scanner.scan()
            progress.update(current_task, advance=1)
            progress.update(overall_progress, advance=1)
    
    # Generate report
    report_gen.generate(results)
    
    # Calculate scan duration
    duration = time.time() - start_time
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    # Display scan summary
    console.print(Panel.fit(
        f"[bold green]Scan Completed![/bold green]\n\n"
        f"Target: [bold]{args.domain}[/bold]\n"
        f"Duration: {int(hours)}h {int(minutes)}m {int(seconds)}s\n"
        f"Results saved to: [bold]{args.output}[/bold]",
        title="Scan Summary", border_style="green"
    ))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)