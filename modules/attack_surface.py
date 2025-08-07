#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import socket
import logging
import time
import json
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from .utils import get_user_agent

# Initialize console
console = Console()

class AttackSurfaceMapper:
    """Class for mapping the attack surface of a target domain"""
    
    def __init__(self, domain, threads=10, timeout=30):
        """Initialize the AttackSurfaceMapper class
        
        Args:
            domain (str): Target domain
            threads (int): Number of threads to use
            timeout (int): Request timeout in seconds
        """
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.user_agent = get_user_agent()
        self.logger = logging.getLogger('domain_scanner.attack_surface')
        self.attack_surface = {
            'open_ports': [],
            'services': {},
            'technologies': {},
            'headers': {},
            'security_headers': {},
            'cookies': [],
            'forms': [],
            'javascript_files': [],
            'api_endpoints': [],
            'subdomains': [],
            'ip_addresses': [],
            'cdn_usage': None,
            'waf_detection': None,
            'email_addresses': [],
            'exposed_documents': []
        }
    
    def map(self):
        """Map the attack surface of the target domain
        
        Returns:
            dict: Attack surface information
        """
        self.logger.info(f"Starting attack surface mapping for {self.domain}")
        
        # Determine if the site uses HTTP or HTTPS
        base_url = self._get_base_url()
        if not base_url:
            self.logger.error(f"Could not connect to {self.domain}")
            return self.attack_surface
        
        self.logger.info(f"Using base URL: {base_url}")
        
        # Map attack surface components
        with Progress() as progress:
            # Create tasks for each component
            tasks = {}
            tasks['ports'] = progress.add_task("[green]Scanning Open Ports", total=1)
            tasks['services'] = progress.add_task("[green]Identifying Services", total=1)
            tasks['web'] = progress.add_task("[green]Analyzing Web Components", total=1)
            tasks['security'] = progress.add_task("[green]Checking Security Headers", total=1)
            tasks['content'] = progress.add_task("[green]Analyzing Content", total=1)
            
            # Scan open ports and services
            self._scan_ports_and_services()
            progress.update(tasks['ports'], advance=1)
            progress.update(tasks['services'], advance=1)
            
            # Analyze web components
            self._analyze_web_components(base_url)
            progress.update(tasks['web'], advance=1)
            
            # Check security headers
            self._check_security_headers(base_url)
            progress.update(tasks['security'], advance=1)
            
            # Analyze content for sensitive information
            self._analyze_content(base_url)
            progress.update(tasks['content'], advance=1)
        
        # Display results
        self._display_results()
        
        return self.attack_surface
    
    def _get_base_url(self):
        """Determine if the site uses HTTP or HTTPS"""
        try:
            # Try HTTPS first
            response = requests.get(
                f"https://{self.domain}",
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            return f"https://{self.domain}"
        except Exception:
            try:
                # Try HTTP if HTTPS fails
                response = requests.get(
                    f"http://{self.domain}",
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout
                )
                return f"http://{self.domain}"
            except Exception as e:
                self.logger.error(f"Error connecting to {self.domain}: {str(e)}")
                return None
    
    def _scan_ports_and_services(self):
        """Scan for open ports and identify services"""
        self.logger.info("Scanning for open ports and services")
        
        # Common ports to scan
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPC
            135,   # RPC
            139,   # NetBIOS
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            993,   # IMAPS
            995,   # POP3S
            1723,  # PPTP
            3306,  # MySQL
            3389,  # RDP
            5900,  # VNC
            8080,  # HTTP Proxy
            8443   # HTTPS Alt
        ]
        
        # Get IP addresses for the domain
        try:
            ip_addresses = socket.gethostbyname_ex(self.domain)[2]
            self.attack_surface['ip_addresses'] = ip_addresses
        except Exception as e:
            self.logger.error(f"Error resolving IP addresses: {str(e)}")
            ip_addresses = []
        
        if not ip_addresses:
            self.logger.error("No IP addresses found for the domain")
            return
        
        # Use the first IP address for port scanning
        target_ip = ip_addresses[0]
        
        # Scan ports
        open_ports = []
        services = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create a list of futures
            futures = [executor.submit(self._check_port, target_ip, port) for port in common_ports]
            
            # Process results as they complete
            for future in futures:
                result = future.result()
                if result:
                    port, service = result
                    open_ports.append(port)
                    services[port] = service
        
        # Update attack surface information
        self.attack_surface['open_ports'] = sorted(open_ports)
        self.attack_surface['services'] = services
    
    def _check_port(self, ip, port):
        """Check if a port is open and identify the service
        
        Args:
            ip (str): IP address to scan
            port (int): Port number to check
            
        Returns:
            tuple: (port, service) if open, None otherwise
        """
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Short timeout for port scanning
            
            # Try to connect to the port
            result = s.connect_ex((ip, port))
            s.close()
            
            # If the port is open
            if result == 0:
                # Try to identify the service
                service = self._identify_service(ip, port)
                return (port, service)
            
            return None
        except Exception as e:
            self.logger.debug(f"Error checking port {port}: {str(e)}")
            return None
    
    def _identify_service(self, ip, port):
        """Identify the service running on a port
        
        Args:
            ip (str): IP address
            port (int): Port number
            
        Returns:
            str: Service name or 'Unknown'
        """
        # Common port to service mapping
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        # Return known service if available
        if port in common_services:
            return common_services[port]
        
        # Try to get service banner
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            
            # Send a generic request to get a banner
            s.send(b'\r\n\r\n')
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            if banner:
                return f"Unknown ({banner[:50]}...)"
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'
    
    def _analyze_web_components(self, base_url):
        """Analyze web components of the target domain"""
        self.logger.info("Analyzing web components")
        
        try:
            # Fetch the main page
            response = requests.get(
                base_url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            
            if response.status_code == 200:
                # Extract headers
                self.attack_surface['headers'] = dict(response.headers)
                
                # Extract cookies
                cookies = response.cookies
                for cookie in cookies:
                    self.attack_surface['cookies'].append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure,
                        'expires': cookie.expires
                    })
                
                # Parse HTML content
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').upper(),
                        'inputs': []
                    }
                    
                    # Extract form inputs
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_field in inputs:
                        input_type = input_field.get('type', '')
                        input_name = input_field.get('name', '')
                        
                        if input_name:
                            form_data['inputs'].append({
                                'name': input_name,
                                'type': input_type
                            })
                    
                    self.attack_surface['forms'].append(form_data)
                
                # Extract JavaScript files
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    src = script.get('src', '')
                    if src:
                        # Convert relative URL to absolute
                        if not src.startswith(('http://', 'https://')):
                            src = urljoin(base_url, src)
                        
                        self.attack_surface['javascript_files'].append(src)
                
                # Detect technologies
                self._detect_technologies(response, soup)
                
                # Detect CDN usage
                self._detect_cdn_usage(response, soup)
                
                # Detect WAF
                self._detect_waf(response)
                
                # Extract potential API endpoints
                self._extract_api_endpoints(response.text, base_url)
        
        except Exception as e:
            self.logger.error(f"Error analyzing web components: {str(e)}")
    
    def _detect_technologies(self, response, soup):
        """Detect technologies used by the website
        
        Args:
            response (Response): HTTP response object
            soup (BeautifulSoup): Parsed HTML content
        """
        technologies = {}
        
        # Check headers for technology clues
        headers = response.headers
        
        # Server software
        if 'Server' in headers:
            technologies['Web Server'] = headers['Server']
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            technologies['Powered By'] = headers['X-Powered-By']
        
        # Content Management Systems
        html = response.text
        
        # WordPress
        if soup.select('meta[name="generator"][content*="WordPress"]') or \
           '/wp-content/' in html or '/wp-includes/' in html:
            technologies['CMS'] = 'WordPress'
        
        # Joomla
        elif soup.select('meta[name="generator"][content*="Joomla"]') or \
             '/media/jui/' in html or '/media/system/js/' in html:
            technologies['CMS'] = 'Joomla'
        
        # Drupal
        elif 'Drupal.settings' in html or '/sites/all/themes/' in html or \
             '/sites/all/modules/' in html:
            technologies['CMS'] = 'Drupal'
        
        # JavaScript frameworks
        if 'react' in html.lower() or 'reactjs' in html.lower():
            technologies['JS Framework'] = 'React'
        
        if 'angular' in html.lower():
            technologies['JS Framework'] = 'Angular'
        
        if 'vue' in html.lower() or 'vuejs' in html.lower():
            technologies['JS Framework'] = 'Vue.js'
        
        # jQuery
        if 'jquery' in html.lower():
            technologies['JS Library'] = 'jQuery'
        
        # Bootstrap
        if 'bootstrap' in html.lower():
            technologies['CSS Framework'] = 'Bootstrap'
        
        # Google Analytics
        if 'google-analytics.com' in html or 'analytics.js' in html or 'gtag' in html:
            technologies['Analytics'] = 'Google Analytics'
        
        self.attack_surface['technologies'] = technologies
    
    def _detect_cdn_usage(self, response, soup):
        """Detect CDN usage
        
        Args:
            response (Response): HTTP response object
            soup (BeautifulSoup): Parsed HTML content
        """
        # Check headers for CDN clues
        headers = response.headers
        cdn = None
        
        # Cloudflare
        if 'cf-ray' in headers or 'cloudflare' in str(headers).lower():
            cdn = 'Cloudflare'
        
        # Akamai
        elif 'x-akamai-transformed' in headers or 'akamai' in str(headers).lower():
            cdn = 'Akamai'
        
        # Fastly
        elif 'fastly' in str(headers).lower():
            cdn = 'Fastly'
        
        # Cloudfront
        elif 'cloudfront' in str(headers).lower() or 'x-amz-cf-id' in headers:
            cdn = 'AWS CloudFront'
        
        # Check for CDN URLs in content
        if not cdn:
            html = response.text.lower()
            
            if 'cloudflare.com' in html:
                cdn = 'Cloudflare'
            elif 'akamai' in html:
                cdn = 'Akamai'
            elif 'fastly.net' in html:
                cdn = 'Fastly'
            elif 'cloudfront.net' in html:
                cdn = 'AWS CloudFront'
            elif 'cdn.jsdelivr.net' in html:
                cdn = 'jsDelivr'
            elif 'cdnjs.cloudflare.com' in html:
                cdn = 'CDNJS (Cloudflare)'
            elif 'unpkg.com' in html:
                cdn = 'unpkg'
        
        self.attack_surface['cdn_usage'] = cdn
    
    def _detect_waf(self, response):
        """Detect Web Application Firewall (WAF)
        
        Args:
            response (Response): HTTP response object
        """
        # Check headers for WAF clues
        headers = response.headers
        waf = None
        
        # Cloudflare WAF
        if 'cf-ray' in headers or 'cloudflare' in str(headers).lower():
            waf = 'Cloudflare WAF'
        
        # ModSecurity
        elif 'mod_security' in str(headers).lower() or 'modsecurity' in str(headers).lower():
            waf = 'ModSecurity'
        
        # AWS WAF
        elif 'x-amzn-waf' in headers:
            waf = 'AWS WAF'
        
        # Imperva Incapsula
        elif 'incapsula' in str(headers).lower():
            waf = 'Imperva Incapsula'
        
        # Akamai
        elif 'akamai' in str(headers).lower():
            waf = 'Akamai WAF'
        
        # F5 BIG-IP ASM
        elif 'bigip' in str(headers).lower() or 'f5' in str(headers).lower():
            waf = 'F5 BIG-IP ASM'
        
        # Sucuri
        elif 'sucuri' in str(headers).lower():
            waf = 'Sucuri WAF'
        
        # Barracuda
        elif 'barracuda' in str(headers).lower():
            waf = 'Barracuda WAF'
        
        self.attack_surface['waf_detection'] = waf
    
    def _check_security_headers(self, base_url):
        """Check security headers
        
        Args:
            base_url (str): Base URL of the target domain
        """
        self.logger.info("Checking security headers")
        
        try:
            # Fetch the main page
            response = requests.get(
                base_url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'X-Frame-Options': 'Missing',
                'X-XSS-Protection': 'Missing',
                'Referrer-Policy': 'Missing',
                'Feature-Policy': 'Missing',
                'Permissions-Policy': 'Missing',
                'Public-Key-Pins': 'Missing',
                'Expect-CT': 'Missing'
            }
            
            # Check for security headers
            headers = response.headers
            for header in security_headers.keys():
                if header.lower() in [h.lower() for h in headers.keys()]:
                    for h in headers.keys():
                        if h.lower() == header.lower():
                            security_headers[header] = headers[h]
                            break
            
            self.attack_surface['security_headers'] = security_headers
        
        except Exception as e:
            self.logger.error(f"Error checking security headers: {str(e)}")
    
    def _extract_api_endpoints(self, html, base_url):
        """Extract potential API endpoints from HTML content
        
        Args:
            html (str): HTML content
            base_url (str): Base URL of the target domain
        """
        # Regular expressions for finding API endpoints
        api_patterns = [
            r'(?:https?:)?//[^"\'\s]+/api/[^"\'\s]+',  # /api/ endpoints
            r'(?:https?:)?//[^"\'\s]+/v[0-9]+/[^"\'\s]+',  # /v1/, /v2/ etc.
            r'(?:https?:)?//api\.[^"\'\s]+',  # api.domain.com
            r'(?:https?:)?//[^"\'\s]+/rest/[^"\'\s]+',  # /rest/ endpoints
            r'(?:https?:)?//[^"\'\s]+/graphql[^"\'\s]*'  # GraphQL endpoints
        ]
        
        api_endpoints = set()
        
        # Search for API endpoints
        for pattern in api_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                # Clean up the URL
                if match.startswith('//'):  # Protocol-relative URL
                    if base_url.startswith('https'):
                        match = 'https:' + match
                    else:
                        match = 'http:' + match
                elif not match.startswith(('http://', 'https://')):
                    match = urljoin(base_url, match)
                
                api_endpoints.add(match)
        
        self.attack_surface['api_endpoints'] = list(api_endpoints)
    
    def _analyze_content(self, base_url):
        """Analyze content for sensitive information
        
        Args:
            base_url (str): Base URL of the target domain
        """
        self.logger.info("Analyzing content for sensitive information")
        
        try:
            # Fetch the main page
            response = requests.get(
                base_url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            
            if response.status_code == 200:
                html = response.text
                
                # Extract email addresses
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                emails = re.findall(email_pattern, html)
                self.attack_surface['email_addresses'] = list(set(emails))
                
                # Look for exposed documents
                doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.zip', '.tar.gz', '.rar']
                doc_pattern = r'(?:https?:)?//[^"\'\s]+(?:' + '|'.join(doc_extensions) + ')'
                docs = re.findall(doc_pattern, html)
                
                # Clean up document URLs
                exposed_docs = set()
                for doc in docs:
                    # Convert to absolute URL
                    if doc.startswith('//'):  # Protocol-relative URL
                        if base_url.startswith('https'):
                            doc = 'https:' + doc
                        else:
                            doc = 'http:' + doc
                    elif not doc.startswith(('http://', 'https://')):
                        doc = urljoin(base_url, doc)
                    
                    exposed_docs.add(doc)
                
                self.attack_surface['exposed_documents'] = list(exposed_docs)
        
        except Exception as e:
            self.logger.error(f"Error analyzing content: {str(e)}")
    
    def _display_results(self):
        """Display attack surface mapping results"""
        console.print(f"\n[bold green]Attack Surface Mapping Results for {self.domain}[/bold green]")
        
        # IP Addresses
        if self.attack_surface['ip_addresses']:
            console.print("\n[bold cyan]IP Addresses:[/bold cyan]")
            for ip in self.attack_surface['ip_addresses']:
                console.print(f"  {ip}")
        
        # Open Ports and Services
        if self.attack_surface['open_ports']:
            table = Table(title="Open Ports and Services")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            
            for port in self.attack_surface['open_ports']:
                service = self.attack_surface['services'].get(port, 'Unknown')
                table.add_row(str(port), service)
            
            console.print(table)
        
        # Technologies
        if self.attack_surface['technologies']:
            table = Table(title="Detected Technologies")
            table.add_column("Category", style="cyan")
            table.add_column("Technology", style="green")
            
            for category, technology in self.attack_surface['technologies'].items():
                table.add_row(category, technology)
            
            console.print(table)
        
        # CDN and WAF
        cdn = self.attack_surface['cdn_usage']
        waf = self.attack_surface['waf_detection']
        
        if cdn or waf:
            table = Table(title="CDN and WAF Detection")
            table.add_column("Type", style="cyan")
            table.add_column("Detected", style="green")
            
            if cdn:
                table.add_row("CDN", cdn)
            else:
                table.add_row("CDN", "Not Detected")
            
            if waf:
                table.add_row("WAF", waf)
            else:
                table.add_row("WAF", "Not Detected")
            
            console.print(table)
        
        # Security Headers
        if self.attack_surface['security_headers']:
            table = Table(title="Security Headers")
            table.add_column("Header", style="cyan")
            table.add_column("Value", style="green")
            
            for header, value in self.attack_surface['security_headers'].items():
                if value == 'Missing':
                    table.add_row(header, "[red]Missing[/red]")
                else:
                    table.add_row(header, value)
            
            console.print(table)
        
        # Forms
        if self.attack_surface['forms']:
            console.print("\n[bold cyan]Detected Forms:[/bold cyan]")
            for i, form in enumerate(self.attack_surface['forms'], 1):
                console.print(f"  Form #{i}:")
                console.print(f"    Action: {form['action']}")
                console.print(f"    Method: {form['method']}")
                console.print("    Inputs:")
                for input_field in form['inputs']:
                    console.print(f"      - {input_field['name']} ({input_field['type']})")
        
        # API Endpoints
        if self.attack_surface['api_endpoints']:
            console.print("\n[bold cyan]Potential API Endpoints:[/bold cyan]")
            for endpoint in self.attack_surface['api_endpoints']:
                console.print(f"  {endpoint}")
        
        # Email Addresses
        if self.attack_surface['email_addresses']:
            console.print("\n[bold cyan]Discovered Email Addresses:[/bold cyan]")
            for email in self.attack_surface['email_addresses']:
                console.print(f"  {email}")
        
        # Exposed Documents
        if self.attack_surface['exposed_documents']:
            console.print("\n[bold cyan]Exposed Documents:[/bold cyan]")
            for doc in self.attack_surface['exposed_documents']:
                console.print(f"  {doc}")