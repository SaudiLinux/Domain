#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import whois
import dns.resolver
import requests
import logging
import time
import json
from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

from .utils import get_user_agent

# Initialize console
console = Console()

class DomainInfo:
    """Class for gathering basic information about a domain"""
    
    def __init__(self, domain, timeout=30, user_agent=None):
        """Initialize the DomainInfo class
        
        Args:
            domain (str): Target domain
            timeout (int): Request timeout in seconds
            user_agent (str): Custom user agent string
        """
        self.domain = domain
        self.timeout = timeout
        self.user_agent = get_user_agent(user_agent)
        self.logger = logging.getLogger('domain_scanner.info_gatherer')
        
    def gather_info(self):
        """Gather comprehensive information about the domain
        
        Returns:
            dict: Dictionary containing domain information
        """
        self.logger.info(f"Gathering information for domain: {self.domain}")
        
        # Initialize results dictionary
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip_addresses': [],
            'whois': {},
            'dns_records': {},
            'http_headers': {},
            'technologies': [],
            'ssl_info': {}
        }
        
        # Get IP addresses
        results['ip_addresses'] = self._get_ip_addresses()
        
        # Get WHOIS information
        results['whois'] = self._get_whois_info()
        
        # Get DNS records
        results['dns_records'] = self._get_dns_records()
        
        # Get HTTP headers
        results['http_headers'] = self._get_http_headers()
        
        # Get website technologies
        results['technologies'] = self._detect_technologies()
        
        # Get SSL certificate information
        results['ssl_info'] = self._get_ssl_info()
        
        # Display results
        self._display_results(results)
        
        return results
    
    def _get_ip_addresses(self):
        """Get IP addresses for the domain"""
        try:
            self.logger.debug(f"Resolving IP addresses for {self.domain}")
            ips = socket.gethostbyname_ex(self.domain)
            return ips[2] if len(ips) > 2 else []
        except Exception as e:
            self.logger.error(f"Error resolving IP addresses: {str(e)}")
            return []
    
    def _get_whois_info(self):
        """Get WHOIS information for the domain"""
        try:
            self.logger.debug(f"Getting WHOIS information for {self.domain}")
            w = whois.whois(self.domain)
            
            # Extract relevant WHOIS information
            whois_info = {
                'registrar': w.registrar,
                'creation_date': w.creation_date.strftime("%Y-%m-%d") if isinstance(w.creation_date, datetime) else str(w.creation_date),
                'expiration_date': w.expiration_date.strftime("%Y-%m-%d") if isinstance(w.expiration_date, datetime) else str(w.expiration_date),
                'updated_date': w.updated_date.strftime("%Y-%m-%d") if isinstance(w.updated_date, datetime) else str(w.updated_date),
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else 'Unknown'
            }
            
            return whois_info
        except Exception as e:
            self.logger.error(f"Error getting WHOIS information: {str(e)}")
            return {
                'error': str(e)
            }
    
    def _get_dns_records(self):
        """Get DNS records for the domain"""
        dns_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        records = {}
        
        for record_type in dns_types:
            try:
                self.logger.debug(f"Getting {record_type} records for {self.domain}")
                answers = dns.resolver.resolve(self.domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception as e:
                self.logger.debug(f"No {record_type} records found or error: {str(e)}")
                records[record_type] = []
        
        return records
    
    def _get_http_headers(self):
        """Get HTTP headers from the domain"""
        headers = {}
        
        try:
            self.logger.debug(f"Getting HTTP headers for {self.domain}")
            response = requests.get(
                f"http://{self.domain}", 
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                allow_redirects=True
            )
            headers = dict(response.headers)
        except Exception as e:
            self.logger.error(f"Error getting HTTP headers: {str(e)}")
        
        # Try HTTPS if HTTP failed
        if not headers:
            try:
                response = requests.get(
                    f"https://{self.domain}", 
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False  # Disable SSL verification for scanning purposes
                )
                headers = dict(response.headers)
            except Exception as e:
                self.logger.error(f"Error getting HTTPS headers: {str(e)}")
        
        return headers
    
    def _detect_technologies(self):
        """Detect technologies used by the website"""
        technologies = []
        
        try:
            self.logger.debug(f"Detecting technologies for {self.domain}")
            response = requests.get(
                f"https://{self.domain}",
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            
            # Check status code
            if response.status_code != 200:
                response = requests.get(
                    f"http://{self.domain}",
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout
                )
            
            if response.status_code == 200:
                # Check headers for technology clues
                headers = response.headers
                
                # Server software
                if 'Server' in headers:
                    technologies.append(f"Server: {headers['Server']}")
                
                # X-Powered-By
                if 'X-Powered-By' in headers:
                    technologies.append(f"Powered By: {headers['X-Powered-By']}")
                
                # Content Management Systems
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')
                
                # WordPress
                if soup.select('meta[name="generator"][content*="WordPress"]') or \
                   '/wp-content/' in html or '/wp-includes/' in html:
                    technologies.append("CMS: WordPress")
                
                # Joomla
                elif soup.select('meta[name="generator"][content*="Joomla"]') or \
                     '/media/jui/' in html or '/media/system/js/' in html:
                    technologies.append("CMS: Joomla")
                
                # Drupal
                elif 'Drupal.settings' in html or '/sites/all/themes/' in html or \
                     '/sites/all/modules/' in html:
                    technologies.append("CMS: Drupal")
                
                # JavaScript frameworks
                if 'react' in html.lower() or 'reactjs' in html.lower():
                    technologies.append("Framework: React")
                
                if 'angular' in html.lower():
                    technologies.append("Framework: Angular")
                
                if 'vue' in html.lower() or 'vuejs' in html.lower():
                    technologies.append("Framework: Vue.js")
                
                # jQuery
                if 'jquery' in html.lower():
                    technologies.append("Library: jQuery")
                
                # Bootstrap
                if 'bootstrap' in html.lower():
                    technologies.append("Framework: Bootstrap")
                
                # Google Analytics
                if 'google-analytics.com' in html or 'analytics.js' in html or 'gtag' in html:
                    technologies.append("Analytics: Google Analytics")
                
        except Exception as e:
            self.logger.error(f"Error detecting technologies: {str(e)}")
        
        return technologies
    
    def _get_ssl_info(self):
        """Get SSL certificate information"""
        ssl_info = {}
        
        try:
            self.logger.debug(f"Getting SSL information for {self.domain}")
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    ssl_info = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subjectAltName': [x[1] for x in cert['subjectAltName']]
                    }
        except Exception as e:
            self.logger.debug(f"Error getting SSL information: {str(e)}")
            ssl_info = {'error': 'No SSL certificate found or connection error'}
        
        return ssl_info
    
    def _display_results(self, results):
        """Display gathered information in a formatted table"""
        # Domain and IP information
        console.print(f"\n[bold green]Domain Information for {results['domain']}[/bold green]")
        
        # IP Addresses
        ip_table = Table(title="IP Addresses")
        ip_table.add_column("IP Address", style="cyan")
        
        for ip in results['ip_addresses']:
            ip_table.add_row(ip)
        
        console.print(ip_table)
        
        # WHOIS Information
        whois_table = Table(title="WHOIS Information")
        whois_table.add_column("Field", style="cyan")
        whois_table.add_column("Value", style="green")
        
        for key, value in results['whois'].items():
            if isinstance(value, list):
                whois_table.add_row(key.replace('_', ' ').title(), "\n".join(value) if value else "N/A")
            else:
                whois_table.add_row(key.replace('_', ' ').title(), str(value) if value else "N/A")
        
        console.print(whois_table)
        
        # DNS Records
        dns_table = Table(title="DNS Records")
        dns_table.add_column("Record Type", style="cyan")
        dns_table.add_column("Value", style="green")
        
        for record_type, records in results['dns_records'].items():
            if records:
                dns_table.add_row(record_type, "\n".join(records))
            else:
                dns_table.add_row(record_type, "No records found")
        
        console.print(dns_table)
        
        # HTTP Headers
        if results['http_headers']:
            headers_table = Table(title="HTTP Headers")
            headers_table.add_column("Header", style="cyan")
            headers_table.add_column("Value", style="green")
            
            for header, value in results['http_headers'].items():
                headers_table.add_row(header, str(value))
            
            console.print(headers_table)
        
        # Technologies
        if results['technologies']:
            tech_table = Table(title="Detected Technologies")
            tech_table.add_column("Technology", style="green")
            
            for tech in results['technologies']:
                tech_table.add_row(tech)
            
            console.print(tech_table)
        
        # SSL Information
        if 'error' not in results['ssl_info']:
            ssl_table = Table(title="SSL Certificate Information")
            ssl_table.add_column("Field", style="cyan")
            ssl_table.add_column("Value", style="green")
            
            # Issuer
            issuer = results['ssl_info'].get('issuer', {})
            issuer_str = ", ".join([f"{k}={v}" for k, v in issuer.items()]) if issuer else "N/A"
            ssl_table.add_row("Issuer", issuer_str)
            
            # Subject
            subject = results['ssl_info'].get('subject', {})
            subject_str = ", ".join([f"{k}={v}" for k, v in subject.items()]) if subject else "N/A"
            ssl_table.add_row("Subject", subject_str)
            
            # Validity
            ssl_table.add_row("Valid From", results['ssl_info'].get('not_before', 'N/A'))
            ssl_table.add_row("Valid Until", results['ssl_info'].get('not_after', 'N/A'))
            
            # Alternative Names
            alt_names = results['ssl_info'].get('subjectAltName', [])
            ssl_table.add_row("Alternative Names", "\n".join(alt_names) if alt_names else "N/A")
            
            console.print(ssl_table)