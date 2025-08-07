#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import requests
import logging
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from .utils import load_wordlist, get_user_agent

# Initialize console
console = Console()

class SubdomainEnumerator:
    """Class for enumerating subdomains of a target domain"""
    
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        """Initialize the SubdomainEnumerator class
        
        Args:
            domain (str): Target domain
            threads (int): Number of threads to use
            timeout (int): Request timeout in seconds
            wordlist (str): Path to custom wordlist file
            delay (float): Delay between requests in seconds
        """
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist_path = wordlist
        self.delay = delay
        self.user_agent = get_user_agent()
        self.logger = logging.getLogger('domain_scanner.subdomain_enum')
        self.found_subdomains = set()
        self.resolvers = self._get_resolvers()
    
    def enumerate(self):
        """Enumerate subdomains using multiple techniques
        
        Returns:
            list: List of discovered subdomains
        """
        self.logger.info(f"Starting subdomain enumeration for {self.domain}")
        
        # Load wordlist
        wordlist = load_wordlist(self.wordlist_path)
        if not wordlist:
            self.logger.error("Failed to load wordlist")
            return []
        
        self.logger.info(f"Loaded {len(wordlist)} subdomain candidates from wordlist")
        
        # Passive enumeration techniques
        self._passive_enumeration()
        
        # Active enumeration using DNS
        self._dns_enumeration(wordlist)
        
        # Display results
        self._display_results()
        
        return list(self.found_subdomains)
    
    def _get_resolvers(self):
        """Get a list of public DNS resolvers"""
        resolvers = [
            '8.8.8.8',        # Google
            '8.8.4.4',        # Google
            '1.1.1.1',        # Cloudflare
            '1.0.0.1',        # Cloudflare
            '9.9.9.9',        # Quad9
            '149.112.112.112', # Quad9
            '208.67.222.222', # OpenDNS
            '208.67.220.220'  # OpenDNS
        ]
        return resolvers
    
    def _passive_enumeration(self):
        """Perform passive subdomain enumeration using various sources"""
        self.logger.info("Performing passive subdomain enumeration")
        
        # Sources for passive enumeration
        sources = [
            self._enum_crtsh,
            self._enum_virustotal,
            self._enum_alienvault,
            self._enum_threatcrowd,
            self._enum_hackertarget
        ]
        
        with Progress() as progress:
            task = progress.add_task("[green]Passive Enumeration", total=len(sources))
            
            for source_func in sources:
                try:
                    source_func()
                    time.sleep(self.delay)  # Respect rate limits
                except Exception as e:
                    self.logger.error(f"Error in passive enumeration source: {str(e)}")
                
                progress.update(task, advance=1)
    
    def _enum_crtsh(self):
        """Enumerate subdomains using crt.sh certificate search"""
        try:
            self.logger.debug("Enumerating subdomains from crt.sh")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        domain = entry.get('name_value', '').lower()
                        # Split by newlines and process each domain
                        for d in domain.split('\n'):
                            if d.endswith(f'.{self.domain}') or d == self.domain:
                                self.found_subdomains.add(d)
                except Exception as e:
                    self.logger.error(f"Error parsing crt.sh response: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {str(e)}")
    
    def _enum_virustotal(self):
        """Enumerate subdomains using VirusTotal"""
        try:
            self.logger.debug("Enumerating subdomains from VirusTotal")
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for item in data.get('data', []):
                        subdomain = item.get('id', '').lower()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            self.found_subdomains.add(subdomain)
                except Exception as e:
                    self.logger.error(f"Error parsing VirusTotal response: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {str(e)}")
    
    def _enum_alienvault(self):
        """Enumerate subdomains using AlienVault OTX"""
        try:
            self.logger.debug("Enumerating subdomains from AlienVault OTX")
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '').lower()
                        if hostname.endswith(f'.{self.domain}') or hostname == self.domain:
                            self.found_subdomains.add(hostname)
                except Exception as e:
                    self.logger.error(f"Error parsing AlienVault response: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error querying AlienVault: {str(e)}")
    
    def _enum_threatcrowd(self):
        """Enumerate subdomains using ThreatCrowd"""
        try:
            self.logger.debug("Enumerating subdomains from ThreatCrowd")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for subdomain in data.get('subdomains', []):
                        subdomain = subdomain.lower()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            self.found_subdomains.add(subdomain)
                except Exception as e:
                    self.logger.error(f"Error parsing ThreatCrowd response: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error querying ThreatCrowd: {str(e)}")
    
    def _enum_hackertarget(self):
        """Enumerate subdomains using HackerTarget"""
        try:
            self.logger.debug("Enumerating subdomains from HackerTarget")
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200 and not response.text.startswith('error'):
                for line in response.text.splitlines():
                    if ',' in line:
                        subdomain = line.split(',')[0].lower()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            self.found_subdomains.add(subdomain)
        except Exception as e:
            self.logger.error(f"Error querying HackerTarget: {str(e)}")
    
    def _dns_enumeration(self, wordlist):
        """Perform active subdomain enumeration using DNS"""
        self.logger.info("Performing active DNS subdomain enumeration")
        
        # Create a queue for subdomain candidates
        subdomain_queue = queue.Queue()
        
        # Add all candidates to the queue
        for word in wordlist:
            subdomain = f"{word}.{self.domain}"
            subdomain_queue.put(subdomain)
        
        # Create and start worker threads
        with Progress() as progress:
            task = progress.add_task("[green]DNS Enumeration", total=len(wordlist))
            
            def worker():
                while not subdomain_queue.empty():
                    try:
                        subdomain = subdomain_queue.get(block=False)
                        if self._is_valid_subdomain(subdomain):
                            self.found_subdomains.add(subdomain)
                        progress.update(task, advance=1)
                        subdomain_queue.task_done()
                        time.sleep(self.delay)  # Add delay between requests
                    except queue.Empty:
                        break
                    except Exception as e:
                        self.logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
                        progress.update(task, advance=1)
                        subdomain_queue.task_done()
            
            # Start worker threads
            threads = []
            for _ in range(min(self.threads, len(wordlist))):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Wait for all threads to complete
            for t in threads:
                t.join()
    
    def _is_valid_subdomain(self, subdomain):
        """Check if a subdomain exists by resolving it
        
        Args:
            subdomain (str): Subdomain to check
            
        Returns:
            bool: True if subdomain exists, False otherwise
        """
        try:
            # Try to resolve the subdomain using multiple resolvers
            for resolver_ip in self.resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    
                    # Try to resolve A record
                    resolver.resolve(subdomain, 'A')
                    return True
                except dns.resolver.NXDOMAIN:
                    continue  # Domain doesn't exist, try next resolver
                except dns.resolver.NoAnswer:
                    return True  # Domain exists but no A record
                except dns.resolver.NoNameservers:
                    return True  # Domain exists but nameserver refused
                except Exception:
                    continue  # Other error, try next resolver
            
            # If all resolvers failed, try HTTP request as a last resort
            try:
                requests.get(f"http://{subdomain}", timeout=self.timeout, headers={'User-Agent': self.user_agent})
                return True
            except requests.exceptions.ConnectionError:
                try:
                    requests.get(f"https://{subdomain}", timeout=self.timeout, headers={'User-Agent': self.user_agent}, verify=False)
                    return True
                except:
                    pass
            except:
                pass
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
            return False
    
    def _display_results(self):
        """Display enumeration results"""
        if self.found_subdomains:
            table = Table(title=f"Discovered Subdomains for {self.domain}")
            table.add_column("Subdomain", style="cyan")
            
            for subdomain in sorted(self.found_subdomains):
                table.add_row(subdomain)
            
            console.print(table)
            console.print(f"[bold green]Total subdomains discovered: {len(self.found_subdomains)}[/bold green]")
        else:
            console.print("[yellow]No subdomains discovered[/yellow]")