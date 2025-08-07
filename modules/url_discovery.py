#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from .utils import load_wordlist, get_user_agent

# Initialize console
console = Console()

class URLDiscovery:
    """Class for discovering hidden URLs in a domain"""
    
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        """Initialize the URLDiscovery class
        
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
        self.logger = logging.getLogger('domain_scanner.url_discovery')
        self.found_urls = set()
        self.crawled_urls = set()
        self.extensions = ['.php', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm', '.xml', '.json', '.txt', '.pdf', '.zip', '.tar.gz', '.sql', '.bak', '.old', '.backup']
    
    def discover(self):
        """Discover hidden URLs using multiple techniques
        
        Returns:
            list: List of discovered URLs
        """
        self.logger.info(f"Starting URL discovery for {self.domain}")
        
        # Determine if the site uses HTTP or HTTPS
        base_url = self._get_base_url()
        if not base_url:
            self.logger.error(f"Could not connect to {self.domain}")
            return []
        
        self.logger.info(f"Using base URL: {base_url}")
        
        # Add the base URL to found URLs
        self.found_urls.add(base_url)
        
        # Crawl the website to discover URLs
        self._crawl_website(base_url)
        
        # Perform directory and file brute forcing
        self._brute_force_urls(base_url)
        
        # Display results
        self._display_results()
        
        return list(self.found_urls)
    
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
    
    def _crawl_website(self, base_url):
        """Crawl the website to discover URLs"""
        self.logger.info("Crawling website for URLs")
        
        # Queue for URLs to crawl
        url_queue = queue.Queue()
        url_queue.put(base_url)
        
        with Progress() as progress:
            task = progress.add_task("[green]Crawling Website", total=None)
            
            while not url_queue.empty() and len(self.crawled_urls) < 1000:  # Limit to prevent infinite crawling
                try:
                    current_url = url_queue.get()
                    
                    # Skip if already crawled
                    if current_url in self.crawled_urls:
                        continue
                    
                    # Mark as crawled
                    self.crawled_urls.add(current_url)
                    
                    # Update progress
                    progress.update(task, description=f"[green]Crawling: {len(self.crawled_urls)} URLs")
                    
                    # Fetch the URL
                    response = self._fetch_url(current_url)
                    if not response:
                        continue
                    
                    # Extract links from the response
                    new_urls = self._extract_links(response, base_url)
                    
                    # Add new URLs to the queue
                    for url in new_urls:
                        if url not in self.crawled_urls and self._is_same_domain(url, base_url):
                            url_queue.put(url)
                            self.found_urls.add(url)
                    
                    # Add delay between requests
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.error(f"Error crawling {current_url}: {str(e)}")
                    continue
    
    def _fetch_url(self, url):
        """Fetch a URL and return the response"""
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False  # Disable SSL verification for scanning purposes
            )
            
            if response.status_code == 200:
                return response
            else:
                self.logger.debug(f"Got status code {response.status_code} for {url}")
                return None
        except Exception as e:
            self.logger.debug(f"Error fetching {url}: {str(e)}")
            return None
    
    def _extract_links(self, response, base_url):
        """Extract links from a response"""
        urls = set()
        
        try:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Skip empty links, javascript, and anchors
                if not href or href.startswith('javascript:') or href == '#':
                    continue
                
                # Convert relative URL to absolute
                absolute_url = urljoin(response.url, href)
                
                # Remove fragments
                absolute_url = absolute_url.split('#')[0]
                
                # Add to set of URLs
                urls.add(absolute_url)
            
            # Find URLs in JavaScript
            for script in soup.find_all('script'):
                if script.string:
                    # Look for URLs in JavaScript
                    for line in script.string.splitlines():
                        if 'http://' in line or 'https://' in line:
                            for word in line.split():
                                if word.startswith('http://') or word.startswith('https://'):
                                    # Clean up URL
                                    url = word.strip('"\';,()[]{}').split('#')[0]
                                    if self._is_same_domain(url, base_url):
                                        urls.add(url)
            
            # Find URLs in CSS
            for style in soup.find_all('style'):
                if style.string:
                    # Look for URLs in CSS
                    for line in style.string.splitlines():
                        if 'url(' in line:
                            for part in line.split('url('):
                                if ')' in part:
                                    url = part.split(')')[0].strip('"\'')
                                    absolute_url = urljoin(response.url, url)
                                    if self._is_same_domain(absolute_url, base_url):
                                        urls.add(absolute_url)
            
            # Find URLs in comments
            for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text):
                for word in comment.split():
                    if word.startswith('http://') or word.startswith('https://'):
                        url = word.strip('"\';,()[]{}').split('#')[0]
                        if self._is_same_domain(url, base_url):
                            urls.add(url)
            
        except Exception as e:
            self.logger.error(f"Error extracting links: {str(e)}")
        
        return urls
    
    def _is_same_domain(self, url, base_url):
        """Check if a URL belongs to the same domain"""
        try:
            url_domain = urlparse(url).netloc
            base_domain = urlparse(base_url).netloc
            
            # Check if the domain is the same or a subdomain
            return url_domain == base_domain or url_domain.endswith(f".{base_domain}")
        except Exception:
            return False
    
    def _brute_force_urls(self, base_url):
        """Perform directory and file brute forcing"""
        self.logger.info("Performing directory and file brute forcing")
        
        # Load wordlist
        wordlist = load_wordlist(self.wordlist_path)
        if not wordlist:
            self.logger.error("Failed to load wordlist")
            return
        
        self.logger.info(f"Loaded {len(wordlist)} path candidates from wordlist")
        
        # Create a queue for path candidates
        path_queue = queue.Queue()
        
        # Add directories to the queue
        for word in wordlist:
            # Add directory
            path_queue.put(f"{word}/")
            
            # Add files with different extensions
            for ext in self.extensions:
                path_queue.put(f"{word}{ext}")
        
        # Create and start worker threads
        with Progress() as progress:
            total_paths = path_queue.qsize()
            task = progress.add_task("[green]Brute Forcing URLs", total=total_paths)
            
            def worker():
                while not path_queue.empty():
                    try:
                        path = path_queue.get(block=False)
                        url = urljoin(base_url, path)
                        
                        # Check if the URL exists
                        response = self._fetch_url(url)
                        if response:
                            self.found_urls.add(url)
                        
                        progress.update(task, advance=1)
                        path_queue.task_done()
                        time.sleep(self.delay)  # Add delay between requests
                    except queue.Empty:
                        break
                    except Exception as e:
                        self.logger.debug(f"Error checking URL {url}: {str(e)}")
                        progress.update(task, advance=1)
                        path_queue.task_done()
            
            # Start worker threads
            threads = []
            for _ in range(min(self.threads, total_paths)):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Wait for all threads to complete
            for t in threads:
                t.join()
    
    def _display_results(self):
        """Display discovery results"""
        if self.found_urls:
            table = Table(title=f"Discovered URLs for {self.domain}")
            table.add_column("URL", style="cyan")
            table.add_column("Type", style="green")
            
            for url in sorted(self.found_urls):
                # Determine URL type
                if url.endswith('/'):
                    url_type = "Directory"
                elif any(url.endswith(ext) for ext in self.extensions):
                    url_type = "File"
                else:
                    url_type = "Other"
                
                table.add_row(url, url_type)
            
            console.print(table)
            console.print(f"[bold green]Total URLs discovered: {len(self.found_urls)}[/bold green]")
        else:
            console.print("[yellow]No URLs discovered[/yellow]")