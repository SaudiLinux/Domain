#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import time
import threading
import queue
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from .utils import load_wordlist, get_user_agent

# Initialize console
console = Console()

class AdminFinder:
    """Class for finding admin pages of a target domain"""
    
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        """Initialize the AdminFinder class
        
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
        self.logger = logging.getLogger('domain_scanner.admin_finder')
        self.found_pages = []
    
    def find(self):
        """Find admin pages using brute force
        
        Returns:
            list: List of discovered admin pages
        """
        self.logger.info(f"Starting admin page finder for {self.domain}")
        
        # Determine if the site uses HTTP or HTTPS
        base_url = self._get_base_url()
        if not base_url:
            self.logger.error(f"Could not connect to {self.domain}")
            return []
        
        self.logger.info(f"Using base URL: {base_url}")
        
        # Load admin page wordlist
        wordlist = self._load_admin_wordlist()
        if not wordlist:
            self.logger.error("Failed to load admin page wordlist")
            return []
        
        self.logger.info(f"Loaded {len(wordlist)} admin page candidates from wordlist")
        
        # Brute force admin pages
        self._brute_force_admin_pages(base_url, wordlist)
        
        # Display results
        self._display_results()
        
        return self.found_pages
    
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
    
    def _load_admin_wordlist(self):
        """Load admin page wordlist"""
        # Use custom wordlist if provided, otherwise use default
        wordlist = load_wordlist(self.wordlist_path)
        
        # If no wordlist is loaded, use a built-in list of common admin paths
        if not wordlist:
            wordlist = [
                'admin/', 'administrator/', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
                'admincp/', 'admincp.php', 'admincp.asp', 'admincp.aspx', 'admin/login.php',
                'admin/login.html', 'admin/login.asp', 'admin/login.aspx', 'admin-login.php',
                'administrator/index.php', 'administrator/index.html', 'administrator/index.asp',
                'administrator/login.php', 'administrator/login.html', 'administrator/login.asp',
                'admin1/', 'admin2/', 'admin_panel/', 'adm/', 'login.php', 'login.asp', 'login.aspx',
                'login.html', 'login/', 'login/admin.php', 'login/admin.asp', 'login/admin.html',
                'wp-admin/', 'wp-login.php', 'panel/', 'panel.php', 'panel.html', 'panel.asp',
                'cp/', 'cp.php', 'cp.html', 'cp.asp', 'cpanel/', 'cpanel.php', 'cpanel.html',
                'dashboard/', 'dashboard.php', 'dashboard.html', 'dashboard.asp', 'control/',
                'control.php', 'control.html', 'control.asp', 'member/', 'member.php', 'member.html',
                'manage/', 'manage.php', 'manage.html', 'manage.asp', 'management/',
                'management.php', 'management.html', 'management.asp', 'signin/', 'signin.php',
                'signin.html', 'signin.asp', 'sign-in/', 'sign-in.php', 'sign-in.html', 'sign-in.asp',
                'users/', 'users.php', 'users.html', 'users.asp', 'acct_login/', 'account/',
                'account.php', 'account.html', 'account.asp', 'accounts/', 'accounts.php',
                'accounts.html', 'accounts.asp', 'wp/', 'blog/wp-login.php', 'admin/cp.php',
                'admin/cp.html', 'admin/cp.asp', 'cms/', 'cms.php', 'cms.html', 'cms.asp',
                'adm.php', 'adm.html', 'adm.asp', 'adm/index.php', 'adm/index.html', 'adm/index.asp',
                'login-redirect/', 'admin/admin-login.php', 'admin/admin-login.html',
                'administrator/', 'moderator/', 'moderator.php', 'moderator.html', 'moderator.asp',
                'controlpanel/', 'controlpanel.php', 'controlpanel.html', 'controlpanel.asp',
                'admin1.php', 'admin1.html', 'admin1.asp', 'admin2.php', 'admin2.html', 'admin2.asp',
                'admin/account.php', 'admin/account.html', 'admin/account.asp', 'admin/index/',
                'admin/index.php', 'admin/index.html', 'admin/index.asp', 'admin/admin/',
                'admin/admin.php', 'admin/admin.html', 'admin/admin.asp', 'admin_area/',
                'admin_area.php', 'admin_area.html', 'admin_area.asp', 'siteadmin/',
                'siteadmin.php', 'siteadmin.html', 'siteadmin.asp', 'adminarea/',
                'adminarea.php', 'adminarea.html', 'adminarea.asp', 'bb-admin/',
                'bb-admin/index.php', 'bb-admin/index.html', 'bb-admin/index.asp',
                'bb-admin/login.php', 'bb-admin/login.html', 'bb-admin/login.asp',
                'admin-login/', 'admin-login.php', 'admin-login.html', 'admin-login.asp',
                'modelsearch/login.php', 'moderator/login.php', 'moderator/login.html',
                'moderator/login.asp', 'moderator/admin.php', 'moderator/admin.html',
                'moderator/admin.asp', 'account.php', 'account.html', 'account.asp',
                'pages/admin/admin-login.php', 'pages/admin/admin-login.html',
                'pages/admin/admin-login.asp', 'admin/admin_login.php', 'admin/admin_login.html',
                'admin/admin_login.asp', 'admin_login.php', 'admin_login.html', 'admin_login.asp',
                'panel-administracion/', 'panel-administracion/index.php',
                'panel-administracion/index.html', 'panel-administracion/index.asp',
                'panel-administracion/login.php', 'panel-administracion/login.html',
                'panel-administracion/login.asp', 'modelsearch/index.php', 'modelsearch/index.html',
                'modelsearch/index.asp', 'modelsearch/admin.php', 'modelsearch/admin.html',
                'modelsearch/admin.asp', 'admincontrol/', 'admincontrol.php', 'admincontrol.html',
                'admincontrol.asp', 'adminpanel/', 'adminpanel.php', 'adminpanel.html',
                'adminpanel.asp', 'admin1.asp', 'admin2.asp', 'yonetim.php', 'yonetim.html',
                'yonetim.asp', 'yonetici.php', 'yonetici.html', 'yonetici.asp', 'phpmyadmin/',
                'myadmin/', 'ur-admin/', 'ur-admin.php', 'ur-admin.html', 'ur-admin.asp',
                'Server.php', 'Server.html', 'Server.asp', 'wp-admin/admin-ajax.php',
                'administrator/admin.php', 'administrator/admin.html', 'administrator/admin.asp',
                'joomla/administrator', 'joomla/administrator/index.php',
                'joomla/administrator/index.html', 'joomla/administrator/index.asp',
                'admin/admin.asp', 'admin.asp', 'admin/home.asp', 'admin/controlpanel.asp',
                'sysadmin.php', 'sysadmin.html', 'sysadmin.asp', 'sysadmin/', 'sys-admin/',
                'typo3/', 'pma/', 'phpMyAdmin/', 'db/', 'dbadmin/', 'mysql/', 'myadmin/',
                'sqlmanager/', 'mysqlmanager/', 'p/m/a/', 'phpmanager/', 'php-myadmin/',
                'phpmy-admin/', 'sqlweb/', 'websql/', 'webdb/', 'mysqladmin/', 'mysql-admin/',
                'phpmyadmin2/', 'phpMyAdmin2/', 'phpMyAdmin-2/', 'php-my-admin/', 'phpMyAdmin-2.2.3/',
                'phpMyAdmin-2.2.6/', 'phpMyAdmin-2.5.1/', 'phpMyAdmin-2.5.4/', 'phpMyAdmin-2.5.5/',
                'phpMyAdmin-2.5.5-pl1/', 'phpMyAdmin-2.5.6/', 'phpMyAdmin-2.6.0-pl1/',
                'phpMyAdmin-2.6.0-pl2/', 'phpMyAdmin-2.6.0-pl3/', 'phpMyAdmin-2.6.0/',
                'phpMyAdmin-2.6.1-pl1/', 'phpMyAdmin-2.6.1-pl2/', 'phpMyAdmin-2.6.1-pl3/',
                'phpMyAdmin-2.6.1/', 'phpMyAdmin-2.6.2-pl1/', 'phpMyAdmin-2.6.2-beta1/',
                'phpMyAdmin-2.6.2/', 'phpMyAdmin-2.6.3-pl1/', 'phpMyAdmin-2.6.3/',
                'phpMyAdmin-2.6.4-pl1/', 'phpMyAdmin-2.6.4-pl2/', 'phpMyAdmin-2.6.4-pl3/',
                'phpMyAdmin-2.6.4-pl4/', 'phpMyAdmin-2.6.4/', 'phpMyAdmin-2.7.0-beta1/',
                'phpMyAdmin-2.7.0-pl1/', 'phpMyAdmin-2.7.0-pl2/', 'phpMyAdmin-2.7.0/',
                'phpMyAdmin-2.8.0-beta1/', 'phpMyAdmin-2.8.0-rc1/', 'phpMyAdmin-2.8.0-rc2/',
                'phpMyAdmin-2.8.0/', 'phpMyAdmin-2.8.1-rc1/', 'phpMyAdmin-2.8.1/', 'phpMyAdmin-2.8.2/',
                'sqlmanager/', 'mysqlmanager/', 'php-myadmin/', 'phpmy-admin/', 'webadmin/',
                'webadmin.php', 'webadmin.html', 'webadmin.asp', 'webadmin/index.php',
                'webadmin/index.html', 'webadmin/index.asp', 'webadmin/admin.php',
                'webadmin/admin.html', 'webadmin/admin.asp', 'admin/webadmin.php',
                'admin/webadmin.html', 'admin/webadmin.asp', 'admin/webadmin/',
                'admin/adminweb/', 'adminweb/', 'adminweb.php', 'adminweb.html', 'adminweb.asp',
                'adminweb/index.php', 'adminweb/index.html', 'adminweb/index.asp',
                'admin/controlpanel.php', 'admin/controlpanel.html', 'admin/controlpanel.asp',
                'admin/cp/', 'admin/cp.php', 'admin/cp.html', 'admin/cp.asp', 'admin/admin_cp.php',
                'admin/admin_cp.html', 'admin/admin_cp.asp'
            ]
        
        return wordlist
    
    def _brute_force_admin_pages(self, base_url, wordlist):
        """Brute force admin pages"""
        self.logger.info("Brute forcing admin pages")
        
        # Create a queue for admin page candidates
        admin_queue = queue.Queue()
        
        # Add all candidates to the queue
        for path in wordlist:
            admin_queue.put(path)
        
        # Create and start worker threads
        with Progress() as progress:
            task = progress.add_task("[green]Finding Admin Pages", total=len(wordlist))
            
            def worker():
                while not admin_queue.empty():
                    try:
                        path = admin_queue.get(block=False)
                        url = urljoin(base_url, path)
                        
                        # Check if the admin page exists
                        result = self._check_admin_page(url)
                        if result:
                            self.found_pages.append(result)
                        
                        progress.update(task, advance=1)
                        admin_queue.task_done()
                        time.sleep(self.delay)  # Add delay between requests
                    except queue.Empty:
                        break
                    except Exception as e:
                        self.logger.debug(f"Error checking admin page {url}: {str(e)}")
                        progress.update(task, advance=1)
                        admin_queue.task_done()
            
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
    
    def _check_admin_page(self, url):
        """Check if an admin page exists
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: Admin page information if found, None otherwise
        """
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False,  # Disable SSL verification for scanning purposes
                allow_redirects=True
            )
            
            # Check if the page exists (status code 200, 401, or 403)
            if response.status_code in [200, 401, 403]:
                # Check if it's likely an admin page
                if self._is_admin_page(response):
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'page_title': self._extract_title(response),
                        'content_length': len(response.content)
                    }
            
            return None
        except Exception as e:
            self.logger.debug(f"Error checking admin page {url}: {str(e)}")
            return None
    
    def _is_admin_page(self, response):
        """Check if a page is likely an admin page
        
        Args:
            response (Response): HTTP response object
            
        Returns:
            bool: True if likely an admin page, False otherwise
        """
        # Check status code
        if response.status_code in [401, 403]:
            return True
        
        # Check for login forms or admin keywords in content
        content_lower = response.text.lower()
        
        # Check for login form
        if '<form' in content_lower and ('login' in content_lower or 'password' in content_lower):
            return True
        
        # Check for admin keywords in title
        title = self._extract_title(response).lower()
        admin_keywords = ['admin', 'administrator', 'login', 'panel', 'dashboard', 'control', 'manage']
        if any(keyword in title for keyword in admin_keywords):
            return True
        
        # Check for admin keywords in content
        admin_content_keywords = ['admin', 'administrator', 'dashboard', 'control panel', 'management']
        if any(keyword in content_lower for keyword in admin_content_keywords):
            return True
        
        return False
    
    def _extract_title(self, response):
        """Extract the title from an HTTP response
        
        Args:
            response (Response): HTTP response object
            
        Returns:
            str: Page title or empty string if not found
        """
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else ""
        except Exception:
            return ""
    
    def _display_results(self):
        """Display admin page finder results"""
        if self.found_pages:
            table = Table(title=f"Discovered Admin Pages for {self.domain}")
            table.add_column("URL", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Title", style="yellow")
            
            for page in self.found_pages:
                # Determine status text
                if page['status_code'] == 200:
                    status = "[green]200 OK[/green]"
                elif page['status_code'] == 401:
                    status = "[yellow]401 Unauthorized[/yellow]"
                elif page['status_code'] == 403:
                    status = "[yellow]403 Forbidden[/yellow]"
                else:
                    status = f"[white]{page['status_code']}[/white]"
                
                table.add_row(page['url'], status, page['page_title'])
            
            console.print(table)
            console.print(f"[bold green]Total admin pages discovered: {len(self.found_pages)}[/bold green]")
        else:
            console.print("[yellow]No admin pages discovered[/yellow]")