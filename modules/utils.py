#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import logging
import pkg_resources
import platform
from rich.console import Console
from datetime import datetime

# Initialize console
console = Console()

def check_requirements():
    """Check if all required packages are installed"""
    try:
        # Read requirements file
        requirements_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'requirements.txt')
        with open(requirements_file, 'r') as f:
            requirements = [line.strip() for line in f if not line.startswith('#') and line.strip()]
        
        # Check each requirement
        installed = {pkg.key for pkg in pkg_resources.working_set}
        missing = []
        
        for requirement in requirements:
            # Extract package name from requirement line (remove version info)
            package_name = re.split(r'[><=~]', requirement)[0].strip()
            if package_name.lower() not in installed and package_name != 'socket' and package_name != 'ssl':
                missing.append(requirement)
        
        if missing:
            console.print(f"[bold yellow]Warning: Missing packages: {', '.join(missing)}[/bold yellow]")
            console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")
            return False
            
        return True
    except Exception as e:
        console.print(f"[bold red]Error checking requirements: {str(e)}[/bold red]")
        return False

def is_valid_domain(domain):
    """Check if the provided domain is valid"""
    # Simple domain validation regex
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def setup_logging(verbose=False):
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"domain_scan_{timestamp}.log")
    
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler() if verbose else logging.NullHandler()
        ]
    )
    
    return logging.getLogger('domain_scanner')

def save_to_file(filename, content):
    """Save content to a file"""
    try:
        with open(filename, 'w') as f:
            f.write(content)
        return True
    except Exception as e:
        logging.error(f"Error saving to file {filename}: {str(e)}")
        return False

def load_wordlist(wordlist_path):
    """Load wordlist from file"""
    try:
        if not wordlist_path or not os.path.exists(wordlist_path):
            # Use default wordlist
            default_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'wordlists',
                'default.txt'
            )
            wordlist_path = default_path
        
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"Error loading wordlist: {str(e)}")
        return []

def get_user_agent(custom_agent=None):
    """Get user agent string"""
    if custom_agent:
        return custom_agent
    
    # Default user agents list
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
    ]
    
    # Return random user agent
    import random
    return random.choice(user_agents)

def format_duration(seconds):
    """Format duration in seconds to human-readable format"""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    elif minutes > 0:
        return f"{int(minutes)}m {int(seconds)}s"
    else:
        return f"{seconds:.2f}s"