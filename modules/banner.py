#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from rich.console import Console
from rich.text import Text
from rich import box
from rich.panel import Panel
import random
from datetime import datetime

# Initialize console
console = Console()

# ASCII Art Banner
ASCII_BANNER = r'''
  _____                        _       
 |  __ \                      (_)      
 | |  | | ___  _ __ ___   __ _ _ _ __  
 | |  | |/ _ \| '_ ` _ \ / _` | | '_ \ 
 | |__| | (_) | | | | | | (_| | | | | |
 |_____/ \___/|_| |_| |_|\__,_|_|_| |_|
                                       
'''

# Color choices for random selection
COLORS = ["red", "green", "blue", "magenta", "cyan", "yellow"]

def display_banner():
    """Display the tool banner with styling"""
    # Select random color for banner
    color = random.choice(COLORS)
    
    # Create styled banner
    banner = Text(ASCII_BANNER, style=f"bold {color}")
    
    # Add tool information
    info = Text()
    info.append("\n")
    info.append("Advanced Domain Reconnaissance Tool", style="bold white")
    info.append("\n\n")
    info.append("Author: ", style="dim")
    info.append("SayerLinux", style="bold green")
    info.append(" | ")
    info.append("Email: ", style="dim")
    info.append("SayerLinux@gmail.com", style="bold green")
    info.append("\n")
    
    # Add current date and time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info.append(f"Started at: {current_time}", style="dim")
    
    # Combine banner and info
    full_banner = Text.assemble(banner, info)
    
    # Display in panel
    console.print(Panel(full_banner, box=box.ROUNDED, border_style=color, expand=False))
    console.print("\n")

if __name__ == "__main__":
    # Test the banner if run directly
    display_banner()