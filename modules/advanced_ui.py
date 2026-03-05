#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced UI Module for Domain Scanner
Provides enhanced user interface with real-time statistics
"""

import time
import threading
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich.align import Align
from rich.text import Text
from rich.live import Live
from rich import print as rprint
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.tree import Tree
from rich.columns import Columns
from rich.spinner import Spinner
from rich.rule import Rule
import asyncio
from collections import deque
from typing import Dict, List, Any, Optional

console = Console()

class RealTimeDashboard:
    """Real-time dashboard with live statistics"""
    
    def __init__(self, domain):
        self.domain = domain
        self.start_time = time.time()
        self.layout = Layout()
        self.setup_layout()
        self.stats_history = deque(maxlen=100)  # Keep last 100 stats
        self.is_running = True
        
    def setup_layout(self):
        """Setup the dashboard layout"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
        
        self.layout["left"].split_column(
            Layout(name="status", ratio=1),
            Layout(name="progress", ratio=1)
        )
        
        self.layout["right"].split_column(
            Layout(name="stats", ratio=1),
            Layout(name="activity", ratio=1)
        )
    
    def create_header(self, current_module="Initializing"):
        """Create header with domain and status"""
        current_time = datetime.now().strftime("%H:%M:%S")
        duration = time.time() - self.start_time
        
        header_text = Text()
        header_text.append(f"Domain: ", style="bold cyan")
        header_text.append(f"{self.domain}", style="bold white")
        header_text.append("  |  ", style="dim")
        header_text.append(f"Status: ", style="bold cyan")
        header_text.append(f"{current_module}", style="bold yellow")
        header_text.append("  |  ", style="dim")
        header_text.append(f"Time: ", style="bold cyan")
        header_text.append(f"{current_time}", style="bold white")
        header_text.append("  |  ", style="dim")
        header_text.append(f"Duration: ", style="bold cyan")
        header_text.append(f"{duration:.1f}s", style="bold green")
        
        return Panel(Align.center(header_text), border_style="cyan", title="Domain Scanner")
    
    def create_status_panel(self, stats):
        """Create status panel with current scan info"""
        status_table = Table(show_header=False, box=None, padding=0)
        status_table.add_column(style="bold cyan", width=15)
        status_table.add_column(style="bold white", width=20)
        
        status_table.add_row("Target:", self.domain)
        status_table.add_row("Modules:", f"{stats.get('modules_completed', 0)}/{stats.get('total_modules', 0)}")
        status_table.add_row("Requests:", f"{stats.get('total_requests', 0)}")
        status_table.add_row("Success Rate:", f"{stats.get('success_rate', 0):.1f}%")
        status_table.add_row("Threads:", str(stats.get('threads', 10)))
        status_table.add_row("Timeout:", f"{stats.get('timeout', 30)}s")
        
        return Panel(status_table, title="[bold blue]Status[/bold blue]", border_style="blue")
    
    def create_stats_panel(self, stats):
        """Create statistics panel with charts"""
        stats_table = Table(show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan", no_wrap=True)
        stats_table.add_column("Value", style="green", justify="right")
        stats_table.add_column("Rate", style="yellow", justify="right")
        
        duration = time.time() - self.start_time
        requests_per_sec = stats.get('total_requests', 0) / max(duration, 1)
        
        stats_table.add_row("Duration", f"{duration:.1f}s", "")
        stats_table.add_row("Total Requests", str(stats.get('total_requests', 0)), f"{requests_per_sec:.1f}/s")
        stats_table.add_row("Successful", str(stats.get('successful_requests', 0)), 
                           f"{(stats.get('successful_requests', 0)/max(stats.get('total_requests', 1), 1)*100):.1f}%")
        stats_table.add_row("Failed", str(stats.get('failed_requests', 0)), 
                           f"{(stats.get('failed_requests', 0)/max(stats.get('total_requests', 1), 1)*100):.1f}%")
        stats_table.add_row("Errors", str(len(stats.get('errors', []))), "")
        
        return Panel(stats_table, title="[bold green]Statistics[/bold green]", border_style="green")
    
    def create_activity_panel(self, recent_activities):
        """Create activity panel with recent events"""
        activity_table = Table(show_header=False, box=None, padding=0)
        activity_table.add_column(style="dim", width=8)
        activity_table.add_column()
        
        for timestamp, activity in recent_activities[-10:]:  # Show last 10 activities
            time_str = timestamp.strftime("%H:%M:%S")
            activity_table.add_row(time_str, activity)
        
        return Panel(activity_table, title="[bold yellow]Recent Activity[/bold yellow]", border_style="yellow")
    
    def create_footer(self, stats):
        """Create footer with tips and shortcuts"""
        footer_text = Text()
        footer_text.append("Shortcuts: ", style="bold cyan")
        footer_text.append("Ctrl+C ", style="bold red")
        footer_text.append("= Stop | ", style="dim")
        footer_text.append("Space ", style="bold green")
        footer_text.append("= Pause | ", style="dim")
        footer_text.append("H ", style="bold yellow")
        footer_text.append("= Help | ", style="dim")
        footer_text.append("S ", style="bold blue")
        footer_text.append("= Save Report", style="dim")
        
        if stats.get('estimated_time_remaining'):
            footer_text.append(" | ", style="dim")
            footer_text.append(f"ETA: {stats['estimated_time_remaining']:.1f}s", style="bold magenta")
        
        return Panel(Align.center(footer_text), border_style="dim")
    
    def update_display(self, stats, recent_activities, current_module):
        """Update the entire dashboard"""
        self.layout["header"].update(self.create_header(current_module))
        self.layout["status"].update(self.create_status_panel(stats))
        self.layout["stats"].update(self.create_stats_panel(stats))
        self.layout["activity"].update(self.create_activity_panel(recent_activities))
        self.layout["footer"].update(self.create_footer(stats))
        
        # Store stats for history
        self.stats_history.append({
            'timestamp': time.time(),
            'stats': stats.copy()
        })
    
    def create_enhanced_progress(self):
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

class InteractiveMenu:
    """Interactive menu system"""
    
    def __init__(self):
        self.console = Console()
    
    def display_main_menu(self):
        """Display main interactive menu"""
        menu_table = Table(show_header=False, box=None, padding=0)
        menu_table.add_column(style="bold cyan", width=3)
        menu_table.add_column()
        menu_table.add_column(style="dim")
        
        options = [
            ("1", "Start New Scan", "Begin a new domain scan"),
            ("2", "View Previous Results", "Browse scan history"),
            ("3", "Configure Settings", "Adjust scan parameters"),
            ("4", "Manage Wordlists", "Edit brute force wordlists"),
            ("5", "View Statistics", "Show scan statistics"),
            ("6", "Export Reports", "Export scan results"),
            ("7", "Help & Documentation", "Show help information"),
            ("0", "Exit", "Quit the application")
        ]
        
        for key, title, desc in options:
            menu_table.add_row(f"[{key}]", title, desc)
        
        return Panel(menu_table, title="[bold white]Main Menu[/bold white]", 
                    border_style="cyan", padding=(1, 2))
    
    def display_scan_config_menu(self):
        """Display scan configuration menu"""
        config_table = Table(show_header=False, box=None)
        config_table.add_column(style="bold yellow")
        config_table.add_column()
        
        configs = [
            ("Domain:", "Target domain to scan"),
            ("Threads:", "Number of concurrent threads"),
            ("Timeout:", "Request timeout in seconds"),
            ("Wordlist:", "Path to wordlist file"),
            ("Output:", "Output file path"),
            ("Modules:", "Scan modules to enable")
        ]
        
        for key, desc in configs:
            config_table.add_row(key, desc)
        
        return Panel(config_table, title="[bold]Scan Configuration[/bold]", 
                     border_style="yellow")

# Advanced visualization components
class SecurityVisualizer:
    """Advanced security visualization tools"""
    
    def __init__(self):
        self.console = Console()
    
    def create_radar_chart(self, metrics):
        """Create simple radar chart for security metrics"""
        chart = Table(show_header=False, box=None)
        chart.add_column(style="bold", width=15)
        chart.add_column()
        
        for metric, value in metrics.items():
            bar_length = int(value / 100 * 30)  # Scale to 30 characters
            bar = "█" * bar_length + "░" * (30 - bar_length)
            color = "red" if value < 30 else "yellow" if value < 70 else "green"
            chart.add_row(f"{metric}:", f"[{color}]{bar}[/{color}] {value:.0f}%")
        
        return Panel(chart, title="Security Score", border_style="blue")
    
    def create_threat_landscape(self, threats):
        """Create threat landscape visualization"""
        landscape = Tree("🌍 Threat Landscape")
        
        categories = {
            "Network Threats": ["DDoS", "Port Scan", "MITM"],
            "Web Threats": ["XSS", "SQLi", "CSRF"],
            "System Threats": ["Malware", "Ransomware", "Backdoor"]
        }
        
        for category, threats_list in categories.items():
            category_node = landscape.add(f"🔍 {category}")
            for threat in threats_list:
                risk_level = random.choice(["🟢 Low", "🟡 Medium", "🔴 High"])
                category_node.add(f"{risk_level} - {threat}")
        
        return Panel(landscape, title="[bold red]Threat Landscape[/bold red]", border_style="red")

# Enhanced progress with animations
class AnimatedProgress:
    """Enhanced progress with animations and effects"""
    
    def __init__(self):
        self.console = Console()
        self.animations = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        
    def create_spinner(self, text="Loading"):
        """Create animated spinner"""
        return Spinner("dots", text=text, style="bold cyan")
    
    def create_progress_bar(self, current, total, width=50, title="Progress"):
        """Create animated progress bar"""
        progress = current / total
        filled = int(width * progress)
        bar = "█" * filled + "░" * (width - filled)
        percentage = progress * 100
        
        color = "red" if percentage < 30 else "yellow" if percentage < 70 else "green"
        
        progress_text = f"[{color}]{bar}[/{color}] {percentage:.1f}% ({current}/{total})"
        return Panel(progress_text, title=f"[bold]{title}[/bold]", border_style=color)

# Utility functions
class UIUtils:
    """Utility functions for UI components"""
    
    @staticmethod
    def format_bytes(bytes_value):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"
    
    @staticmethod
    def format_duration(seconds):
        """Format duration in seconds to human readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    @staticmethod
    def create_status_badge(text, status="success"):
        """Create status badge"""
        colors = {
            "success": "[bold green]✅",
            "warning": "[bold yellow]⚠️",
            "error": "[bold red]❌",
            "info": "[bold blue]ℹ️",
            "loading": "[bold cyan]⏳"
        }
        
        color = colors.get(status, "[bold white]")
        return f"{color} {text}[/]"

# Example usage and testing
if __name__ == "__main__":
    # Test components
    dashboard = RealTimeDashboard("example.com")
    visualizer = SecurityVisualizer()
    animated_progress = AnimatedProgress()
    ui_utils = UIUtils()
    
    # Simulate stats
    stats = {
        'modules_completed': 3,
        'total_modules': 6,
        'total_requests': 1250,
        'successful_requests': 1180,
        'failed_requests': 70,
        'threads': 20,
        'timeout': 30,
        'success_rate': 94.4,
        'current_module': 'Vulnerability Analysis',
        'estimated_time_remaining': 45.2
    }
    
    activities = [
        (datetime.now(), "Starting subdomain enumeration"),
        (datetime.now(), "Found 15 subdomains"),
        (datetime.now(), "Starting admin finder"),
        (datetime.now(), "Found 3 admin pages"),
        (datetime.now(), "Starting vulnerability scan")
    ]
    
    # Test security visualizations
    security_metrics = {
        'Network Security': 85,
        'Application Security': 72,
        'Data Protection': 68,
        'Access Control': 91,
        'Monitoring': 79
    }
    
    # Display components
    with Live(dashboard.layout, refresh_per_second=4, screen=False):
        for i in range(10):
            dashboard.update_display(stats, activities, f"Module {i+1}")
            
            # Test additional components
            if i == 5:
                # Show security radar chart
                radar_panel = visualizer.create_radar_chart(security_metrics)
                dashboard.layout["right"].update(radar_panel)
            
            time.sleep(1)