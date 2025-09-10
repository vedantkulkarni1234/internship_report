#!/usr/bin/env python3
"""
Personal Firewall - GUI Interface
Tkinter-based GUI for managing firewall rules and monitoring traffic.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from typing import Optional
import math
import random

# Import the firewall engine
try:
    from firewall_core import FirewallEngine, FirewallRule, RuleAction, Protocol, PacketLog
except ImportError:
    print("Error: firewall_core.py not found. Make sure both files are in the same directory.")
    exit(1)

class AnimatedGauge:
    """Animated gauge widget for visualizing statistics"""
    
    def __init__(self, parent, width=200, height=150, title="", max_value=100):
        self.parent = parent
        self.width = width
        self.height = height
        self.title = title
        self.max_value = max_value
        self.current_value = 0
        self.target_value = 0
        
        # Create canvas
        self.canvas = tk.Canvas(parent, width=width, height=height, bg='#2b2b2b', highlightthickness=0)
        self.canvas.pack(pady=5)
        
        # Draw gauge background
        self.draw_gauge()
        
    def draw_gauge(self):
        """Draw the gauge background"""
        self.canvas.delete("all")
        
        # Draw title
        self.canvas.create_text(self.width/2, 20, text=self.title, fill="#ffffff", font=("Arial", 10, "bold"))
        
        # Draw gauge arc
        start_angle = 150  # Start from bottom left
        end_angle = 30     # End at bottom right
        extent = end_angle - start_angle
        
        # Background arc
        self.canvas.create_arc(20, 40, self.width-20, self.height-20, 
                              start=start_angle, extent=extent, 
                              outline="#444444", width=20, style="arc")
        
        # Value arc
        value_extent = extent * (self.current_value / max(self.max_value, 1))
        if self.current_value > 0:
            color = "#00ff00"  # Green
            if self.current_value > self.max_value * 0.7:
                color = "#ffff00"  # Yellow
            if self.current_value > self.max_value * 0.9:
                color = "#ff0000"  # Red
                
            self.canvas.create_arc(20, 40, self.width-20, self.height-20, 
                                  start=start_angle, extent=value_extent, 
                                  outline=color, width=20, style="arc")
        
        # Draw center value
        self.canvas.create_text(self.width/2, self.height/2+10, 
                               text=f"{self.current_value}", 
                               fill="#ffffff", font=("Arial", 16, "bold"))
        
    def update_value(self, value):
        """Update the gauge value with animation"""
        self.target_value = min(value, self.max_value)
        self.animate()
        
    def animate(self):
        """Animate the gauge to the target value"""
        if abs(self.current_value - self.target_value) > 0.5:
            self.current_value += (self.target_value - self.current_value) * 0.1
            self.draw_gauge()
            self.canvas.after(50, self.animate)
        else:
            self.current_value = self.target_value
            self.draw_gauge()

class FirewallRuleDialog:
    """Dialog for creating/editing firewall rules"""
    
    def __init__(self, parent, rule: Optional[FirewallRule] = None):
        self.parent = parent
        self.rule = rule
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Firewall Rule" if rule is None else "Edit Rule")
        self.dialog.geometry("450x600")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()  # Make dialog modal
        self.dialog.configure(bg='#2b2b2b')
        
        # Set custom style
        self.setup_styles()
        
        self.create_widgets()
        
        # Populate fields if editing
        if rule:
            self.populate_fields(rule)
            
        # Center the dialog
        self.dialog.transient(parent)
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))

    def setup_styles(self):
        """Setup custom styles for the dialog"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabel', background='#2b2b2b', foreground='#ffffff', font=('Arial', 10))
        self.style.configure('TButton', background='#3a7ca5', foreground='#ffffff', font=('Arial', 9, 'bold'))
        self.style.map('TButton', background=[('active', '#2a5a75')])
        self.style.configure('TEntry', fieldbackground='#3c3c3c', foreground='#ffffff')
        self.style.configure('TCombobox', fieldbackground='#3c3c3c', background='#3c3c3c', foreground='#ffffff')
        self.style.map('TCombobox', fieldbackground=[('readonly', '#3c3c3c')], 
                      background=[('readonly', '#3c3c3c')], foreground=[('readonly', '#ffffff')])
        self.style.configure('TCheckbutton', background='#2b2b2b', foreground='#ffffff')

    def create_widgets(self):
        """Create dialog widgets"""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = tk.Frame(main_frame, bg='#1e5b8f', height=40)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(header_frame, text="Firewall Rule Configuration", 
                               bg='#1e5b8f', fg='#ffffff', font=('Arial', 12, 'bold'))
        header_label.pack(pady=10)
        
        # Rule Name
        ttk.Label(main_frame, text="Rule Name:").pack(anchor=tk.W, pady=(0, 5))
        self.name_var = tk.StringVar()
        name_entry = ttk.Entry(main_frame, textvariable=self.name_var, width=50)
        name_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Action
        ttk.Label(main_frame, text="Action:").pack(anchor=tk.W, pady=(0, 5))
        self.action_var = tk.StringVar()
        action_combo = ttk.Combobox(main_frame, textvariable=self.action_var, 
                                   values=["allow", "block", "log"], state="readonly", width=47)
        action_combo.pack(fill=tk.X, pady=(0, 15))
        action_combo.set("allow")
        
        # Protocol
        ttk.Label(main_frame, text="Protocol:").pack(anchor=tk.W, pady=(0, 5))
        self.protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(main_frame, textvariable=self.protocol_var, 
                                     values=["all", "tcp", "udp", "icmp"], state="readonly", width=47)
        protocol_combo.pack(fill=tk.X, pady=(0, 15))
        protocol_combo.set("all")
        
        # Source IP
        ttk.Label(main_frame, text="Source IP:").pack(anchor=tk.W, pady=(0, 5))
        self.src_ip_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.src_ip_var, width=50).pack(fill=tk.X, pady=(0, 5))
        ttk.Label(main_frame, text="(Leave empty for any, use * for wildcards like 192.168.*.*)", 
                 font=('Arial', 8)).pack(anchor=tk.W, pady=(0, 15))
        
        # Destination IP
        ttk.Label(main_frame, text="Destination IP:").pack(anchor=tk.W, pady=(0, 5))
        self.dst_ip_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.dst_ip_var, width=50).pack(fill=tk.X, pady=(0, 15))
        
        # Source Port
        ttk.Label(main_frame, text="Source Port:").pack(anchor=tk.W, pady=(0, 5))
        self.src_port_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.src_port_var, width=50).pack(fill=tk.X, pady=(0, 5))
        ttk.Label(main_frame, text="(Leave empty for any port)", font=('Arial', 8)).pack(anchor=tk.W, pady=(0, 15))
        
        # Destination Port
        ttk.Label(main_frame, text="Destination Port:").pack(anchor=tk.W, pady=(0, 5))
        self.dst_port_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.dst_port_var, width=50).pack(fill=tk.X, pady=(0, 15))
        
        # Priority
        ttk.Label(main_frame, text="Priority:").pack(anchor=tk.W, pady=(0, 5))
        self.priority_var = tk.StringVar(value="10")
        ttk.Entry(main_frame, textvariable=self.priority_var, width=50).pack(fill=tk.X, pady=(0, 5))
        ttk.Label(main_frame, text="(Higher numbers = higher priority)", font=('Arial', 8)).pack(anchor=tk.W, pady=(0, 15))
        
        # Enabled checkbox
        self.enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Rule Enabled", variable=self.enabled_var).pack(anchor=tk.W, pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#2b2b2b')
        button_frame.pack(fill=tk.X)
        
        ok_button = tk.Button(button_frame, text="OK", command=self.ok_clicked, 
                             bg='#3a7ca5', fg='#ffffff', font=('Arial', 9, 'bold'),
                             relief=tk.FLAT, padx=20)
        ok_button.pack(side=tk.RIGHT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.cancel_clicked, 
                                 bg='#8b3a3a', fg='#ffffff', font=('Arial', 9, 'bold'),
                                 relief=tk.FLAT, padx=20)
        cancel_button.pack(side=tk.RIGHT, padx=5)

    def populate_fields(self, rule: FirewallRule):
        """Populate dialog fields with rule data"""
        self.name_var.set(rule.name)
        self.action_var.set(rule.action.value)
        self.protocol_var.set(rule.protocol.value)
        self.src_ip_var.set(rule.src_ip or "")
        self.dst_ip_var.set(rule.dst_ip or "")
        self.src_port_var.set(str(rule.src_port) if rule.src_port else "")
        self.dst_port_var.set(str(rule.dst_port) if rule.dst_port else "")
        self.priority_var.set(str(rule.priority))
        self.enabled_var.set(rule.enabled)

    def ok_clicked(self):
        """Handle OK button click"""
        try:
            # Validate inputs
            name = self.name_var.get().strip()
            if not name:
                messagebox.showerror("Error", "Rule name is required")
                return
                
            action = RuleAction(self.action_var.get())
            protocol = Protocol(self.protocol_var.get())
            
            src_ip = self.src_ip_var.get().strip() or None
            dst_ip = self.dst_ip_var.get().strip() or None
            
            src_port = None
            if self.src_port_var.get().strip():
                src_port = int(self.src_port_var.get().strip())
                
            dst_port = None
            if self.dst_port_var.get().strip():
                dst_port = int(self.dst_port_var.get().strip())
                
            priority = int(self.priority_var.get().strip())
            enabled = self.enabled_var.get()
            
            # Create rule
            self.result = FirewallRule(
                name=name,
                action=action,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                priority=priority,
                enabled=enabled
            )
            
            self.dialog.destroy()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")

    def cancel_clicked(self):
        """Handle Cancel button click"""
        self.result = None
        self.dialog.destroy()

class FirewallGUI:
    """Main GUI application for the personal firewall"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CyberShield Firewall")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Initialize firewall engine
        self.firewall = FirewallEngine()
        self.firewall.add_callback(self.packet_callback)
        
        # GUI state
        self.is_monitoring = False
        self.update_thread = None
        
        # Setup styles
        self.setup_styles()
        
        # Create widgets
        self.create_widgets()
        
        # Refresh data
        self.refresh_rules()
        self.refresh_logs()
        
        # Start GUI update thread
        self.start_gui_updates()

    def setup_styles(self):
        """Setup GUI styles with modern dark theme"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors for dark theme
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        self.style.configure('TNotebook', background='#1e1e1e')
        self.style.configure('TNotebook.Tab', background='#3a3a3a', foreground='#ffffff')
        self.style.map('TNotebook.Tab', background=[('selected', '#1e5b8f')], 
                      foreground=[('selected', '#ffffff')])
        
        # Configure treeview
        self.style.configure("Treeview", 
                            background="#2d2d2d",
                            foreground="#ffffff",
                            fieldbackground="#2d2d2d",
                            rowheight=25)
        self.style.configure("Treeview.Heading", 
                            background="#1e5b8f", 
                            foreground="#ffffff",
                            font=('Arial', 9, 'bold'))
        self.style.map('Treeview', background=[('selected', '#3a7ca5')])
        
        # Configure buttons
        self.style.configure('TButton', 
                            background='#3a7ca5', 
                            foreground='#ffffff',
                            font=('Arial', 9, 'bold'))
        self.style.map('TButton', 
                      background=[('active', '#2a5a75')],
                      foreground=[('active', '#ffffff')])
        
        # Configure scrollbar
        self.style.configure("Vertical.TScrollbar", 
                            background="#3a3a3a", 
                            troughcolor="#2b2b2b")
        self.style.map("Vertical.TScrollbar", 
                      background=[("active", "#4a4a4a")])

    def create_widgets(self):
        """Create main GUI widgets"""
        # Create header
        self.create_header()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_rules_tab()
        self.create_logs_tab()
        self.create_settings_tab()

    def create_header(self):
        """Create application header with title and status"""
        header_frame = tk.Frame(self.root, bg='#1e5b8f', height=60)
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(header_frame, text="CYBERSHIELD FIREWALL", 
                              bg='#1e5b8f', fg='#ffffff', 
                              font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Status indicator
        self.status_frame = tk.Frame(header_frame, bg='#1e5b8f')
        self.status_frame.pack(side=tk.RIGHT, padx=20)
        
        self.status_indicator = tk.Canvas(self.status_frame, width=20, height=20, 
                                         bg='#1e5b8f', highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT)
        self.status_circle = self.status_indicator.create_oval(5, 5, 15, 15, fill='#8b3a3a')
        
        self.status_label = tk.Label(self.status_frame, text="STOPPED", 
                                    bg='#1e5b8f', fg='#ff6b6b', 
                                    font=('Arial', 10, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))

    def create_dashboard_tab(self):
        """Create dashboard tab with statistics and visualizations"""
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Control panel
        control_frame = tk.Frame(self.dashboard_frame, bg='#2b2b2b', height=80)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        control_frame.pack_propagate(False)
        
        # Start/Stop button
        self.start_button = tk.Button(control_frame, text="Start Monitoring", 
                                     command=self.toggle_monitoring,
                                     bg='#3a7ca5', fg='#ffffff', 
                                     font=('Arial', 10, 'bold'),
                                     relief=tk.FLAT, padx=20, pady=5)
        self.start_button.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Statistics frame
        stats_frame = tk.Frame(self.dashboard_frame, bg='#2b2b2b')
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Gauges
        gauge_frame = tk.Frame(stats_frame, bg='#2b2b2b')
        gauge_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Create gauges
        self.total_gauge = AnimatedGauge(gauge_frame, width=220, height=170, title="Total Packets")
        self.blocked_gauge = AnimatedGauge(gauge_frame, width=220, height=170, title="Blocked Packets")
        self.allowed_gauge = AnimatedGauge(gauge_frame, width=220, height=170, title="Allowed Packets")
        
        # Right panel - Recent activity
        activity_frame = tk.Frame(stats_frame, bg='#2b2b2b')
        activity_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        activity_label = tk.Label(activity_frame, text="Recent Activity", 
                                 bg='#2b2b2b', fg='#ffffff', 
                                 font=('Arial', 12, 'bold'))
        activity_label.pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Activity tree
        tree_frame = tk.Frame(activity_frame, bg='#2b2b2b')
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.activity_tree = ttk.Treeview(tree_frame, 
                                         columns=("Time", "Action", "Source", "Destination", "Protocol"), 
                                         show="headings", height=15)
        self.activity_tree.heading("Time", text="Time")
        self.activity_tree.heading("Action", text="Action")
        self.activity_tree.heading("Source", text="Source")
        self.activity_tree.heading("Destination", text="Destination")
        self.activity_tree.heading("Protocol", text="Protocol")
        
        # Column widths
        self.activity_tree.column("Time", width=120)
        self.activity_tree.column("Action", width=80)
        self.activity_tree.column("Source", width=150)
        self.activity_tree.column("Destination", width=150)
        self.activity_tree.column("Protocol", width=80)
        
        activity_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scroll.set)
        
        self.activity_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        activity_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for treeview
        self.activity_tree.tag_configure('blocked', foreground='#ff6b6b')
        self.activity_tree.tag_configure('allowed', foreground='#4ecdc4')
        self.activity_tree.tag_configure('logged', foreground='#ffd166')

    def create_rules_tab(self):
        """Create rules management tab"""
        self.rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_frame, text="Rules")
        
        # Rules toolbar
        toolbar_frame = tk.Frame(self.rules_frame, bg='#2b2b2b', height=60)
        toolbar_frame.pack(fill=tk.X, padx=10, pady=10)
        toolbar_frame.pack_propagate(False)
        
        # Buttons with modern styling
        add_btn = tk.Button(toolbar_frame, text="Add Rule", command=self.add_rule,
                           bg='#4ecdc4', fg='#000000', font=('Arial', 9, 'bold'),
                           relief=tk.FLAT, padx=15)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        edit_btn = tk.Button(toolbar_frame, text="Edit Rule", command=self.edit_rule,
                            bg='#ffd166', fg='#000000', font=('Arial', 9, 'bold'),
                            relief=tk.FLAT, padx=15)
        edit_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = tk.Button(toolbar_frame, text="Delete Rule", command=self.delete_rule,
                              bg='#8b3a3a', fg='#ffffff', font=('Arial', 9, 'bold'),
                              relief=tk.FLAT, padx=15)
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = tk.Button(toolbar_frame, text="Refresh", command=self.refresh_rules,
                               bg='#3a7ca5', fg='#ffffff', font=('Arial', 9, 'bold'),
                               relief=tk.FLAT, padx=15)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Rules list
        rules_list_frame = tk.Frame(self.rules_frame, bg='#2b2b2b')
        rules_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.rules_tree = ttk.Treeview(rules_list_frame, 
                                      columns=("Name", "Action", "Protocol", "Source", "Destination", "Ports", "Priority", "Enabled"), 
                                      show="headings")
        
        # Configure columns
        columns = ["Name", "Action", "Protocol", "Source", "Destination", "Ports", "Priority", "Enabled"]
        for col in columns:
            self.rules_tree.heading(col, text=col)
            
        # Set column widths
        self.rules_tree.column("Name", width=180)
        self.rules_tree.column("Action", width=80)
        self.rules_tree.column("Protocol", width=80)
        self.rules_tree.column("Source", width=120)
        self.rules_tree.column("Destination", width=120)
        self.rules_tree.column("Ports", width=100)
        self.rules_tree.column("Priority", width=70)
        self.rules_tree.column("Enabled", width=70)
        
        rules_scroll = ttk.Scrollbar(rules_list_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scroll.set)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rules_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for treeview
        self.rules_tree.tag_configure('disabled', foreground='#888888')
        self.rules_tree.tag_configure('allow', foreground='#4ecdc4')
        self.rules_tree.tag_configure('block', foreground='#ff6b6b')
        self.rules_tree.tag_configure('log', foreground='#ffd166')

    def create_logs_tab(self):
        """Create logs tab"""
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs")
        
        # Logs toolbar
        logs_toolbar = tk.Frame(self.logs_frame, bg='#2b2b2b', height=60)
        logs_toolbar.pack(fill=tk.X, padx=10, pady=10)
        logs_toolbar.pack_propagate(False)
        
        refresh_btn = tk.Button(logs_toolbar, text="Refresh", command=self.refresh_logs,
                               bg='#3a7ca5', fg='#ffffff', font=('Arial', 9, 'bold'),
                               relief=tk.FLAT, padx=15)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(logs_toolbar, text="Clear Logs", command=self.clear_logs,
                             bg='#8b3a3a', fg='#ffffff', font=('Arial', 9, 'bold'),
                             relief=tk.FLAT, padx=15)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = tk.Button(logs_toolbar, text="Export Logs", command=self.export_logs,
                              bg='#4ecdc4', fg='#000000', font=('Arial', 9, 'bold'),
                              relief=tk.FLAT, padx=15)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Filter frame
        filter_frame = tk.Frame(logs_toolbar, bg='#2b2b2b')
        filter_frame.pack(side=tk.RIGHT, padx=20)
        
        tk.Label(filter_frame, text="Filter:", bg='#2b2b2b', fg='#ffffff').pack(side=tk.LEFT, padx=5)
        self.log_filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.log_filter_var, 
                                   values=["All", "BLOCKED", "ALLOWED"], state="readonly", width=12)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.set("All")
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_logs())
        
        # Logs list
        logs_list_frame = tk.Frame(self.logs_frame, bg='#2b2b2b')
        logs_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.logs_tree = ttk.Treeview(logs_list_frame, 
                                     columns=("Timestamp", "Action", "Source", "Destination", "Protocol", "Ports", "Rule"), 
                                     show="headings")
        
        log_columns = ["Timestamp", "Action", "Source", "Destination", "Protocol", "Ports", "Rule"]
        for col in log_columns:
            self.logs_tree.heading(col, text=col)
            
        # Set log column widths
        self.logs_tree.column("Timestamp", width=150)
        self.logs_tree.column("Action", width=80)
        self.logs_tree.column("Source", width=150)
        self.logs_tree.column("Destination", width=150)
        self.logs_tree.column("Protocol", width=80)
        self.logs_tree.column("Ports", width=100)
        self.logs_tree.column("Rule", width=180)
        
        logs_scroll = ttk.Scrollbar(logs_list_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=logs_scroll.set)
        
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        logs_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for treeview
        self.logs_tree.tag_configure('blocked', foreground='#ff6b6b')
        self.logs_tree.tag_configure('allowed', foreground='#4ecdc4')

    def create_settings_tab(self):
        """Create settings tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Settings container
        settings_container = tk.Frame(self.settings_frame, bg='#2b2b2b')
        settings_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(settings_container, bg='#1e5b8f', height=40)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(header_frame, text="Firewall Settings", 
                               bg='#1e5b8f', fg='#ffffff', font=('Arial', 12, 'bold'))
        header_label.pack(pady=10)
        
        # Network interface selection
        interface_frame = tk.Frame(settings_container, bg='#2b2b2b')
        interface_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(interface_frame, text="Network Interface:", 
                bg='#2b2b2b', fg='#ffffff', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        self.interface_var = tk.StringVar()
        
        try:
            from scapy.all import get_if_list
            interfaces = ["Auto"] + get_if_list()
        except:
            interfaces = ["Auto", "eth0", "wlan0", "lo"]
            
        interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, 
                                      values=interfaces, state="readonly", width=30)
        interface_combo.pack(anchor=tk.W, pady=10)
        interface_combo.set("Auto")
        
        # Logging settings
        logging_frame = tk.Frame(settings_container, bg='#2b2b2b')
        logging_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(logging_frame, text="Logging Settings:", 
                bg='#2b2b2b', fg='#ffffff', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        self.log_all_var = tk.BooleanVar()
        log_check = tk.Checkbutton(logging_frame, text="Log all packets (warning: high disk usage)", 
                                  variable=self.log_all_var, bg='#2b2b2b', fg='#ffffff',
                                  selectcolor='#2b2b2b', activebackground='#2b2b2b')
        log_check.pack(anchor=tk.W, pady=10)
        
        # System integration
        system_frame = tk.Frame(settings_container, bg='#2b2b2b')
        system_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(system_frame, text="System Integration:", 
                bg='#2b2b2b', fg='#ffffff', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        iptables_frame = tk.Frame(system_frame, bg='#2b2b2b')
        iptables_frame.pack(fill=tk.X, pady=10)
        
        install_btn = tk.Button(iptables_frame, text="Install iptables Rules", command=self.install_iptables,
                               bg='#3a7ca5', fg='#ffffff', font=('Arial', 9, 'bold'),
                               relief=tk.FLAT, padx=15)
        install_btn.pack(side=tk.LEFT, padx=5)
        
        remove_btn = tk.Button(iptables_frame, text="Remove iptables Rules", command=self.remove_iptables,
                              bg='#8b3a3a', fg='#ffffff', font=('Arial', 9, 'bold'),
                              relief=tk.FLAT, padx=15)
        remove_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Label(system_frame, text="Note: Requires root privileges", 
                bg='#2b2b2b', fg='#aaaaaa', font=('Arial', 8)).pack(anchor=tk.W, pady=(5, 0))
        
        # About section
        about_frame = tk.Frame(settings_container, bg='#2b2b2b')
        about_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(about_frame, text="About CyberShield Firewall:", 
                bg='#2b2b2b', fg='#ffffff', font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        about_text = """CyberShield Firewall v2.0
A next-generation Python-based firewall with advanced GUI interface.

Features:
• Real-time packet filtering and monitoring
• Customizable rule management
• Advanced data visualization
• Comprehensive logging and audit trail
• iptables integration (Linux)

Requirements:
• Python 3.6+
• Scapy library
• Root privileges for packet capture

Designed with a modern dark theme for optimal visual experience.
"""
        
        about_label = tk.Label(about_frame, text=about_text, 
                              bg='#2b2b2b', fg='#cccccc', 
                              font=('Arial', 9), justify=tk.LEFT)
        about_label.pack(anchor=tk.W, pady=10)

    def toggle_monitoring(self):
        """Toggle firewall monitoring on/off"""
        if not self.is_monitoring:
            # Start monitoring
            interface = self.interface_var.get() if self.interface_var.get() != "Auto" else None
            
            if self.firewall.start_monitoring(interface):
                self.is_monitoring = True
                self.start_button.config(text="Stop Monitoring", bg='#8b3a3a')
                self.status_indicator.item(self.status_circle, fill='#4ecdc4')
                self.status_label.config(text="RUNNING", fg='#4ecdc4')
                messagebox.showinfo("Success", "Firewall monitoring started successfully!")
            else:
                messagebox.showerror("Error", "Failed to start monitoring. Check that you have root privileges and Scapy is installed.")
        else:
            # Stop monitoring
            self.firewall.stop_monitoring()
            self.is_monitoring = False
            self.start_button.config(text="Start Monitoring", bg='#3a7ca5')
            self.status_indicator.item(self.status_circle, fill='#8b3a3a')
            self.status_label.config(text="STOPPED", fg='#ff6b6b')
            messagebox.showinfo("Info", "Firewall monitoring stopped.")

    def packet_callback(self, packet_info, action, rule):
        """Callback for packet processing (called from firewall engine)"""
        # This will be called from the sniffing thread, so we need to be careful
        # In a real implementation, you'd use thread-safe queues here
        pass

    def add_rule(self):
        """Add a new firewall rule"""
        dialog = FirewallRuleDialog(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            if self.firewall.add_rule(dialog.result):
                self.refresh_rules()
                messagebox.showinfo("Success", f"Rule '{dialog.result.name}' added successfully!")
            else:
                messagebox.showerror("Error", "Failed to add rule.")

    def edit_rule(self):
        """Edit selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to edit.")
            return
            
        item = selection[0]
        rule_name = self.rules_tree.item(item)['values'][0]
        
        # Find the rule
        rule = None
        for r in self.firewall.get_rules():
            if r.name == rule_name:
                rule = r
                break
                
        if not rule:
            messagebox.showerror("Error", "Rule not found.")
            return
            
        dialog = FirewallRuleDialog(self.root, rule)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            if self.firewall.update_rule(rule_name, dialog.result):
                self.refresh_rules()
                messagebox.showinfo("Success", f"Rule '{dialog.result.name}' updated successfully!")
            else:
                messagebox.showerror("Error", "Failed to update rule.")

    def delete_rule(self):
        """Delete selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to delete.")
            return
            
        item = selection[0]
        rule_name = self.rules_tree.item(item)['values'][0]
        
        if messagebox.askyesno("Confirm", f"Delete rule '{rule_name}'?"):
            if self.firewall.remove_rule(rule_name):
                self.refresh_rules()
                messagebox.showinfo("Success", f"Rule '{rule_name}' deleted successfully!")
            else:
                messagebox.showerror("Error", "Failed to delete rule.")

    def refresh_rules(self):
        """Refresh rules list"""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        # Add current rules
        for rule in self.firewall.get_rules():
            source = rule.src_ip or "Any"
            destination = rule.dst_ip or "Any"
            ports = ""
            if rule.src_port or rule.dst_port:
                ports = f"{rule.src_port or '*'}:{rule.dst_port or '*'}"
            else:
                ports = "Any"
                
            values = (
                rule.name,
                rule.action.value.upper(),
                rule.protocol.value.upper(),
                source,
                destination,
                ports,
                rule.priority,
                "Yes" if rule.enabled else "No"
            )
            
            tags = ('disabled',) if not rule.enabled else (rule.action.value,)
            self.rules_tree.insert('', 'end', values=values, tags=tags)

    def refresh_logs(self):
        """Refresh logs list"""
        # Clear existing items
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
            
        # Get filtered logs
        filter_action = self.log_filter_var.get()
        logs = self.firewall.get_recent_logs(100)
        
        for log in reversed(logs):  # Show most recent first
            if filter_action != "All" and log.action != filter_action:
                continue
                
            timestamp = datetime.fromisoformat(log.timestamp).strftime("%H:%M:%S")
            ports = ""
            if log.src_port or log.dst_port:
                ports = f"{log.src_port or '*'}:{log.dst_port or '*'}"
            else:
                ports = "N/A"
                
            values = (
                timestamp,
                log.action,
                log.src_ip,
                log.dst_ip,
                log.protocol.upper(),
                ports,
                log.rule_name or "Default"
            )
            
            tags = ('blocked',) if log.action == "BLOCKED" else ('allowed',)
            self.logs_tree.insert('', 'end', values=values, tags=tags)

    def clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            self.firewall.clear_logs()
            self.refresh_logs()
            messagebox.showinfo("Success", "Logs cleared successfully!")

    def export_logs(self):
        """Export logs to file"""
        from tkinter import filedialog
        import csv
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Timestamp", "Action", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Rule"])
                    
                    for log in self.firewall.get_recent_logs(1000):
                        writer.writerow([
                            log.timestamp,
                            log.action,
                            log.src_ip,
                            log.dst_ip,
                            log.protocol,
                            log.src_port or "",
                            log.dst_port or "",
                            log.rule_name or ""
                        ])
                        
                messagebox.showinfo("Success", f"Logs exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")

    def install_iptables(self):
        """Install iptables rules (Linux only)"""
        messagebox.showinfo("Info", "iptables integration would require root privileges and platform-specific implementation.")

    def remove_iptables(self):
        """Remove iptables rules (Linux only)"""
        messagebox.showinfo("Info", "iptables integration would require root privileges and platform-specific implementation.")

    def update_statistics(self):
        """Update statistics display"""
        stats = self.firewall.get_statistics()
        
        # Update gauges with animation
        self.total_gauge.update_value(stats['total_packets'])
        self.blocked_gauge.update_value(stats['blocked_packets'])
        self.allowed_gauge.update_value(stats['allowed_packets'])

    def update_activity(self):
        """Update recent activity display"""
        # Clear old entries
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
            
        # Add recent logs
        recent_logs = self.firewall.get_recent_logs(15)
        for log in reversed(recent_logs):
            timestamp = datetime.fromisoformat(log.timestamp).strftime("%H:%M:%S")
            source = f"{log.src_ip}:{log.src_port}" if log.src_port else log.src_ip
            destination = f"{log.dst_ip}:{log.dst_port}" if log.dst_port else log.dst_ip
            
            values = (timestamp, log.action, source, destination, log.protocol.upper())
            tags = ('blocked',) if log.action == "BLOCKED" else ('allowed',)
            self.activity_tree.insert('', 'end', values=values, tags=tags)

    def start_gui_updates(self):
        """Start GUI update thread"""
        def update_loop():
            while True:
                try:
                    self.root.after(0, self.update_statistics)
                    self.root.after(0, self.update_activity)
                    time.sleep(2)  # Update every 2 seconds
                except:
                    break
                    
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()

    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            if self.is_monitoring:
                self.firewall.stop_monitoring()

def main():
    """Main entry point"""
    try:
        import sys
        if len(sys.argv) > 1 and sys.argv[1] == "--help":
            print("""CyberShield Firewall GUI

Usage: python firewall_gui.py [options]

Options:
  --help    Show this help message

Features:
- Real-time packet monitoring
- Custom firewall rules
- Traffic logging and analysis
- System integration (iptables)
- Modern dark theme interface

Note: Root privileges required for packet capture on most systems.
""")
            return
            
        # Check for root privileges on Unix systems
        if hasattr(sys, 'platform') and sys.platform.startswith('linux'):
            import os
            if os.geteuid() != 0:
                print("Warning: Root privileges recommended for full functionality.")
                print("Some features may not work without sudo.")
        
        app = FirewallGUI()
        app.run()
        
    except ImportError as e:
        print(f"Error: Missing required dependency: {e}")
        print("Install required packages with: pip install scapy")
    except Exception as e:
        print(f"Error starting application: {e}")

if __name__ == "__main__":
    main()