#!/usr/bin/env python3
"""
Personal Firewall - Core Engine
A lightweight firewall implementation with packet filtering and rule management.
"""

import json
import threading
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Callable
import logging
from enum import Enum

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

class RuleAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"

@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    name: str
    action: RuleAction
    protocol: Protocol
    src_ip: Optional[str] = None  # None means any IP
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    enabled: bool = True
    priority: int = 0  # Higher priority rules are checked first

    def matches_packet(self, packet_info: Dict) -> bool:
        """Check if this rule matches the given packet"""
        if not self.enabled:
            return False

        # Check protocol
        if self.protocol != Protocol.ALL and self.protocol.value != packet_info.get('protocol', '').lower():
            return False

        # Check source IP
        if self.src_ip and self.src_ip != packet_info.get('src_ip'):
            if not self._ip_matches_pattern(packet_info.get('src_ip', ''), self.src_ip):
                return False

        # Check destination IP
        if self.dst_ip and self.dst_ip != packet_info.get('dst_ip'):
            if not self._ip_matches_pattern(packet_info.get('dst_ip', ''), self.dst_ip):
                return False

        # Check source port
        if self.src_port and self.src_port != packet_info.get('src_port'):
            return False

        # Check destination port
        if self.dst_port and self.dst_port != packet_info.get('dst_port'):
            return False

        return True

    def _ip_matches_pattern(self, ip: str, pattern: str) -> bool:
        """Check if IP matches pattern (supports wildcards like 192.168.*.*)"""
        if pattern == "*":
            return True
        
        ip_parts = ip.split('.')
        pattern_parts = pattern.split('.')
        
        if len(ip_parts) != 4 or len(pattern_parts) != 4:
            return False
            
        for ip_part, pattern_part in zip(ip_parts, pattern_parts):
            if pattern_part != "*" and ip_part != pattern_part:
                return False
                
        return True

@dataclass
class PacketLog:
    """Represents a logged packet"""
    timestamp: str
    action: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    rule_name: Optional[str] = None

class FirewallEngine:
    """Core firewall engine for packet filtering and rule management"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        self.config_file = config_file
        self.rules: List[FirewallRule] = []
        self.packet_logs: List[PacketLog] = []
        self.blocked_packets = 0
        self.allowed_packets = 0
        self.total_packets = 0
        self.is_running = False
        self.sniff_thread = None
        self.callbacks: List[Callable] = []
        
        # Setup logging
        try:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler('firewall.log'),
                    logging.StreamHandler()
                ]
            )
        except PermissionError:
            # If we can't write to firewall.log, just use console logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.StreamHandler()
                ]
            )
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.load_config()
        
        # Add default rules if none exist
        if not self.rules:
            self._create_default_rules()

    def _create_default_rules(self):
        """Create default firewall rules"""
        default_rules = [
            FirewallRule("Allow Outbound HTTP", RuleAction.ALLOW, Protocol.TCP, dst_port=80, priority=10),
            FirewallRule("Allow Outbound HTTPS", RuleAction.ALLOW, Protocol.TCP, dst_port=443, priority=10),
            FirewallRule("Allow Outbound DNS", RuleAction.ALLOW, Protocol.UDP, dst_port=53, priority=10),
            FirewallRule("Allow Local Network", RuleAction.ALLOW, Protocol.ALL, src_ip="192.168.*.*", priority=5),
            FirewallRule("Allow Loopback", RuleAction.ALLOW, Protocol.ALL, src_ip="127.0.0.1", priority=15),
            FirewallRule("Block All Incoming", RuleAction.BLOCK, Protocol.ALL, priority=1),
        ]
        self.rules.extend(default_rules)
        self.save_config()

    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a new firewall rule"""
        try:
            self.rules.append(rule)
            self.rules.sort(key=lambda r: r.priority, reverse=True)
            self.save_config()
            self.logger.info(f"Added rule: {rule.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add rule: {e}")
            return False

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a firewall rule by name"""
        try:
            self.rules = [r for r in self.rules if r.name != rule_name]
            self.save_config()
            self.logger.info(f"Removed rule: {rule_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to remove rule: {e}")
            return False

    def get_rules(self) -> List[FirewallRule]:
        """Get all firewall rules"""
        return self.rules.copy()

    def update_rule(self, old_name: str, new_rule: FirewallRule) -> bool:
        """Update an existing rule"""
        try:
            for i, rule in enumerate(self.rules):
                if rule.name == old_name:
                    self.rules[i] = new_rule
                    self.rules.sort(key=lambda r: r.priority, reverse=True)
                    self.save_config()
                    self.logger.info(f"Updated rule: {old_name} -> {new_rule.name}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to update rule: {e}")
            return False

    def process_packet(self, packet):
        """Process a single packet through the firewall rules"""
        if not packet.haslayer(IP):
            return

        # Extract packet information
        packet_info = self._extract_packet_info(packet)
        self.total_packets += 1

        # Find matching rule
        action = RuleAction.ALLOW  # Default action
        matched_rule = None
        
        for rule in self.rules:
            if rule.matches_packet(packet_info):
                action = rule.action
                matched_rule = rule
                break

        # Apply action
        if action == RuleAction.BLOCK:
            self.blocked_packets += 1
            self._log_packet(packet_info, "BLOCKED", matched_rule)
        elif action == RuleAction.ALLOW:
            self.allowed_packets += 1
            # Only log allowed packets if explicitly set to log
            if matched_rule and matched_rule.action == RuleAction.LOG:
                self._log_packet(packet_info, "ALLOWED", matched_rule)
        
        # Notify callbacks
        self._notify_callbacks(packet_info, action.value, matched_rule)

    def _extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from a packet"""
        info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'unknown',
            'src_port': None,
            'dst_port': None
        }

        if packet.haslayer(TCP):
            info['protocol'] = 'tcp'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            info['protocol'] = 'udp'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
        elif packet.haslayer(ICMP):
            info['protocol'] = 'icmp'

        return info

    def _log_packet(self, packet_info: Dict, action: str, rule: Optional[FirewallRule]):
        """Log a packet"""
        log_entry = PacketLog(
            timestamp=datetime.now().isoformat(),
            action=action,
            src_ip=packet_info['src_ip'],
            dst_ip=packet_info['dst_ip'],
            protocol=packet_info['protocol'],
            src_port=packet_info.get('src_port'),
            dst_port=packet_info.get('dst_port'),
            rule_name=rule.name if rule else None
        )
        
        self.packet_logs.append(log_entry)
        
        # Keep only last 1000 logs to prevent memory issues
        if len(self.packet_logs) > 1000:
            self.packet_logs = self.packet_logs[-1000:]
            
        self.logger.info(f"{action}: {packet_info['src_ip']} -> {packet_info['dst_ip']} ({packet_info['protocol']})")

    def start_monitoring(self, interface: Optional[str] = None):
        """Start packet monitoring"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot start monitoring.")
            return False

        if self.is_running:
            self.logger.warning("Firewall is already running")
            return False

        try:
            self.is_running = True
            self.logger.info("Starting firewall monitoring...")
            
            # Start sniffing in a separate thread
            self.sniff_thread = threading.Thread(
                target=self._sniff_packets,
                args=(interface,),
                daemon=True
            )
            self.sniff_thread.start()
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            self.is_running = False
            return False

    def stop_monitoring(self):
        """Stop packet monitoring"""
        self.is_running = False
        self.logger.info("Stopping firewall monitoring...")
        
        if self.sniff_thread and self.sniff_thread.is_alive():
            # Note: scapy's sniff function doesn't have a clean stop mechanism
            # In a production environment, you'd want to implement proper thread stopping
            pass

    def _sniff_packets(self, interface: Optional[str]):
        """Sniff packets in a separate thread"""
        try:
            # Get available interfaces
            interfaces = get_if_list() if interface is None else [interface]
            
            sniff(
                iface=interface,
                prn=self.process_packet,
                filter="ip",  # Only capture IP packets
                store=0,      # Don't store packets in memory
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Error in packet sniffing: {e}")
            self.is_running = False

    def get_statistics(self) -> Dict:
        """Get firewall statistics"""
        return {
            'total_packets': self.total_packets,
            'blocked_packets': self.blocked_packets,
            'allowed_packets': self.allowed_packets,
            'active_rules': len([r for r in self.rules if r.enabled]),
            'total_rules': len(self.rules),
            'logs_count': len(self.packet_logs)
        }

    def get_recent_logs(self, limit: int = 50) -> List[PacketLog]:
        """Get recent packet logs"""
        return self.packet_logs[-limit:]

    def clear_logs(self):
        """Clear all packet logs"""
        self.packet_logs.clear()
        self.blocked_packets = 0
        self.allowed_packets = 0
        self.total_packets = 0

    def add_callback(self, callback: Callable):
        """Add a callback function to be called when packets are processed"""
        self.callbacks.append(callback)

    def _notify_callbacks(self, packet_info: Dict, action: str, rule: Optional[FirewallRule]):
        """Notify all registered callbacks"""
        for callback in self.callbacks:
            try:
                callback(packet_info, action, rule)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                'rules': [asdict(rule) for rule in self.rules]
            }
            # Convert enums to strings
            for rule_dict in config['rules']:
                rule_dict['action'] = rule_dict['action'].value if isinstance(rule_dict['action'], RuleAction) else rule_dict['action']
                rule_dict['protocol'] = rule_dict['protocol'].value if isinstance(rule_dict['protocol'], Protocol) else rule_dict['protocol']
                
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")

    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            self.rules = []
            for rule_dict in config.get('rules', []):
                # Convert strings back to enums
                rule_dict['action'] = RuleAction(rule_dict['action'])
                rule_dict['protocol'] = Protocol(rule_dict['protocol'])
                rule = FirewallRule(**rule_dict)
                self.rules.append(rule)
                
            self.rules.sort(key=lambda r: r.priority, reverse=True)
            
        except FileNotFoundError:
            self.logger.info("Config file not found, starting with empty configuration")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")

# Example usage
if __name__ == "__main__":
    # Create firewall engine
    firewall = FirewallEngine()
    
    # Add a custom rule
    custom_rule = FirewallRule(
        name="Block Suspicious Port",
        action=RuleAction.BLOCK,
        protocol=Protocol.TCP,
        dst_port=1337,
        priority=20
    )
    firewall.add_rule(custom_rule)
    
    # Start monitoring (requires root privileges on Linux)
    print("Starting firewall... (Press Ctrl+C to stop)")
    try:
        if firewall.start_monitoring():
            while True:
                time.sleep(1)
                stats = firewall.get_statistics()
                print(f"Packets: {stats['total_packets']}, Blocked: {stats['blocked_packets']}, Allowed: {stats['allowed_packets']}")
    except KeyboardInterrupt:
        firewall.stop_monitoring()
        print("\nFirewall stopped.")
