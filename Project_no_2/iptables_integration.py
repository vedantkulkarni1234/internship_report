#!/usr/bin/env python3
"""
iptables Integration Module
Provides system-level firewall rule enforcement using iptables (Linux only).
"""

import subprocess
import os
import logging
from typing import List, Optional
from firewall_core import FirewallRule, RuleAction, Protocol

class IptablesManager:
    """Manages iptables rules for system-level enforcement"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.chain_name = "PERSONAL_FIREWALL"
        self.backup_file = "/tmp/iptables_backup.rules"
        
        # Check if we're on Linux and have root privileges
        if not self._is_linux():
            raise RuntimeError("iptables integration is only supported on Linux")
            
        if not self._has_root():
            raise RuntimeError("Root privileges required for iptables integration")

    def _is_linux(self) -> bool:
        """Check if running on Linux"""
        return os.name == 'posix' and 'linux' in os.sys.platform.lower()

    def _has_root(self) -> bool:
        """Check if running with root privileges"""
        return os.geteuid() == 0

    def _run_command(self, command: List[str]) -> tuple:
        """Run a command and return (success, output, error)"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def backup_current_rules(self) -> bool:
        """Backup current iptables rules"""
        try:
            success, output, error = self._run_command(['iptables-save'])
            if success:
                with open(self.backup_file, 'w') as f:
                    f.write(output)
                self.logger.info(f"iptables rules backed up to {self.backup_file}")
                return True
            else:
                self.logger.error(f"Failed to backup iptables rules: {error}")
                return False
        except Exception as e:
            self.logger.error(f"Error backing up iptables rules: {e}")
            return False

    def restore_backup(self) -> bool:
        """Restore iptables rules from backup"""
        try:
            if os.path.exists(self.backup_file):
                success, output, error = self._run_command(['iptables-restore', self.backup_file])
                if success:
                    self.logger.info("iptables rules restored from backup")
                    return True
                else:
                    self.logger.error(f"Failed to restore iptables rules: {error}")
                    return False
            else:
                self.logger.warning("No backup file found")
                return False
        except Exception as e:
            self.logger.error(f"Error restoring iptables rules: {e}")
            return False

    def create_chain(self) -> bool:
        """Create custom chain for personal firewall rules"""
        # First, check if chain already exists
        success, output, error = self._run_command(['iptables', '-L', self.chain_name])
        if success:
            self.logger.info(f"Chain {self.chain_name} already exists")
            return True

        # Create new chain
        success, output, error = self._run_command(['iptables', '-N', self.chain_name])
        if not success:
            self.logger.error(f"Failed to create chain {self.chain_name}: {error}")
            return False

        # Insert jump to our chain at the beginning of INPUT and OUTPUT chains
        commands = [
            ['iptables', '-I', 'INPUT', '1', '-j', self.chain_name],
            ['iptables', '-I', 'OUTPUT', '1', '-j', self.chain_name]
        ]

        for cmd in commands:
            success, output, error = self._run_command(cmd)
            if not success:
                self.logger.error(f"Failed to add jump rule: {error}")
                # Try to clean up
                self.remove_chain()
                return False

        self.logger.info(f"Created chain {self.chain_name} and added jump rules")
        return True

    def remove_chain(self) -> bool:
        """Remove custom chain and all associated rules"""
        success = True

        # Remove jump rules from INPUT and OUTPUT chains
        jump_rules = [
            ['iptables', '-D', 'INPUT', '-j', self.chain_name],
            ['iptables', '-D', 'OUTPUT', '-j', self.chain_name]
        ]

        for cmd in jump_rules:
            cmd_success, output, error = self._run_command(cmd)
            if not cmd_success and "No chain/target/match by that name" not in error:
                self.logger.warning(f"Failed to remove jump rule: {error}")

        # Flush the chain
        cmd_success, output, error = self._run_command(['iptables', '-F', self.chain_name])
        if not cmd_success:
            self.logger.warning(f"Failed to flush chain {self.chain_name}: {error}")
            success = False

        # Delete the chain
        cmd_success, output, error = self._run_command(['iptables', '-X', self.chain_name])
        if not cmd_success:
            self.logger.warning(f"Failed to delete chain {self.chain_name}: {error}")
            success = False

        if success:
            self.logger.info(f"Removed chain {self.chain_name}")
        return success

    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule to iptables"""
        if not rule.enabled:
            return True  # Skip disabled rules

        iptables_cmd = self._convert_rule_to_iptables(rule)
        if not iptables_cmd:
            return False

        success, output, error = self._run_command(iptables_cmd)
        if success:
            self.logger.info(f"Added iptables rule: {rule.name}")
            return True
        else:
            self.logger.error(f"Failed to add iptables rule {rule.name}: {error}")
            return False

    def remove_rule(self, rule: FirewallRule) -> bool:
        """Remove a firewall rule from iptables"""
        iptables_cmd = self._convert_rule_to_iptables(rule, delete=True)
        if not iptables_cmd:
            return False

        success, output, error = self._run_command(iptables_cmd)
        if success:
            self.logger.info(f"Removed iptables rule: {rule.name}")
            return True
        else:
            # Rule might not exist, which is okay
            if "No chain/target/match by that name" in error or "Bad rule" in error:
                return True
            self.logger.error(f"Failed to remove iptables rule {rule.name}: {error}")
            return False

    def sync_rules(self, rules: List[FirewallRule]) -> bool:
        """Synchronize all firewall rules with iptables"""
        # Clear existing rules in our chain
        success, output, error = self._run_command(['iptables', '-F', self.chain_name])
        if not success:
            self.logger.error(f"Failed to flush chain {self.chain_name}: {error}")
            return False

        # Add all enabled rules
        success_count = 0
        for rule in rules:
            if rule.enabled and self.add_rule(rule):
                success_count += 1

        self.logger.info(f"Synchronized {success_count}/{len(rules)} rules with iptables")
        return success_count == len([r for r in rules if r.enabled])

    def _convert_rule_to_iptables(self, rule: FirewallRule, delete: bool = False) -> Optional[List[str]]:
        """Convert a FirewallRule to iptables command"""
        cmd = ['iptables']
        
        # Add or delete rule
        cmd.append('-D' if delete else '-A')
        cmd.append(self.chain_name)

        # Protocol
        if rule.protocol != Protocol.ALL:
            cmd.extend(['-p', rule.protocol.value])

        # Source IP
        if rule.src_ip:
            if '*' in rule.src_ip:
                # Convert wildcard format to CIDR if possible
                cidr = self._wildcard_to_cidr(rule.src_ip)
                if cidr:
                    cmd.extend(['-s', cidr])
            else:
                cmd.extend(['-s', rule.src_ip])

        # Destination IP
        if rule.dst_ip:
            if '*' in rule.dst_ip:
                cidr = self._wildcard_to_cidr(rule.dst_ip)
                if cidr:
                    cmd.extend(['-d', cidr])
            else:
                cmd.extend(['-d', rule.dst_ip])

        # Source port
        if rule.src_port and rule.protocol in [Protocol.TCP, Protocol.UDP]:
            cmd.extend(['--sport', str(rule.src_port)])

        # Destination port
        if rule.dst_port and rule.protocol in [Protocol.TCP, Protocol.UDP]:
            cmd.extend(['--dport', str(rule.dst_port)])

        # Action
        if rule.action == RuleAction.BLOCK:
            cmd.extend(['-j', 'DROP'])
        elif rule.action == RuleAction.ALLOW:
            cmd.extend(['-j', 'ACCEPT'])
        elif rule.action == RuleAction.LOG:
            # For LOG action, we need to create two rules: LOG and ACCEPT
            log_cmd = cmd + ['-j', 'LOG', '--log-prefix', f"FW:{rule.name}:"]
            accept_cmd = cmd + ['-j', 'ACCEPT']
            
            if delete:
                # For deletion, we need to remove both rules
                # This is simplified - in practice, you'd track both rules
                return cmd + ['-j', 'LOG']
            else:
                # Add LOG rule first
                log_success, _, log_error = self._run_command(log_cmd)
                if not log_success:
                    self.logger.error(f"Failed to add LOG rule: {log_error}")
                return accept_cmd
        else:
            self.logger.error(f"Unknown action: {rule.action}")
            return None

        # Add comment to identify our rules
        cmd.extend(['-m', 'comment', '--comment', f"PersonalFW:{rule.name}"])

        return cmd

    def _wildcard_to_cidr(self, wildcard: str) -> Optional[str]:
        """Convert wildcard IP format to CIDR notation where possible"""
        parts = wildcard.split('.')
        if len(parts) != 4:
            return None

        # Simple conversions
        if wildcard == "192.168.*.*":
            return "192.168.0.0/16"
        elif wildcard == "10.*.*.*":
            return "10.0.0.0/8"
        elif wildcard == "172.16.*.*":
            return "172.16.0.0/12"
        elif wildcard.endswith("*.*.*"):
            # Class A network
            return f"{parts[0]}.0.0.0/8"
        elif wildcard.endswith("*.*"):
            # Class B network
            return f"{parts[0]}.{parts[1]}.0.0/16"
        elif wildcard.endswith("*"):
            # Class C network
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            # Can't convert complex wildcards
            return None

    def get_current_rules(self) -> List[str]:
        """Get current iptables rules in our chain"""
        success, output, error = self._run_command(['iptables', '-L', self.chain_name, '-n', '--line-numbers'])
        if success:
            return output.split('\n')
        else:
            return []

    def list_rules(self) -> str:
        """Get formatted list of current iptables rules"""
        rules = self.get_current_rules()
        if rules:
            return '\n'.join(rules)
        else:
            return "No rules found or chain doesn't exist"

class SystemFirewallIntegration:
    """High-level interface for system firewall integration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.iptables_mgr = None
        
        try:
            self.iptables_mgr = IptablesManager()
            self.available = True
        except RuntimeError as e:
            self.logger.warning(f"System firewall integration not available: {e}")
            self.available = False

    def is_available(self) -> bool:
        """Check if system integration is available"""
        return self.available

    def install_rules(self, rules: List[FirewallRule]) -> bool:
        """Install firewall rules at system level"""
        if not self.available:
            self.logger.error("System firewall integration not available")
            return False

        try:
            # Backup current rules
            if not self.iptables_mgr.backup_current_rules():
                self.logger.warning("Failed to backup current iptables rules")

            # Create our custom chain
            if not self.iptables_mgr.create_chain():
                return False

            # Synchronize rules
            return self.iptables_mgr.sync_rules(rules)

        except Exception as e:
            self.logger.error(f"Failed to install system firewall rules: {e}")
            return False

    def uninstall_rules(self) -> bool:
        """Remove all system-level firewall rules"""
        if not self.available:
            self.logger.error("System firewall integration not available")
            return False

        try:
            return self.iptables_mgr.remove_chain()
        except Exception as e:
            self.logger.error(f"Failed to uninstall system firewall rules: {e}")
            return False

    def update_rules(self, rules: List[FirewallRule]) -> bool:
        """Update system-level firewall rules"""
        if not self.available:
            return False

        try:
            return self.iptables_mgr.sync_rules(rules)
        except Exception as e:
            self.logger.error(f"Failed to update system firewall rules: {e}")
            return False

    def restore_backup(self) -> bool:
        """Restore original iptables configuration"""
        if not self.available:
            return False

        try:
            return self.iptables_mgr.restore_backup()
        except Exception as e:
            self.logger.error(f"Failed to restore backup: {e}")
            return False

    def get_status(self) -> dict:
        """Get status of system firewall integration"""
        if not self.available:
            return {
                'available': False,
                'installed': False,
                'rules_count': 0,
                'error': 'System integration not available'
            }

        try:
            rules = self.iptables_mgr.get_current_rules()
            return {
                'available': True,
                'installed': len(rules) > 2,  # Header lines don't count
                'rules_count': max(0, len(rules) - 2),
                'chain_name': self.iptables_mgr.chain_name
            }
        except Exception as e:
            return {
                'available': True,
                'installed': False,
                'rules_count': 0,
                'error': str(e)
            }

# Example usage and testing
def test_iptables_integration():
    """Test iptables integration functionality"""
    from firewall_core import FirewallRule, RuleAction, Protocol
    
    print("Testing iptables integration...")
    
    try:
        # Create system integration
        sys_fw = SystemFirewallIntegration()
        
        if not sys_fw.is_available():
            print("System firewall integration not available")
            return
            
        print("System firewall integration available")
        
        # Create test rules
        test_rules = [
            FirewallRule(
                name="Block SSH",
                action=RuleAction.BLOCK,
                protocol=Protocol.TCP,
                dst_port=22,
                priority=10
            ),
            FirewallRule(
                name="Allow HTTP",
                action=RuleAction.ALLOW,
                protocol=Protocol.TCP,
                dst_port=80,
                priority=5
            ),
            FirewallRule(
                name="Log ICMP",
                action=RuleAction.LOG,
                protocol=Protocol.ICMP,
                priority=1
            )
        ]
        
        # Install rules
        print("Installing test rules...")
        if sys_fw.install_rules(test_rules):
            print("Rules installed successfully")
            
            # Get status
            status = sys_fw.get_status()
            print(f"Status: {status}")
            
            # Wait for user input
            input("Press Enter to uninstall rules...")
            
            # Uninstall rules
            if sys_fw.uninstall_rules():
                print("Rules uninstalled successfully")
            else:
                print("Failed to uninstall rules")
        else:
            print("Failed to install rules")
            
    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    test_iptables_integration()
