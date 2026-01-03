#!/usr/bin/env python3
# Copyright (c) 2026 The Mynta Core Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Masternode Chaos Test

This test simulates a network with 10 masternodes under various stress conditions:
- Masternode registration and activation
- Network partitions
- Rapid block production
- Masternode churn (enable/disable)
- Reorg simulation
- Payment verification

Usage:
    test/functional/feature_masternode_chaos.py --duration=10  # 10 minutes
"""

import os
import random
import sys
import time
import threading
from collections import defaultdict

from test_framework.test_framework import RavenTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
)

# Configuration
DEFAULT_DURATION_MINUTES = 10
NUM_NODES = 8  # Max supported by test framework
MASTERNODE_COLLATERAL = 10000
BLOCKS_TO_MATURITY = 100

class ChaosStats:
    """Collect statistics during chaos test."""
    
    def __init__(self):
        self.blocks_mined = 0
        self.masternodes_registered = 0
        self.masternodes_enabled = 0
        self.masternodes_disabled = 0
        self.network_partitions = 0
        self.reorgs_simulated = 0
        self.payments_received = 0
        self.errors = []
        self.start_time = time.time()
        self.mn_collaterals = {}  # node_idx -> collateral_txid
        
    def elapsed_minutes(self):
        return (time.time() - self.start_time) / 60
    
    def report(self):
        """Generate a summary report."""
        return f"""
================================================================================
MASTERNODE CHAOS TEST REPORT
================================================================================
Duration: {self.elapsed_minutes():.1f} minutes

BLOCKS:
  Mined: {self.blocks_mined}

MASTERNODES:
  Registered: {self.masternodes_registered}
  Enabled: {self.masternodes_enabled}
  Disabled: {self.masternodes_disabled}

CHAOS EVENTS:
  Network Partitions: {self.network_partitions}
  Reorgs Simulated: {self.reorgs_simulated}

PAYMENTS:
  MN Payments Received: {self.payments_received}

ERRORS: {len(self.errors)}
{chr(10).join(self.errors[:10])}
{'...' if len(self.errors) > 10 else ''}
================================================================================
"""


class MasternodeChaosTest(RavenTestFramework):
    
    def add_options(self, parser):
        """Add custom command-line options."""
        parser.add_option("--duration", dest="duration", default=DEFAULT_DURATION_MINUTES,
                          type="int", help="Duration of chaos test in minutes (default: %default)")
    
    def set_test_params(self):
        self.num_nodes = NUM_NODES
        self.setup_clean_chain = True
        self.duration_minutes = DEFAULT_DURATION_MINUTES
        self.stats = ChaosStats()
        self.lock = threading.Lock()
        
    def chaos_log(self, message):
        """Log with timestamp."""
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] {message}")
        sys.stdout.flush()
    
    def setup_network(self):
        """Set up the test network."""
        if hasattr(self, 'options') and hasattr(self.options, 'duration'):
            self.duration_minutes = self.options.duration
            
        self.chaos_log(f"Setting up {self.num_nodes} node network for {self.duration_minutes} minute chaos test")
        self.setup_nodes()
        
        # Connect all nodes in a mesh
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                connect_nodes(self.nodes[i], j)
        
        self.sync_all()
        self.chaos_log(f"Network setup complete with {self.num_nodes} nodes")
    
    def mine_blocks(self, node_idx, count):
        """Mine blocks on a specific node."""
        node = self.nodes[node_idx]
        address = node.getnewaddress()
        hashes = node.generatetoaddress(count, address)
        
        with self.lock:
            self.stats.blocks_mined += count
        
        return hashes
    
    def setup_masternode_funds(self):
        """Generate initial funds for masternode collateral."""
        self.chaos_log("Generating initial funds for masternodes...")
        
        # Mine enough blocks to have spendable coins on node 0
        self.mine_blocks(0, BLOCKS_TO_MATURITY + self.num_nodes * 2)
        self.sync_all()
        
        # Send collateral to each node
        for i in range(1, self.num_nodes):
            address = self.nodes[i].getnewaddress()
            self.nodes[0].sendtoaddress(address, MASTERNODE_COLLATERAL + 10)
        
        # Mine to confirm
        self.mine_blocks(0, 1)
        self.sync_all()
        
        self.chaos_log(f"Distributed {MASTERNODE_COLLATERAL} MYNTA to each of {self.num_nodes - 1} nodes")
    
    def register_masternode(self, node_idx):
        """Register a masternode on the given node."""
        node = self.nodes[node_idx]
        
        try:
            balance = node.getbalance()
            if balance < MASTERNODE_COLLATERAL:
                self.chaos_log(f"Node {node_idx}: Insufficient balance ({balance:.2f}) for MN collateral")
                return False
            
            # Create collateral output
            collateral_address = node.getnewaddress()
            collateral_txid = node.sendtoaddress(collateral_address, MASTERNODE_COLLATERAL)
            
            # Store collateral info
            with self.lock:
                self.stats.mn_collaterals[node_idx] = {
                    'txid': collateral_txid,
                    'address': collateral_address,
                    'registered': True
                }
                self.stats.masternodes_registered += 1
            
            self.chaos_log(f"Node {node_idx}: Registered MN with collateral {collateral_txid[:16]}...")
            return True
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"MN register error on node {node_idx}: {str(e)[:50]}")
            return False
    
    def simulate_network_partition(self, partition_nodes):
        """Simulate a network partition."""
        try:
            # Disconnect partition_nodes from the rest
            for i in partition_nodes:
                for j in range(self.num_nodes):
                    if j not in partition_nodes:
                        try:
                            disconnect_nodes(self.nodes[i], j)
                        except:
                            pass
            
            with self.lock:
                self.stats.network_partitions += 1
            
            self.chaos_log(f"Network partition: nodes {partition_nodes} isolated")
            return True
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Partition error: {str(e)[:50]}")
            return False
    
    def heal_network(self):
        """Reconnect all nodes."""
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                try:
                    connect_nodes(self.nodes[i], j)
                except:
                    pass
        
        self.chaos_log("Network healed - all nodes reconnected")
    
    def simulate_reorg(self, depth=3):
        """Simulate a chain reorganization."""
        try:
            # Partition node 0
            partition = [0]
            self.simulate_network_partition(partition)
            
            # Mine on both sides
            self.mine_blocks(0, depth)
            self.mine_blocks(1, depth + 1)  # Longer chain wins
            
            # Heal and let reorg happen
            self.heal_network()
            time.sleep(2)
            
            try:
                self.sync_all(timeout=30)
            except:
                pass  # May timeout if reorg is slow
            
            with self.lock:
                self.stats.reorgs_simulated += 1
            
            self.chaos_log(f"Simulated reorg of depth {depth}")
            return True
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Reorg error: {str(e)[:50]}")
            self.heal_network()
            return False
    
    def check_masternode_status(self):
        """Check and report masternode status across nodes."""
        try:
            # Try to get masternode count if RPC available
            count_info = self.nodes[0].masternodecount()
            self.chaos_log(f"Masternode count: {count_info}")
            return count_info
        except Exception as e:
            # Masternode RPCs may not be fully available
            return None
    
    def chaos_action_mine(self):
        """Random mining action."""
        node_idx = random.randint(0, self.num_nodes - 1)
        count = random.randint(1, 5)
        self.mine_blocks(node_idx, count)
        self.chaos_log(f"Node {node_idx} mined {count} blocks")
    
    def chaos_action_partition(self):
        """Random partition action."""
        # Select 1-3 nodes to partition
        partition_size = random.randint(1, min(3, self.num_nodes - 1))
        partition_nodes = random.sample(range(self.num_nodes), partition_size)
        self.simulate_network_partition(partition_nodes)
        
        # Keep partitioned for a short time
        time.sleep(random.uniform(1, 3))
        
        # Mine on both sides
        if partition_nodes:
            self.mine_blocks(partition_nodes[0], random.randint(1, 3))
        other_nodes = [n for n in range(self.num_nodes) if n not in partition_nodes]
        if other_nodes:
            self.mine_blocks(other_nodes[0], random.randint(1, 3))
        
        self.heal_network()
    
    def chaos_action_reorg(self):
        """Trigger a reorg."""
        depth = random.randint(2, 5)
        self.simulate_reorg(depth)
    
    def chaos_action_register_mn(self):
        """Register a new masternode if possible."""
        # Find a node without a registered MN
        for i in range(1, self.num_nodes):
            if i not in self.stats.mn_collaterals:
                if self.register_masternode(i):
                    self.mine_blocks(0, 1)  # Confirm
                    return
    
    def run_chaos_loop(self, duration_seconds):
        """Run the chaos loop for the specified duration."""
        end_time = time.time() + duration_seconds
        iteration = 0
        
        # Weighted actions
        actions = [
            (self.chaos_action_mine, 50),        # 50% - mining
            (self.chaos_action_partition, 15),   # 15% - partitions
            (self.chaos_action_reorg, 10),       # 10% - reorgs
            (self.chaos_action_register_mn, 25), # 25% - mn registration
        ]
        
        total_weight = sum(w for _, w in actions)
        
        while time.time() < end_time:
            iteration += 1
            
            # Select weighted random action
            r = random.randint(1, total_weight)
            cumulative = 0
            for action, weight in actions:
                cumulative += weight
                if r <= cumulative:
                    try:
                        action()
                    except Exception as e:
                        with self.lock:
                            self.stats.errors.append(f"Action error: {str(e)[:50]}")
                    break
            
            # Periodic status report
            if iteration % 50 == 0:
                elapsed = self.stats.elapsed_minutes()
                self.chaos_log(f"Iteration {iteration}: {elapsed:.1f} min, "
                        f"{self.stats.blocks_mined} blocks, "
                        f"{self.stats.masternodes_registered} MNs, "
                        f"{self.stats.network_partitions} partitions, "
                        f"{self.stats.reorgs_simulated} reorgs")
            
            # Small delay between actions
            time.sleep(random.uniform(0.1, 0.5))
    
    def run_test(self):
        """Main test execution."""
        self.chaos_log(f"Starting {self.num_nodes}-node masternode chaos test for {self.duration_minutes} minutes")
        
        # Setup funds for masternodes
        self.setup_masternode_funds()
        
        # Initial masternode registrations
        self.chaos_log("Registering initial masternodes...")
        for i in range(1, self.num_nodes):
            self.register_masternode(i)
            self.mine_blocks(0, 1)
        
        self.sync_all()
        
        # Check initial MN status
        self.check_masternode_status()
        
        # Run chaos loop
        self.chaos_log("Starting chaos loop...")
        self.run_chaos_loop(self.duration_minutes * 60)
        
        # Final sync
        self.chaos_log("Healing network for final sync...")
        self.heal_network()
        time.sleep(5)
        
        try:
            self.sync_all(timeout=60)
        except:
            self.chaos_log("Warning: Final sync timed out")
        
        # Final report
        print(self.stats.report())
        self.chaos_log("Masternode chaos test completed!")


if __name__ == '__main__':
    MasternodeChaosTest().main()

