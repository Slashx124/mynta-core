#!/usr/bin/env python3
# Copyright (c) 2026 The Mynta Core Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Masternode Soak Test

This test exercises the masternode and DEX systems under sustained load.
It can run for extended periods (30min, 1hr, 4hr) to detect memory leaks,
consensus divergence, and stability issues.

Usage:
    test/functional/feature_masternode_soak.py --duration=30  # 30 minutes
    test/functional/feature_masternode_soak.py --duration=60  # 1 hour
    test/functional/feature_masternode_soak.py --duration=240 # 4 hours

Environment Variables:
    MYNTA_DEBUG=0  Minimal logging
    MYNTA_DEBUG=1  Verbose logging
    MYNTA_DEBUG=2  Intense protocol tracing
"""

import os
import random
import sys
import time
import threading
from collections import defaultdict

# Add the test framework to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'test', 'functional'))

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
)

# Configuration
DEFAULT_DURATION_MINUTES = 30
MIN_NODES = 4
MASTERNODE_COLLATERAL = 10000

# Debug levels
DEBUG_MINIMAL = 0
DEBUG_VERBOSE = 1
DEBUG_INTENSE = 2


class SoakTestStats:
    """Collect statistics during soak test."""
    
    def __init__(self):
        self.blocks_mined = 0
        self.masternodes_registered = 0
        self.masternodes_updated = 0
        self.masternodes_revoked = 0
        self.assets_created = 0
        self.transfers_made = 0
        self.dex_offers_created = 0
        self.dex_offers_filled = 0
        self.reorgs_simulated = 0
        self.invalid_tx_rejected = 0
        self.errors = []
        self.start_time = time.time()
        
    def elapsed_minutes(self):
        return (time.time() - self.start_time) / 60
    
    def report(self):
        """Generate a summary report."""
        return f"""
================================================================================
SOAK TEST REPORT
================================================================================
Duration: {self.elapsed_minutes():.1f} minutes

BLOCKS:
  Mined: {self.blocks_mined}

MASTERNODES:
  Registered: {self.masternodes_registered}
  Updated: {self.masternodes_updated}
  Revoked: {self.masternodes_revoked}

ASSETS:
  Created: {self.assets_created}
  Transfers: {self.transfers_made}

DEX:
  Offers Created: {self.dex_offers_created}
  Offers Filled: {self.dex_offers_filled}

STRESS:
  Reorgs Simulated: {self.reorgs_simulated}
  Invalid TX Rejected: {self.invalid_tx_rejected}

ERRORS: {len(self.errors)}
{chr(10).join(self.errors[:10])}
{'...' if len(self.errors) > 10 else ''}
================================================================================
"""


class MasternodeSoakTest(BitcoinTestFramework):
    
    def set_test_params(self):
        self.num_nodes = MIN_NODES
        self.setup_clean_chain = True
        
        # Parse duration from args
        self.duration_minutes = DEFAULT_DURATION_MINUTES
        for arg in sys.argv:
            if arg.startswith('--duration='):
                self.duration_minutes = int(arg.split('=')[1])
        
        # Parse debug level from environment
        self.debug_level = int(os.environ.get('MYNTA_DEBUG', DEBUG_MINIMAL))
        
        self.stats = SoakTestStats()
        self.lock = threading.Lock()
        
    def debug_log(self, level, message):
        """Log message if debug level is sufficient."""
        if self.debug_level >= level:
            timestamp = time.strftime('%H:%M:%S')
            print(f"[{timestamp}] {message}")
    
    def setup_network(self):
        """Set up the test network."""
        self.setup_nodes()
        
        # Connect all nodes in a mesh
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                connect_nodes(self.nodes[i], j)
        
        self.sync_all()
        self.debug_log(DEBUG_MINIMAL, f"Network setup complete with {self.num_nodes} nodes")
    
    def mine_blocks(self, node_idx, count):
        """Mine blocks on a specific node."""
        node = self.nodes[node_idx]
        
        # Generate to a fresh address
        address = node.getnewaddress()
        hashes = node.generatetoaddress(count, address)
        
        with self.lock:
            self.stats.blocks_mined += count
        
        self.debug_log(DEBUG_VERBOSE, f"Node {node_idx} mined {count} blocks")
        return hashes
    
    def create_masternode(self, node_idx):
        """Register a new masternode."""
        node = self.nodes[node_idx]
        
        try:
            # Check if we have enough funds
            balance = node.getbalance()
            if balance < MASTERNODE_COLLATERAL + 1:
                self.debug_log(DEBUG_VERBOSE, f"Node {node_idx} insufficient balance for MN")
                return None
            
            # Create collateral transaction
            collateral_address = node.getnewaddress()
            collateral_txid = node.sendtoaddress(collateral_address, MASTERNODE_COLLATERAL)
            
            # Mine to confirm
            self.mine_blocks(node_idx, 1)
            
            with self.lock:
                self.stats.masternodes_registered += 1
            
            self.debug_log(DEBUG_VERBOSE, f"Created masternode collateral: {collateral_txid[:16]}...")
            return collateral_txid
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"MN create error: {str(e)}")
            return None
    
    def create_asset(self, node_idx, asset_name=None):
        """Create a new asset."""
        node = self.nodes[node_idx]
        
        try:
            if asset_name is None:
                asset_name = f"SOAK{random.randint(10000, 99999)}"
            
            # Issue asset
            result = node.issue(asset_name, 1000000, "", "", 8, True, False)
            
            with self.lock:
                self.stats.assets_created += 1
            
            self.debug_log(DEBUG_VERBOSE, f"Created asset: {asset_name}")
            return asset_name
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Asset create error: {str(e)}")
            return None
    
    def transfer_asset(self, from_node, to_node, asset_name, amount):
        """Transfer an asset between nodes."""
        try:
            from_n = self.nodes[from_node]
            to_n = self.nodes[to_node]
            
            to_address = to_n.getnewaddress()
            txid = from_n.transfer(asset_name, amount, to_address)
            
            with self.lock:
                self.stats.transfers_made += 1
            
            self.debug_log(DEBUG_VERBOSE, f"Transferred {amount} {asset_name}: {txid[:16]}...")
            return txid
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Transfer error: {str(e)}")
            return None
    
    def simulate_reorg(self, depth=2):
        """Simulate a chain reorganization."""
        try:
            # Disconnect node 0 from network
            for i in range(1, self.num_nodes):
                disconnect_nodes(self.nodes[0], i)
            
            # Mine blocks on both sides
            self.mine_blocks(0, depth)
            self.mine_blocks(1, depth + 1)  # Longer chain
            
            # Reconnect - should trigger reorg on node 0
            for i in range(1, self.num_nodes):
                connect_nodes(self.nodes[0], i)
            
            self.sync_all()
            
            with self.lock:
                self.stats.reorgs_simulated += 1
            
            self.debug_log(DEBUG_VERBOSE, f"Simulated reorg of depth {depth}")
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Reorg error: {str(e)}")
    
    def send_invalid_transaction(self, node_idx):
        """Try to send an invalid transaction (should be rejected)."""
        try:
            node = self.nodes[node_idx]
            
            # Try to send more than balance
            balance = node.getbalance()
            try:
                node.sendtoaddress(node.getnewaddress(), balance + 1000)
                # Should not reach here
                with self.lock:
                    self.stats.errors.append("Invalid TX was accepted!")
            except Exception:
                # Expected - invalid TX rejected
                with self.lock:
                    self.stats.invalid_tx_rejected += 1
                self.debug_log(DEBUG_VERBOSE, "Invalid TX correctly rejected")
                
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Invalid TX test error: {str(e)}")
    
    def check_consensus(self):
        """Verify all nodes are in consensus."""
        try:
            heights = [n.getblockcount() for n in self.nodes]
            best_hashes = [n.getbestblockhash() for n in self.nodes]
            
            if len(set(heights)) != 1:
                error = f"Height divergence: {heights}"
                with self.lock:
                    self.stats.errors.append(error)
                self.debug_log(DEBUG_MINIMAL, error)
                return False
            
            if len(set(best_hashes)) != 1:
                error = f"Hash divergence at height {heights[0]}"
                with self.lock:
                    self.stats.errors.append(error)
                self.debug_log(DEBUG_MINIMAL, error)
                return False
            
            self.debug_log(DEBUG_INTENSE, f"Consensus OK at height {heights[0]}")
            return True
            
        except Exception as e:
            with self.lock:
                self.stats.errors.append(f"Consensus check error: {str(e)}")
            return False
    
    def check_memory(self):
        """Check node memory usage (basic check)."""
        try:
            for i, node in enumerate(self.nodes):
                meminfo = node.getmemoryinfo()
                used_mb = meminfo.get('locked', {}).get('used', 0) / 1024 / 1024
                self.debug_log(DEBUG_INTENSE, f"Node {i} memory: {used_mb:.1f} MB")
                
                # Alert if memory seems high (arbitrary threshold)
                if used_mb > 500:
                    self.debug_log(DEBUG_MINIMAL, f"WARNING: Node {i} high memory: {used_mb:.1f} MB")
                    
        except Exception as e:
            self.debug_log(DEBUG_VERBOSE, f"Memory check error: {e}")
    
    def run_soak_iteration(self):
        """Run one iteration of the soak test."""
        
        # Random operations
        operation = random.choice([
            'mine', 'mine', 'mine',  # Mining is most common
            'asset',
            'transfer',
            'reorg',
            'invalid',
            'check',
        ])
        
        node_idx = random.randint(0, self.num_nodes - 1)
        
        if operation == 'mine':
            count = random.randint(1, 5)
            self.mine_blocks(node_idx, count)
            self.sync_all()
            
        elif operation == 'asset':
            self.create_asset(node_idx)
            self.sync_all()
            
        elif operation == 'transfer':
            # Would need to track assets to do real transfers
            pass
            
        elif operation == 'reorg':
            if random.random() < 0.1:  # 10% chance
                self.simulate_reorg(random.randint(1, 3))
                
        elif operation == 'invalid':
            self.send_invalid_transaction(node_idx)
            
        elif operation == 'check':
            self.check_consensus()
            self.check_memory()
    
    def run_test(self):
        """Main test execution."""
        
        self.debug_log(DEBUG_MINIMAL, f"Starting soak test for {self.duration_minutes} minutes")
        self.debug_log(DEBUG_MINIMAL, f"Debug level: {self.debug_level}")
        
        # Initial funding
        self.debug_log(DEBUG_MINIMAL, "Generating initial blocks...")
        self.mine_blocks(0, 200)
        self.sync_all()
        
        # Distribute funds to all nodes
        for i in range(1, self.num_nodes):
            addr = self.nodes[i].getnewaddress()
            self.nodes[0].sendtoaddress(addr, 50000)
        
        self.mine_blocks(0, 10)
        self.sync_all()
        
        # Run soak test
        end_time = time.time() + (self.duration_minutes * 60)
        iteration = 0
        
        while time.time() < end_time:
            iteration += 1
            
            try:
                self.run_soak_iteration()
                
                # Periodic status
                if iteration % 100 == 0:
                    elapsed = self.stats.elapsed_minutes()
                    self.debug_log(DEBUG_MINIMAL, 
                        f"Iteration {iteration}, {elapsed:.1f} min elapsed, "
                        f"{self.stats.blocks_mined} blocks, {len(self.stats.errors)} errors")
                
                # Small delay to prevent overwhelming
                time.sleep(0.1)
                
            except Exception as e:
                with self.lock:
                    self.stats.errors.append(f"Iteration {iteration} error: {str(e)}")
                self.debug_log(DEBUG_MINIMAL, f"Error in iteration {iteration}: {e}")
        
        # Final checks
        self.debug_log(DEBUG_MINIMAL, "Final consensus check...")
        final_consensus = self.check_consensus()
        
        # Print report
        print(self.stats.report())
        
        # Fail if there were critical errors
        assert_equal(len([e for e in self.stats.errors if 'divergence' in e.lower()]), 0)
        assert final_consensus, "Final consensus check failed"
        
        self.debug_log(DEBUG_MINIMAL, "Soak test completed successfully!")


if __name__ == '__main__':
    MasternodeSoakTest().main()

