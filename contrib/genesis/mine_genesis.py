#!/usr/bin/env python3
"""
Mynta Genesis Block Mining Tool

This script generates the commands and parameters needed to mine a new genesis block.
The actual mining is done by the daemon with special genesis mining code.

Usage:
    python3 mine_genesis.py --network mainnet --timestamp "Mynta Genesis 01/Jan/2026"

For KawPoW genesis blocks, we set nKAWPOWActivationTime=0 so that KawPoW is used
from the very first block (genesis). The daemon's internal mining code will be used.

Output: Genesis parameters to insert into chainparams.cpp
"""

import argparse
import time
import hashlib

def main():
    parser = argparse.ArgumentParser(description='Mynta Genesis Block Parameter Generator')
    parser.add_argument('--network', choices=['mainnet', 'testnet', 'regtest'], required=True)
    parser.add_argument('--timestamp', type=str, required=True, help='pszTimestamp string')
    parser.add_argument('--time', type=int, default=int(time.time()), help='Genesis nTime (unix timestamp)')
    parser.add_argument('--bits', type=str, help='nBits in hex (default varies by network)')
    parser.add_argument('--reward', type=int, default=5000, help='Block reward in coins')
    
    args = parser.parse_args()
    
    # Default difficulty targets by network
    default_bits = {
        'mainnet': '0x1e00ffff',   # Same as original Ravencoin mainnet
        'testnet': '0x1e00ffff',   # Same as original Ravencoin testnet  
        'regtest': '0x207fffff',   # Very easy for regtest
    }
    
    bits = args.bits if args.bits else default_bits[args.network]
    
    print(f"""
================================================================================
                    MYNTA GENESIS BLOCK PARAMETERS
================================================================================

Network:      {args.network}
Timestamp:    "{args.timestamp}"
nTime:        {args.time}
nBits:        {bits}
Reward:       {args.reward} COIN

To mine this genesis block:

1. Update chainparams.cpp with these parameters in CreateGenesisBlock():
   - pszTimestamp = "{args.timestamp}"
   - nTime = {args.time}
   - nBits = {bits}
   - nNonce = 0 (will be mined)
   - genesisReward = {args.reward} * COIN

2. Set nKAWPOWActivationTime = 0 to enable KawPoW from genesis

3. Comment out the genesis hash assertion temporarily

4. Build and run: ./src/myntad -daemon=0 -printtoconsole 2>&1 | head -50

5. The daemon will mine genesis and print the hash values

6. Update chainparams.cpp with the mined values and uncomment assertions

================================================================================
""")

    # Generate the scriptSig for the coinbase transaction
    # This matches the format in CreateGenesisBlock
    print("Genesis creation parameters:")
    print(f"const char* pszTimestamp = \"{args.timestamp}\";")
    print(f"genesis = CreateGenesisBlock({args.time}, 0, {bits}, 4, {args.reward} * COIN);")
    print()
    print("// For KawPoW from genesis, set:")  
    print("nKAWPOWActivationTime = 0;")
    print()

if __name__ == '__main__':
    main()


