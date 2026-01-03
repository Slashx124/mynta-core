#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test RPC commands for signing and verifying messages."""

from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal

class SignMessagesTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        # Use a wallet-generated key for consistent address format
        address = self.nodes[0].getnewaddress()
        priv_key = self.nodes[0].dumpprivkey(address)
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)
        # Verify the signature can be verified (round-trip test)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test signing with an address with wallet')
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test verifying with another address should not work')
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert(not self.nodes[0].verifymessage(other_address, signature, message))
        assert(not self.nodes[0].verifymessage(address, other_signature, message))

if __name__ == '__main__':
    SignMessagesTest().main()
