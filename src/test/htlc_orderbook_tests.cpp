// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_mynta.h"

#include "assets/atomicswap.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "uint256.h"
#include "streams.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(htlc_orderbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(htlc_preimage_verification)
{
    // Generate a random preimage
    std::vector<unsigned char> preimage(32);
    GetRandBytes(preimage.data(), preimage.size());
    
    // Create hash of preimage
    uint256 hashLock = HashSecret(preimage);
    
    // Verify correct preimage
    BOOST_CHECK(VerifyPreimage(preimage, hashLock));
    
    // Wrong preimage should fail
    std::vector<unsigned char> wrongPreimage(32);
    GetRandBytes(wrongPreimage.data(), wrongPreimage.size());
    BOOST_CHECK(!VerifyPreimage(wrongPreimage, hashLock));
}

BOOST_AUTO_TEST_CASE(atomic_swap_offer_basic)
{
    CAtomicSwapOffer offer;
    offer.offerHash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    offer.makerAssetName = "ASSET1";
    offer.makerAmount = 1000 * COIN;
    offer.takerAssetName = "ASSET2";
    offer.takerAmount = 500 * COIN;
    offer.createdHeight = 100000;
    offer.timeoutBlocks = 144;
    
    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << offer;
    
    // Deserialize
    CAtomicSwapOffer offer2;
    ss >> offer2;
    
    BOOST_CHECK(offer.offerHash == offer2.offerHash);
    BOOST_CHECK_EQUAL(offer.makerAssetName, offer2.makerAssetName);
    BOOST_CHECK_EQUAL(offer.makerAmount, offer2.makerAmount);
    BOOST_CHECK_EQUAL(offer.takerAssetName, offer2.takerAssetName);
    BOOST_CHECK_EQUAL(offer.takerAmount, offer2.takerAmount);
}

BOOST_AUTO_TEST_CASE(atomic_swap_offer_expiry)
{
    CAtomicSwapOffer offer;
    offer.createdHeight = 100000;
    offer.timeoutBlocks = 144;
    
    // Before expiry
    BOOST_CHECK(!offer.IsExpired(100100));
    
    // At expiry boundary
    BOOST_CHECK(!offer.IsExpired(100143));
    
    // After expiry
    BOOST_CHECK(offer.IsExpired(100144));
    BOOST_CHECK(offer.IsExpired(200000));
}

BOOST_AUTO_TEST_CASE(chtlc_serialization)
{
    CHTLC htlc;
    htlc.senderPubKeyHash.SetHex("1111111111111111111111111111111111111111");
    htlc.receiverPubKeyHash.SetHex("2222222222222222222222222222222222222222");
    htlc.hashLock = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    htlc.timeoutHeight = 100144;
    htlc.amount = 10 * COIN;
    htlc.assetName = "MYASSET";
    
    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << htlc;
    
    // Deserialize
    CHTLC htlc2;
    ss >> htlc2;
    
    BOOST_CHECK(htlc.senderPubKeyHash == htlc2.senderPubKeyHash);
    BOOST_CHECK(htlc.receiverPubKeyHash == htlc2.receiverPubKeyHash);
    BOOST_CHECK(htlc.hashLock == htlc2.hashLock);
    BOOST_CHECK_EQUAL(htlc.timeoutHeight, htlc2.timeoutHeight);
    BOOST_CHECK_EQUAL(htlc.amount, htlc2.amount);
    BOOST_CHECK_EQUAL(htlc.assetName, htlc2.assetName);
}

BOOST_AUTO_TEST_SUITE_END()
