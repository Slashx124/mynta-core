// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/atomicswap.h"
#include "hash.h"
#include "random.h"
#include "test/test_bitcoin.h"
#include "script/script.h"
#include "script/standard.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(htlc_orderbook_tests, BasicTestingSetup)

// ============================================================================
// HTLC Script Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(htlc_script_creation)
{
    // Create test addresses (P2PKH)
    CKey senderKey, receiverKey;
    senderKey.MakeNewKey(true);
    receiverKey.MakeNewKey(true);
    
    CScript senderScript = GetScriptForDestination(senderKey.GetPubKey().GetID());
    CScript receiverScript = GetScriptForDestination(receiverKey.GetPubKey().GetID());
    
    // Create hash lock
    std::vector<unsigned char> secret(32);
    GetRandBytes(secret.data(), 32);
    uint256 hashLock = HashSecret(secret);
    
    // Create HTLC script
    CScript htlcScript = HTLCScript::CreateHTLCScript(
        std::vector<unsigned char>(hashLock.begin(), hashLock.end()),
        receiverScript,
        senderScript,
        1000  // timeout at block 1000
    );
    
    BOOST_CHECK(!htlcScript.empty());
    BOOST_CHECK(htlcScript.size() > 50); // Should be substantial
}

BOOST_AUTO_TEST_CASE(htlc_preimage_verification)
{
    CHTLC htlc;
    
    // Generate a secret
    std::vector<unsigned char> realSecret(32);
    GetRandBytes(realSecret.data(), 32);
    
    // Set the hash lock
    htlc.hashLock = HashSecret(realSecret);
    
    // Correct preimage should verify
    BOOST_CHECK(htlc.VerifyPreimage(realSecret));
    
    // Wrong preimage should fail
    std::vector<unsigned char> wrongSecret(32);
    GetRandBytes(wrongSecret.data(), 32);
    BOOST_CHECK(!htlc.VerifyPreimage(wrongSecret));
    
    // Empty preimage should fail
    std::vector<unsigned char> emptySecret;
    BOOST_CHECK(!htlc.VerifyPreimage(emptySecret));
}

BOOST_AUTO_TEST_CASE(htlc_timeout_check)
{
    CHTLC htlc;
    htlc.timeLock = 1000;
    
    // Before timeout
    BOOST_CHECK(!htlc.CanRefund(500));
    BOOST_CHECK(!htlc.CanRefund(999));
    
    // At timeout
    BOOST_CHECK(htlc.CanRefund(1000));
    
    // After timeout
    BOOST_CHECK(htlc.CanRefund(1001));
    BOOST_CHECK(htlc.CanRefund(2000));
}

BOOST_AUTO_TEST_CASE(htlc_claim_script_creation)
{
    std::vector<unsigned char> preimage(32);
    GetRandBytes(preimage.data(), 32);
    
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    
    // Create a dummy signature
    std::vector<unsigned char> signature(71);
    GetRandBytes(signature.data(), 71);
    
    CScript claimScript = HTLCScript::CreateClaimScript(
        preimage,
        signature,
        std::vector<unsigned char>(pubkey.begin(), pubkey.end())
    );
    
    BOOST_CHECK(!claimScript.empty());
    
    // Should contain OP_TRUE (claim path indicator)
    BOOST_CHECK(claimScript.back() == OP_TRUE);
}

BOOST_AUTO_TEST_CASE(htlc_refund_script_creation)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    
    std::vector<unsigned char> signature(71);
    GetRandBytes(signature.data(), 71);
    
    CScript refundScript = HTLCScript::CreateRefundScript(
        signature,
        std::vector<unsigned char>(pubkey.begin(), pubkey.end())
    );
    
    BOOST_CHECK(!refundScript.empty());
    
    // Should contain OP_FALSE (refund path indicator)
    BOOST_CHECK(refundScript.back() == OP_FALSE);
}

BOOST_AUTO_TEST_CASE(htlc_preimage_extraction)
{
    std::vector<unsigned char> originalPreimage(32);
    GetRandBytes(originalPreimage.data(), 32);
    
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    
    std::vector<unsigned char> signature(71);
    GetRandBytes(signature.data(), 71);
    
    // Create claim script with preimage
    CScript claimScript = HTLCScript::CreateClaimScript(
        originalPreimage,
        signature,
        std::vector<unsigned char>(pubkey.begin(), pubkey.end())
    );
    
    // Extract preimage
    std::vector<unsigned char> extractedPreimage;
    BOOST_CHECK(HTLCScript::ExtractPreimage(claimScript, extractedPreimage));
    BOOST_CHECK(extractedPreimage == originalPreimage);
}

BOOST_AUTO_TEST_CASE(htlc_serialization)
{
    CHTLC htlc1;
    htlc1.htlcId.SetHex("aaaa000000000000000000000000000000000000000000000000000000000000");
    htlc1.hashLock.SetHex("bbbb000000000000000000000000000000000000000000000000000000000000");
    htlc1.timeLock = 12345;
    htlc1.assetName = "TESTASSET";
    htlc1.amount = 1000000;
    htlc1.state = CHTLC::PENDING;
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << htlc1;
    
    // Deserialize
    CHTLC htlc2;
    ss >> htlc2;
    
    BOOST_CHECK(htlc1.htlcId == htlc2.htlcId);
    BOOST_CHECK(htlc1.hashLock == htlc2.hashLock);
    BOOST_CHECK_EQUAL(htlc1.timeLock, htlc2.timeLock);
    BOOST_CHECK_EQUAL(htlc1.assetName, htlc2.assetName);
    BOOST_CHECK_EQUAL(htlc1.amount, htlc2.amount);
    BOOST_CHECK(htlc1.state == htlc2.state);
}

// ============================================================================
// Atomic Swap Offer Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(offer_creation_validation)
{
    CAtomicSwapOffer offer;
    offer.offerHash.SetHex("cccc000000000000000000000000000000000000000000000000000000000000");
    offer.makerAssetName = "";  // MYNTA
    offer.makerAmount = 100000000;  // 1 MYNTA
    offer.takerAssetName = "GOLD";
    offer.takerAmount = 10000;
    offer.timeoutBlocks = 144;
    offer.createdHeight = 1000;
    
    // Create a simple maker address script
    CKey key;
    key.MakeNewKey(true);
    offer.makerAddress = GetScriptForDestination(key.GetPubKey().GetID());
    
    std::string strError;
    BOOST_CHECK(CheckAtomicSwapOffer(offer, strError));
}

BOOST_AUTO_TEST_CASE(offer_invalid_amount)
{
    CAtomicSwapOffer offer;
    offer.makerAmount = 0;  // Invalid
    offer.takerAmount = 10000;
    offer.timeoutBlocks = 144;
    
    CKey key;
    key.MakeNewKey(true);
    offer.makerAddress = GetScriptForDestination(key.GetPubKey().GetID());
    
    std::string strError;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    BOOST_CHECK(strError.find("positive") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(offer_invalid_timeout)
{
    CAtomicSwapOffer offer;
    offer.makerAmount = 100000;
    offer.takerAmount = 10000;
    offer.timeoutBlocks = 5;  // Too short (< 10)
    
    CKey key;
    key.MakeNewKey(true);
    offer.makerAddress = GetScriptForDestination(key.GetPubKey().GetID());
    
    std::string strError;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    BOOST_CHECK(strError.find("10 blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(offer_rate_calculation)
{
    CAtomicSwapOffer offer;
    offer.makerAmount = 1000;
    offer.takerAmount = 2000;
    
    double rate = offer.GetRate();
    BOOST_CHECK_CLOSE(rate, 2.0, 0.001);
}

BOOST_AUTO_TEST_CASE(offer_expiration)
{
    CAtomicSwapOffer offer;
    offer.createdHeight = 1000;
    offer.timeoutBlocks = 100;
    
    // Not expired before timeout
    BOOST_CHECK(!offer.IsExpired(1050));
    BOOST_CHECK(!offer.IsExpired(1099));
    
    // Expired at or after timeout
    BOOST_CHECK(offer.IsExpired(1100));
    BOOST_CHECK(offer.IsExpired(1200));
}

BOOST_AUTO_TEST_CASE(offer_serialization)
{
    CAtomicSwapOffer offer1;
    offer1.offerHash.SetHex("dddd000000000000000000000000000000000000000000000000000000000000");
    offer1.makerAssetName = "SILVER";
    offer1.makerAmount = 50000;
    offer1.takerAssetName = "";
    offer1.takerAmount = 100000;
    offer1.hashLock.SetHex("eeee000000000000000000000000000000000000000000000000000000000000");
    offer1.timeoutBlocks = 288;
    offer1.createdHeight = 5000;
    offer1.isActive = true;
    offer1.isFilled = false;
    
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << offer1;
    
    CAtomicSwapOffer offer2;
    ss >> offer2;
    
    BOOST_CHECK(offer1.offerHash == offer2.offerHash);
    BOOST_CHECK_EQUAL(offer1.makerAssetName, offer2.makerAssetName);
    BOOST_CHECK_EQUAL(offer1.makerAmount, offer2.makerAmount);
    BOOST_CHECK_EQUAL(offer1.takerAssetName, offer2.takerAssetName);
    BOOST_CHECK_EQUAL(offer1.takerAmount, offer2.takerAmount);
    BOOST_CHECK(offer1.hashLock == offer2.hashLock);
    BOOST_CHECK_EQUAL(offer1.timeoutBlocks, offer2.timeoutBlocks);
    BOOST_CHECK_EQUAL(offer1.createdHeight, offer2.createdHeight);
    BOOST_CHECK_EQUAL(offer1.isActive, offer2.isActive);
    BOOST_CHECK_EQUAL(offer1.isFilled, offer2.isFilled);
}

// ============================================================================
// Order Book Tests (In-Memory)
// ============================================================================

BOOST_AUTO_TEST_CASE(orderbook_add_remove)
{
    CAtomicSwapOrderBook orderBook;
    
    CAtomicSwapOffer offer;
    offer.offerHash.SetHex("ffff000000000000000000000000000000000000000000000000000000000000");
    offer.makerAssetName = "";
    offer.makerAmount = 100000;
    offer.takerAssetName = "GOLD";
    offer.takerAmount = 10;
    offer.timeoutBlocks = 144;
    offer.createdHeight = 1000;
    offer.isActive = true;
    
    CKey key;
    key.MakeNewKey(true);
    offer.makerAddress = GetScriptForDestination(key.GetPubKey().GetID());
    
    // Add offer
    BOOST_CHECK(orderBook.AddOffer(offer));
    
    // Should find it
    CAtomicSwapOffer* found = orderBook.GetOffer(offer.offerHash);
    BOOST_CHECK(found != nullptr);
    BOOST_CHECK(found->offerHash == offer.offerHash);
    
    // Can't add duplicate
    BOOST_CHECK(!orderBook.AddOffer(offer));
    
    // Remove
    BOOST_CHECK(orderBook.RemoveOffer(offer.offerHash));
    
    // Should not find it anymore
    found = orderBook.GetOffer(offer.offerHash);
    BOOST_CHECK(found == nullptr);
    
    // Can't remove twice
    BOOST_CHECK(!orderBook.RemoveOffer(offer.offerHash));
}

BOOST_AUTO_TEST_CASE(orderbook_pair_lookup)
{
    CAtomicSwapOrderBook orderBook;
    
    CKey key;
    key.MakeNewKey(true);
    CScript makerAddr = GetScriptForDestination(key.GetPubKey().GetID());
    
    // Add MYNTA/GOLD offers
    for (int i = 0; i < 5; i++) {
        CAtomicSwapOffer offer;
        offer.offerHash.SetHex(strprintf("1111%060d", i));
        offer.makerAssetName = "";
        offer.makerAmount = 100000 * (i + 1);
        offer.takerAssetName = "GOLD";
        offer.takerAmount = 10 * (i + 1);
        offer.timeoutBlocks = 144;
        offer.createdHeight = 1000;
        offer.isActive = true;
        offer.makerAddress = makerAddr;
        
        orderBook.AddOffer(offer);
    }
    
    // Add SILVER/BRONZE offers
    for (int i = 0; i < 3; i++) {
        CAtomicSwapOffer offer;
        offer.offerHash.SetHex(strprintf("2222%060d", i));
        offer.makerAssetName = "SILVER";
        offer.makerAmount = 50000 * (i + 1);
        offer.takerAssetName = "BRONZE";
        offer.takerAmount = 100 * (i + 1);
        offer.timeoutBlocks = 144;
        offer.createdHeight = 1000;
        offer.isActive = true;
        offer.makerAddress = makerAddr;
        
        orderBook.AddOffer(offer);
    }
    
    // Should find 5 MYNTA/GOLD offers
    auto myntaGoldOffers = orderBook.GetOffersForPair("", "GOLD");
    BOOST_CHECK_EQUAL(myntaGoldOffers.size(), 5);
    
    // Should find 3 SILVER/BRONZE offers
    auto silverBronzeOffers = orderBook.GetOffersForPair("SILVER", "BRONZE");
    BOOST_CHECK_EQUAL(silverBronzeOffers.size(), 3);
    
    // Order should be symmetric
    auto bronzeSilverOffers = orderBook.GetOffersForPair("BRONZE", "SILVER");
    BOOST_CHECK_EQUAL(bronzeSilverOffers.size(), 3);
    
    // Should find 0 for non-existent pair
    auto noOffers = orderBook.GetOffersForPair("PLATINUM", "DIAMOND");
    BOOST_CHECK_EQUAL(noOffers.size(), 0);
}

BOOST_AUTO_TEST_CASE(orderbook_cleanup_expired)
{
    CAtomicSwapOrderBook orderBook;
    
    CKey key;
    key.MakeNewKey(true);
    CScript makerAddr = GetScriptForDestination(key.GetPubKey().GetID());
    
    // Add offer that expires at height 1100
    CAtomicSwapOffer offer1;
    offer1.offerHash.SetHex("3333000000000000000000000000000000000000000000000000000000000000");
    offer1.makerAssetName = "";
    offer1.makerAmount = 100000;
    offer1.takerAssetName = "GOLD";
    offer1.takerAmount = 10;
    offer1.timeoutBlocks = 100;
    offer1.createdHeight = 1000;
    offer1.isActive = true;
    offer1.makerAddress = makerAddr;
    
    // Add offer that expires at height 1500
    CAtomicSwapOffer offer2;
    offer2.offerHash.SetHex("4444000000000000000000000000000000000000000000000000000000000000");
    offer2.makerAssetName = "";
    offer2.makerAmount = 200000;
    offer2.takerAssetName = "GOLD";
    offer2.takerAmount = 20;
    offer2.timeoutBlocks = 500;
    offer2.createdHeight = 1000;
    offer2.isActive = true;
    offer2.makerAddress = makerAddr;
    
    orderBook.AddOffer(offer1);
    orderBook.AddOffer(offer2);
    
    // At height 1050, both should exist
    orderBook.CleanupExpired(1050);
    BOOST_CHECK(orderBook.GetOffer(offer1.offerHash) != nullptr);
    BOOST_CHECK(orderBook.GetOffer(offer2.offerHash) != nullptr);
    
    // At height 1150, first should be removed
    orderBook.CleanupExpired(1150);
    BOOST_CHECK(orderBook.GetOffer(offer1.offerHash) == nullptr);
    BOOST_CHECK(orderBook.GetOffer(offer2.offerHash) != nullptr);
    
    // At height 1600, both should be removed
    orderBook.CleanupExpired(1600);
    BOOST_CHECK(orderBook.GetOffer(offer2.offerHash) == nullptr);
}

// ============================================================================
// Trading Pair Key Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(trading_pair_key_normalization)
{
    // Same pair in different order should produce same key
    std::string key1 = GetTradingPairKey("GOLD", "SILVER");
    std::string key2 = GetTradingPairKey("SILVER", "GOLD");
    BOOST_CHECK_EQUAL(key1, key2);
    
    // MYNTA (empty) should be normalized
    std::string key3 = GetTradingPairKey("", "GOLD");
    std::string key4 = GetTradingPairKey("GOLD", "");
    BOOST_CHECK_EQUAL(key3, key4);
    
    // Different pairs should have different keys
    std::string key5 = GetTradingPairKey("GOLD", "SILVER");
    std::string key6 = GetTradingPairKey("GOLD", "BRONZE");
    BOOST_CHECK(key5 != key6);
}

// ============================================================================
// Secret Generation Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(swap_secret_generation)
{
    // Generate multiple secrets
    uint256 secret1 = GenerateSwapSecret();
    uint256 secret2 = GenerateSwapSecret();
    
    // Should not be null
    BOOST_CHECK(!secret1.IsNull());
    BOOST_CHECK(!secret2.IsNull());
    
    // Should be different (with overwhelming probability)
    BOOST_CHECK(secret1 != secret2);
}

BOOST_AUTO_TEST_CASE(secret_hashing)
{
    std::vector<unsigned char> secret(32);
    GetRandBytes(secret.data(), 32);
    
    uint256 hash1 = HashSecret(secret);
    uint256 hash2 = HashSecret(secret);
    
    // Same secret should produce same hash
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(!hash1.IsNull());
    
    // Different secret should produce different hash
    secret[0] ^= 0xFF;
    uint256 hash3 = HashSecret(secret);
    BOOST_CHECK(hash1 != hash3);
}

BOOST_AUTO_TEST_SUITE_END()

