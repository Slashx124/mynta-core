// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/atomicswap.h"
#include "hash.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_mynta.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(atomicswap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(htlc_preimage_verification)
{
    // Generate a secret and its hash
    std::vector<unsigned char> secret = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    uint256 hashLock = HashSecret(secret);
    
    CHTLC htlc;
    htlc.hashLock = hashLock;
    
    // Correct preimage should verify
    BOOST_CHECK(htlc.VerifyPreimage(secret));
    
    // Wrong preimage should fail
    std::vector<unsigned char> wrongSecret = secret;
    wrongSecret[0] = 0xFF;
    BOOST_CHECK(!htlc.VerifyPreimage(wrongSecret));
    
    // Empty preimage should fail
    std::vector<unsigned char> emptySecret;
    BOOST_CHECK(!htlc.VerifyPreimage(emptySecret));
}

BOOST_AUTO_TEST_CASE(htlc_refund_timeout)
{
    CHTLC htlc;
    htlc.timeLock = 1000;
    
    // Before timeout, cannot refund
    BOOST_CHECK(!htlc.CanRefund(999));
    
    // At timeout, can refund
    BOOST_CHECK(htlc.CanRefund(1000));
    
    // After timeout, can refund
    BOOST_CHECK(htlc.CanRefund(1001));
}

BOOST_AUTO_TEST_CASE(htlc_serialization)
{
    CHTLC htlc1;
    htlc1.htlcId = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    htlc1.senderAddress = CScript() << OP_DUP << OP_HASH160 << ParseHex("0123456789abcdef0123456789abcdef01234567") << OP_EQUALVERIFY << OP_CHECKSIG;
    htlc1.receiverAddress = CScript() << OP_DUP << OP_HASH160 << ParseHex("abcdef0123456789abcdef0123456789abcdef01") << OP_EQUALVERIFY << OP_CHECKSIG;
    htlc1.hashLock = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    htlc1.timeLock = 1440;
    htlc1.assetName = "TESTASSET";
    htlc1.amount = 100 * COIN;
    htlc1.state = CHTLC::PENDING;
    
    // Serialize
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << htlc1;
    
    // Deserialize
    CHTLC htlc2;
    ss >> htlc2;
    
    // Verify
    BOOST_CHECK(htlc1.htlcId == htlc2.htlcId);
    BOOST_CHECK(htlc1.senderAddress == htlc2.senderAddress);
    BOOST_CHECK(htlc1.receiverAddress == htlc2.receiverAddress);
    BOOST_CHECK(htlc1.hashLock == htlc2.hashLock);
    BOOST_CHECK_EQUAL(htlc1.timeLock, htlc2.timeLock);
    BOOST_CHECK_EQUAL(htlc1.assetName, htlc2.assetName);
    BOOST_CHECK_EQUAL(htlc1.amount, htlc2.amount);
    BOOST_CHECK_EQUAL(static_cast<int>(htlc1.state), static_cast<int>(htlc2.state));
}

BOOST_AUTO_TEST_CASE(atomic_swap_offer_rate)
{
    CAtomicSwapOffer offer;
    offer.makerAmount = 100 * COIN;
    offer.takerAmount = 50 * COIN;
    
    // Rate should be taker/maker
    BOOST_CHECK_CLOSE(offer.GetRate(), 0.5, 0.001);
    
    // Different ratio
    offer.makerAmount = 200 * COIN;
    offer.takerAmount = 100 * COIN;
    BOOST_CHECK_CLOSE(offer.GetRate(), 0.5, 0.001);
    
    // 1:1 ratio
    offer.makerAmount = 100 * COIN;
    offer.takerAmount = 100 * COIN;
    BOOST_CHECK_CLOSE(offer.GetRate(), 1.0, 0.001);
}

BOOST_AUTO_TEST_CASE(atomic_swap_offer_expiry)
{
    CAtomicSwapOffer offer;
    offer.createdHeight = 1000;
    offer.timeoutBlocks = 100;
    
    // Before expiry
    BOOST_CHECK(!offer.IsExpired(1099));
    
    // At expiry
    BOOST_CHECK(offer.IsExpired(1100));
    
    // After expiry
    BOOST_CHECK(offer.IsExpired(1200));
}

BOOST_AUTO_TEST_CASE(atomic_swap_offer_serialization)
{
    CAtomicSwapOffer offer1;
    offer1.offerHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    offer1.makerAssetName = "MYTOKEN";
    offer1.makerAmount = 100 * COIN;
    offer1.makerAddress = CScript() << OP_DUP << OP_HASH160 << ParseHex("0123456789abcdef0123456789abcdef01234567") << OP_EQUALVERIFY << OP_CHECKSIG;
    offer1.takerAssetName = "";  // MYNTA
    offer1.takerAmount = 50 * COIN;
    offer1.hashLock = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    offer1.timeoutBlocks = 1440;
    offer1.createdHeight = 500;
    offer1.isActive = true;
    offer1.isFilled = false;
    
    // Serialize
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << offer1;
    
    // Deserialize
    CAtomicSwapOffer offer2;
    ss >> offer2;
    
    // Verify
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

BOOST_AUTO_TEST_CASE(trading_pair_key_normalization)
{
    // Test that pair keys are normalized (sorted alphabetically)
    std::string key1 = GetTradingPairKey("ALPHA", "BETA");
    std::string key2 = GetTradingPairKey("BETA", "ALPHA");
    BOOST_CHECK_EQUAL(key1, key2);
    BOOST_CHECK_EQUAL(key1, "ALPHA:BETA");
    
    // Empty string becomes "MYNTA"
    std::string key3 = GetTradingPairKey("", "TOKEN");
    BOOST_CHECK_EQUAL(key3, "MYNTA:TOKEN");
    
    std::string key4 = GetTradingPairKey("TOKEN", "");
    BOOST_CHECK_EQUAL(key4, "MYNTA:TOKEN");
}

BOOST_AUTO_TEST_CASE(hash_secret_deterministic)
{
    std::vector<unsigned char> secret1 = {0x01, 0x02, 0x03, 0x04};
    
    uint256 hash1 = HashSecret(secret1);
    uint256 hash2 = HashSecret(secret1);
    
    // Same secret should produce same hash
    BOOST_CHECK(hash1 == hash2);
    
    // Different secret should produce different hash
    std::vector<unsigned char> secret2 = {0x05, 0x06, 0x07, 0x08};
    uint256 hash3 = HashSecret(secret2);
    BOOST_CHECK(hash1 != hash3);
}

BOOST_AUTO_TEST_CASE(offer_validation)
{
    CAtomicSwapOffer offer;
    std::string strError;
    
    // Invalid: zero maker amount
    offer.makerAmount = 0;
    offer.takerAmount = 100;
    offer.timeoutBlocks = 100;
    offer.makerAddress = CScript() << OP_TRUE;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    
    // Invalid: zero taker amount
    offer.makerAmount = 100;
    offer.takerAmount = 0;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    
    // Invalid: timeout too short
    offer.takerAmount = 100;
    offer.timeoutBlocks = 5;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    
    // Invalid: timeout too long
    offer.timeoutBlocks = 10000;
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    
    // Invalid: empty maker address
    offer.timeoutBlocks = 100;
    offer.makerAddress = CScript();
    BOOST_CHECK(!CheckAtomicSwapOffer(offer, strError));
    
    // Valid offer
    offer.makerAddress = CScript() << OP_TRUE;
    BOOST_CHECK(CheckAtomicSwapOffer(offer, strError));
}

BOOST_AUTO_TEST_CASE(htlc_validation)
{
    CHTLC htlc;
    std::string strError;
    
    // Invalid: zero amount
    htlc.amount = 0;
    htlc.senderAddress = CScript() << OP_TRUE;
    htlc.receiverAddress = CScript() << OP_TRUE;
    htlc.hashLock = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    BOOST_CHECK(!CheckHTLC(htlc, strError));
    
    // Invalid: empty sender
    htlc.amount = 100;
    htlc.senderAddress = CScript();
    BOOST_CHECK(!CheckHTLC(htlc, strError));
    
    // Invalid: empty receiver
    htlc.senderAddress = CScript() << OP_TRUE;
    htlc.receiverAddress = CScript();
    BOOST_CHECK(!CheckHTLC(htlc, strError));
    
    // Invalid: null hash lock
    htlc.receiverAddress = CScript() << OP_TRUE;
    htlc.hashLock = uint256();
    BOOST_CHECK(!CheckHTLC(htlc, strError));
    
    // Valid HTLC
    htlc.hashLock = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    BOOST_CHECK(CheckHTLC(htlc, strError));
}

BOOST_AUTO_TEST_CASE(htlc_script_generation)
{
    std::vector<unsigned char> hashLock = ParseHex("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234");
    CScript receiverScript = CScript() << OP_DUP << OP_HASH160 << ParseHex("0123456789abcdef0123456789abcdef01234567") << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript senderScript = CScript() << OP_DUP << OP_HASH160 << ParseHex("abcdef0123456789abcdef0123456789abcdef01") << OP_EQUALVERIFY << OP_CHECKSIG;
    uint32_t timeout = 1000;
    
    CScript htlcScript = HTLCScript::CreateHTLCScript(hashLock, receiverScript, senderScript, timeout);
    
    // Script should not be empty
    BOOST_CHECK(!htlcScript.empty());
    
    // Script should contain OP_IF and OP_ELSE and OP_ENDIF
    std::string scriptStr = ScriptToAsmStr(htlcScript);
    BOOST_CHECK(scriptStr.find("OP_IF") != std::string::npos);
    BOOST_CHECK(scriptStr.find("OP_ELSE") != std::string::npos);
    BOOST_CHECK(scriptStr.find("OP_ENDIF") != std::string::npos);
    BOOST_CHECK(scriptStr.find("OP_SHA256") != std::string::npos);
    BOOST_CHECK(scriptStr.find("OP_CHECKLOCKTIMEVERIFY") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

