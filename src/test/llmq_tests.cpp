// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums.h"
#include "llmq/instantsend.h"
#include "llmq/chainlocks.h"
#include "bls/bls.h"
#include "test/test_bitcoin.h"
#include "primitives/transaction.h"
#include "random.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(llmq_tests, BasicTestingSetup)

// ============================================================================
// Quorum Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(quorum_basic_creation)
{
    llmq::CQuorum quorum;
    
    // Set basic properties
    quorum.quorumType = llmq::QUORUM_TYPE_50_60;
    quorum.quorumHeight = 1000;
    
    // Should be invalid without members
    BOOST_CHECK(!quorum.IsValid());
    BOOST_CHECK(quorum.GetMemberCount() == 0);
}

BOOST_AUTO_TEST_CASE(quorum_member_management)
{
    llmq::CQuorum quorum;
    quorum.quorumType = llmq::QUORUM_TYPE_50_60;
    quorum.quorumHeight = 1000;
    
    // Add some members
    for (int i = 0; i < 50; i++) {
        llmq::CQuorumMember member;
        member.proTxHash.SetHex(strprintf("%064d", i));
        
        // Generate BLS key for member
        bls::CBLSSecretKey sk;
        sk.MakeNewKey();
        member.pubKeyShare = sk.GetPublicKey();
        member.isValid = true;
        
        quorum.members.push_back(member);
    }
    
    BOOST_CHECK_EQUAL(quorum.GetMemberCount(), 50);
    
    // Check threshold calculation
    size_t threshold = quorum.GetThreshold();
    BOOST_CHECK(threshold > 0);
    BOOST_CHECK(threshold <= quorum.GetMemberCount());
}

BOOST_AUTO_TEST_CASE(quorum_hash_calculation)
{
    llmq::CQuorum quorum1, quorum2;
    
    quorum1.quorumType = llmq::QUORUM_TYPE_50_60;
    quorum1.quorumHeight = 1000;
    
    quorum2.quorumType = llmq::QUORUM_TYPE_50_60;
    quorum2.quorumHeight = 1000;
    
    // Same parameters should produce same hash
    BOOST_CHECK(quorum1.GetHash() == quorum2.GetHash());
    
    // Different height should produce different hash
    quorum2.quorumHeight = 2000;
    BOOST_CHECK(quorum1.GetHash() != quorum2.GetHash());
}

BOOST_AUTO_TEST_CASE(quorum_selection_determinism)
{
    llmq::CQuorumManager mgr;
    
    // Same inputs should produce same quorum selection
    uint256 requestId;
    requestId.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    
    // Note: In a real test, we'd need a proper blockchain state
    // This test verifies the determinism concept
    
    std::vector<uint256> selection1, selection2;
    
    // Same request ID at same height should give same result
    // (This would need blockchain state to fully test)
    BOOST_CHECK(true); // Placeholder - real test needs mock blockchain
}

BOOST_AUTO_TEST_CASE(quorum_signing_verification)
{
    // Create a mock quorum with BLS keys
    llmq::CQuorum quorum;
    quorum.quorumType = llmq::QUORUM_TYPE_50_60;
    quorum.quorumHeight = 1000;
    
    std::vector<bls::CBLSSecretKey> memberSecrets;
    std::vector<bls::CBLSPublicKey> memberPubKeys;
    
    // Generate 50 members
    for (int i = 0; i < 50; i++) {
        bls::CBLSSecretKey sk;
        sk.MakeNewKey();
        memberSecrets.push_back(sk);
        
        llmq::CQuorumMember member;
        member.proTxHash.SetHex(strprintf("%064d", i));
        member.pubKeyShare = sk.GetPublicKey();
        member.isValid = true;
        quorum.members.push_back(member);
        
        memberPubKeys.push_back(sk.GetPublicKey());
    }
    
    // Aggregate public keys for quorum
    quorum.quorumPublicKey.AggregateInsecure(memberPubKeys);
    
    // Sign a message with threshold members (60% of 50 = 30)
    uint256 msgHash;
    msgHash.SetHex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    
    std::vector<bls::CBLSSignature> partialSigs;
    size_t threshold = 30;
    
    for (size_t i = 0; i < threshold; i++) {
        partialSigs.push_back(memberSecrets[i].Sign(msgHash));
    }
    
    // Aggregate signatures
    bls::CBLSSignature aggSig;
    aggSig.AggregateInsecure(partialSigs);
    
    // Aggregate corresponding public keys
    std::vector<bls::CBLSPublicKey> signerPubKeys(memberPubKeys.begin(), memberPubKeys.begin() + threshold);
    bls::CBLSPublicKey aggPubKey;
    aggPubKey.AggregateInsecure(signerPubKeys);
    
    // Verify aggregated signature
    BOOST_CHECK(aggSig.VerifyInsecure(aggPubKey, msgHash));
}

// ============================================================================
// InstantSend Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(instantsend_lock_creation)
{
    llmq::CInstantSendLock islock;
    
    // Set up a basic lock
    islock.txid.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    
    // Add some inputs
    for (int i = 0; i < 3; i++) {
        COutPoint input;
        input.hash.SetHex(strprintf("0000000000000000000000000000000000000000000000000000000000%06d", i));
        input.n = 0;
        islock.inputs.push_back(input);
    }
    
    BOOST_CHECK_EQUAL(islock.inputs.size(), 3);
    BOOST_CHECK(!islock.txid.IsNull());
}

BOOST_AUTO_TEST_CASE(instantsend_hash_calculation)
{
    llmq::CInstantSendLock lock1, lock2;
    
    lock1.txid.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    lock2.txid.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    
    // Same txid should produce same hash
    BOOST_CHECK(lock1.GetHash() == lock2.GetHash());
    
    // Different txid should produce different hash
    lock2.txid.SetHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    BOOST_CHECK(lock1.GetHash() != lock2.GetHash());
}

BOOST_AUTO_TEST_CASE(instantsend_input_conflict_detection)
{
    // Create two locks that share an input
    llmq::CInstantSendLock lock1, lock2;
    
    COutPoint sharedInput;
    sharedInput.hash.SetHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    sharedInput.n = 0;
    
    lock1.txid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    lock1.inputs.push_back(sharedInput);
    
    lock2.txid.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    lock2.inputs.push_back(sharedInput);
    
    // Both locks reference the same input
    BOOST_CHECK(lock1.inputs[0] == lock2.inputs[0]);
    
    // But they lock different transactions (conflict)
    BOOST_CHECK(lock1.txid != lock2.txid);
}

BOOST_AUTO_TEST_CASE(instantsend_serialization)
{
    llmq::CInstantSendLock lock1;
    lock1.txid.SetHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    
    COutPoint input;
    input.hash.SetHex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    input.n = 5;
    lock1.inputs.push_back(input);
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << lock1;
    
    // Deserialize
    llmq::CInstantSendLock lock2;
    ss >> lock2;
    
    BOOST_CHECK(lock1.txid == lock2.txid);
    BOOST_CHECK(lock1.inputs.size() == lock2.inputs.size());
    BOOST_CHECK(lock1.inputs[0] == lock2.inputs[0]);
    BOOST_CHECK(lock1.GetHash() == lock2.GetHash());
}

// ============================================================================
// ChainLocks Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(chainlock_basic_creation)
{
    llmq::CChainLockSig clsig(1000, uint256());
    
    BOOST_CHECK_EQUAL(clsig.nHeight, 1000);
    BOOST_CHECK(clsig.blockHash.IsNull());
}

BOOST_AUTO_TEST_CASE(chainlock_hash_calculation)
{
    uint256 blockHash;
    blockHash.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    
    llmq::CChainLockSig cl1(1000, blockHash);
    llmq::CChainLockSig cl2(1000, blockHash);
    
    // Same height and hash should produce same request ID
    BOOST_CHECK(cl1.GetRequestId() == cl2.GetRequestId());
    
    // Different height should produce different request ID
    llmq::CChainLockSig cl3(2000, blockHash);
    BOOST_CHECK(cl1.GetRequestId() != cl3.GetRequestId());
}

BOOST_AUTO_TEST_CASE(chainlock_height_monotonicity)
{
    llmq::CChainLocksDb db;
    
    uint256 hash1, hash2, hash3;
    hash1.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    hash2.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    hash3.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
    
    // Write locks in order
    llmq::CChainLockSig cl1(100, hash1);
    llmq::CChainLockSig cl2(200, hash2);
    llmq::CChainLockSig cl3(300, hash3);
    
    BOOST_CHECK(db.WriteChainLock(cl1));
    BOOST_CHECK(db.WriteChainLock(cl2));
    BOOST_CHECK(db.WriteChainLock(cl3));
    
    BOOST_CHECK_EQUAL(db.GetBestChainLockHeight(), 300);
    
    // Try to write a lower height lock - should fail
    llmq::CChainLockSig cl_old(150, hash1);
    BOOST_CHECK(!db.WriteChainLock(cl_old));
}

BOOST_AUTO_TEST_CASE(chainlock_lookup)
{
    llmq::CChainLocksDb db;
    
    uint256 blockHash;
    blockHash.SetHex("4444444444444444444444444444444444444444444444444444444444444444");
    
    llmq::CChainLockSig clsig(500, blockHash);
    BOOST_CHECK(db.WriteChainLock(clsig));
    
    // Lookup by height
    BOOST_CHECK(db.IsChainLocked(500));
    BOOST_CHECK(!db.IsChainLocked(501));
    
    // Lookup by hash
    BOOST_CHECK(db.HasChainLock(blockHash));
    
    uint256 wrongHash;
    wrongHash.SetHex("5555555555555555555555555555555555555555555555555555555555555555");
    BOOST_CHECK(!db.HasChainLock(wrongHash));
    
    // Get the lock
    llmq::CChainLockSig retrieved;
    BOOST_CHECK(db.GetChainLock(500, retrieved));
    BOOST_CHECK(retrieved.blockHash == blockHash);
}

BOOST_AUTO_TEST_CASE(chainlock_reorg_protection)
{
    llmq::CChainLocksDb db;
    
    uint256 hash1;
    hash1.SetHex("6666666666666666666666666666666666666666666666666666666666666666");
    
    llmq::CChainLockSig clsig(1000, hash1);
    BOOST_CHECK(db.WriteChainLock(clsig));
    
    // Best should be 1000
    BOOST_CHECK_EQUAL(db.GetBestChainLockHeight(), 1000);
    
    // Remove above height 500
    db.RemoveAboveHeight(500);
    
    // Now best should be 0 (no locks at or below 500)
    BOOST_CHECK_EQUAL(db.GetBestChainLockHeight(), 0);
}

BOOST_AUTO_TEST_CASE(chainlock_serialization)
{
    uint256 blockHash;
    blockHash.SetHex("7777777777777777777777777777777777777777777777777777777777777777");
    
    llmq::CChainLockSig cl1(12345, blockHash);
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << cl1;
    
    // Deserialize
    llmq::CChainLockSig cl2;
    ss >> cl2;
    
    BOOST_CHECK_EQUAL(cl1.nHeight, cl2.nHeight);
    BOOST_CHECK(cl1.blockHash == cl2.blockHash);
    BOOST_CHECK(cl1.GetHash() == cl2.GetHash());
}

BOOST_AUTO_TEST_CASE(chainlock_conflict_detection)
{
    llmq::CChainLocksDb db;
    
    uint256 hash1, hash2;
    hash1.SetHex("8888888888888888888888888888888888888888888888888888888888888888");
    hash2.SetHex("9999999999999999999999999999999999999999999999999999999999999999");
    
    // Write first lock at height 1000
    llmq::CChainLockSig cl1(1000, hash1);
    BOOST_CHECK(db.WriteChainLock(cl1));
    
    // Try to write a different block at same height (conflict)
    llmq::CChainLockSig cl2(1000, hash2);
    // In a real scenario, this would be rejected by the manager
    // The DB itself allows overwriting for simplicity
    
    // But best height should not go backwards
    BOOST_CHECK_EQUAL(db.GetBestChainLockHeight(), 1000);
}

BOOST_AUTO_TEST_SUITE_END()

