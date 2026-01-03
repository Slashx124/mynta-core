// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_mynta.h"

#include "llmq/quorums.h"
#include "llmq/instantsend.h"
#include "llmq/chainlocks.h"
#include "bls/bls.h"
#include "hash.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(llmq_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(llmq_params)
{
    // Test getting LLMQ parameters
    const llmq::LLMQParams& params50 = llmq::GetLLMQParams(llmq::LLMQType::LLMQ_50_60);
    BOOST_CHECK_EQUAL(params50.size, 50);
    BOOST_CHECK_EQUAL(params50.threshold, 60);
    
    const llmq::LLMQParams& params400 = llmq::GetLLMQParams(llmq::LLMQType::LLMQ_400_60);
    BOOST_CHECK_EQUAL(params400.size, 400);
    BOOST_CHECK_EQUAL(params400.threshold, 60);
}

BOOST_AUTO_TEST_CASE(llmq_quorum_member)
{
    llmq::CQuorumMember member;
    member.proTxHash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    member.valid = true;
    
    CBLSSecretKey sk;
    sk.MakeNewKey();
    member.pubKeyOperator = sk.GetPublicKey();
    
    BOOST_CHECK(member.valid);
    BOOST_CHECK(member.pubKeyOperator.IsValid());
}

BOOST_AUTO_TEST_CASE(llmq_quorum_snapshot)
{
    llmq::CQuorumSnapshot snapshot;
    snapshot.llmqType = llmq::LLMQType::LLMQ_50_60;
    snapshot.quorumHash = uint256S("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    snapshot.quorumHeight = 100000;
    snapshot.activeMembers.resize(50, true);
    
    BOOST_CHECK_EQUAL(snapshot.activeMembers.size(), 50);
    BOOST_CHECK(snapshot.activeMembers[0]);
}

BOOST_AUTO_TEST_CASE(llmq_recovered_sig)
{
    llmq::CRecoveredSig sig;
    sig.llmqType = llmq::LLMQType::LLMQ_50_60;
    sig.quorumHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    sig.id = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    sig.msgHash = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    
    // Generate a test signature
    CBLSSecretKey sk;
    sk.MakeNewKey();
    sig.sig = sk.Sign(sig.msgHash);
    
    BOOST_CHECK(sig.sig.IsValid());
    
    // Build sign hash
    uint256 signHash = sig.BuildSignHash();
    BOOST_CHECK(!signHash.IsNull());
}

BOOST_AUTO_TEST_CASE(instantsend_lock)
{
    llmq::CInstantSendLock islock;
    islock.txid = uint256S("4444444444444444444444444444444444444444444444444444444444444444");
    islock.quorumHash = uint256S("5555555555555555555555555555555555555555555555555555555555555555");
    
    // Add some inputs
    islock.inputs.push_back(COutPoint(uint256S("6666666666666666666666666666666666666666666666666666666666666666"), 0));
    islock.inputs.push_back(COutPoint(uint256S("7777777777777777777777777777777777777777777777777777777777777777"), 1));
    
    // Generate signature
    CBLSSecretKey sk;
    sk.MakeNewKey();
    
    uint256 signHash = islock.GetSignHash();
    islock.sig = sk.Sign(signHash);
    
    BOOST_CHECK(islock.sig.IsValid());
    BOOST_CHECK_EQUAL(islock.inputs.size(), 2);
}

BOOST_AUTO_TEST_CASE(chainlock_sig)
{
    llmq::CChainLockSig clsig;
    clsig.nHeight = 500000;
    clsig.blockHash = uint256S("8888888888888888888888888888888888888888888888888888888888888888");
    clsig.quorumHash = uint256S("9999999999999999999999999999999999999999999999999999999999999999");
    
    // Generate signature
    CBLSSecretKey sk;
    sk.MakeNewKey();
    
    uint256 signHash = clsig.GetSignHash();
    clsig.sig = sk.Sign(signHash);
    
    BOOST_CHECK(clsig.sig.IsValid());
    BOOST_CHECK_EQUAL(clsig.nHeight, 500000);
    
    // Request ID should be deterministic
    uint256 reqId = clsig.GetRequestId();
    BOOST_CHECK(!reqId.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
