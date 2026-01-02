// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evo/deterministicmns.h"
#include "evo/providertx.h"
#include "evo/evodb.h"
#include "hash.h"
#include "test/test_mynta.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(evo_deterministicmns_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deterministicmn_state_serialization)
{
    CDeterministicMNState state1;
    state1.nRegisteredHeight = 1000;
    state1.nLastPaidHeight = 950;
    state1.nPoSePenalty = 10;
    state1.nPoSeRevivedHeight = 900;
    state1.nPoSeBanHeight = -1;
    state1.nRevocationReason = 0;
    
    // Serialize
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << state1;
    
    // Deserialize
    CDeterministicMNState state2;
    ss >> state2;
    
    // Verify
    BOOST_CHECK_EQUAL(state1.nRegisteredHeight, state2.nRegisteredHeight);
    BOOST_CHECK_EQUAL(state1.nLastPaidHeight, state2.nLastPaidHeight);
    BOOST_CHECK_EQUAL(state1.nPoSePenalty, state2.nPoSePenalty);
    BOOST_CHECK_EQUAL(state1.nPoSeRevivedHeight, state2.nPoSeRevivedHeight);
    BOOST_CHECK_EQUAL(state1.nPoSeBanHeight, state2.nPoSeBanHeight);
    BOOST_CHECK_EQUAL(state1.nRevocationReason, state2.nRevocationReason);
    BOOST_CHECK(state1 == state2);
}

BOOST_AUTO_TEST_CASE(deterministicmn_serialization)
{
    auto mn = std::make_shared<CDeterministicMN>();
    mn->proTxHash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    mn->collateralOutpoint = COutPoint(uint256S("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"), 0);
    mn->nOperatorReward = 500; // 5%
    mn->state.nRegisteredHeight = 1000;
    mn->internalId = 42;
    
    // Serialize
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << *mn;
    
    // Deserialize
    CDeterministicMN mn2;
    ss >> mn2;
    
    // Verify
    BOOST_CHECK(mn->proTxHash == mn2.proTxHash);
    BOOST_CHECK(mn->collateralOutpoint == mn2.collateralOutpoint);
    BOOST_CHECK_EQUAL(mn->nOperatorReward, mn2.nOperatorReward);
    BOOST_CHECK_EQUAL(mn->state.nRegisteredHeight, mn2.state.nRegisteredHeight);
    BOOST_CHECK_EQUAL(mn->internalId, mn2.internalId);
}

BOOST_AUTO_TEST_CASE(deterministicmn_is_valid)
{
    auto mn = std::make_shared<CDeterministicMN>();
    mn->proTxHash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    mn->state.nPoSeBanHeight = -1;
    mn->state.nRevocationReason = 0;
    
    // Initially valid
    BOOST_CHECK(mn->IsValid());
    
    // Banned should be invalid
    mn->state.nPoSeBanHeight = 1000;
    BOOST_CHECK(!mn->IsValid());
    
    // Reset ban, revoked should be invalid
    mn->state.nPoSeBanHeight = -1;
    mn->state.nRevocationReason = 1;
    BOOST_CHECK(!mn->IsValid());
}

BOOST_AUTO_TEST_CASE(deterministicmn_score_calculation)
{
    auto mn1 = std::make_shared<CDeterministicMN>();
    mn1->proTxHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    
    auto mn2 = std::make_shared<CDeterministicMN>();
    mn2->proTxHash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    
    uint256 blockHash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    
    arith_uint256 score1 = mn1->CalcScore(blockHash);
    arith_uint256 score2 = mn2->CalcScore(blockHash);
    
    // Scores should be different for different MNs
    BOOST_CHECK(score1 != score2);
    
    // Same MN should have same score for same block
    arith_uint256 score1b = mn1->CalcScore(blockHash);
    BOOST_CHECK(score1 == score1b);
    
    // Different block should give different score
    uint256 blockHash2 = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    arith_uint256 score1c = mn1->CalcScore(blockHash2);
    BOOST_CHECK(score1 != score1c);
}

BOOST_AUTO_TEST_CASE(deterministicmnlist_operations)
{
    CDeterministicMNList list(uint256(), 0);
    
    // Create test MNs
    auto mn1 = std::make_shared<CDeterministicMN>();
    mn1->proTxHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    mn1->collateralOutpoint = COutPoint(uint256S("aaaa"), 0);
    mn1->state.nRegisteredHeight = 100;
    mn1->state.addr = CService("192.168.1.1:8770");
    
    auto mn2 = std::make_shared<CDeterministicMN>();
    mn2->proTxHash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    mn2->collateralOutpoint = COutPoint(uint256S("bbbb"), 0);
    mn2->state.nRegisteredHeight = 101;
    mn2->state.addr = CService("192.168.1.2:8770");
    
    // Add MNs
    CDeterministicMNList list1 = list.AddMN(mn1);
    BOOST_CHECK_EQUAL(list1.GetAllMNsCount(), 1);
    BOOST_CHECK(list1.GetMN(mn1->proTxHash) != nullptr);
    
    CDeterministicMNList list2 = list1.AddMN(mn2);
    BOOST_CHECK_EQUAL(list2.GetAllMNsCount(), 2);
    
    // Test lookup functions
    BOOST_CHECK(list2.GetMN(mn1->proTxHash) != nullptr);
    BOOST_CHECK(list2.GetMN(mn2->proTxHash) != nullptr);
    BOOST_CHECK(list2.GetMNByCollateral(mn1->collateralOutpoint) != nullptr);
    BOOST_CHECK(list2.GetMNByService(mn1->state.addr) != nullptr);
    
    // Test update
    CDeterministicMNState newState = mn1->state;
    newState.nLastPaidHeight = 200;
    CDeterministicMNList list3 = list2.UpdateMN(mn1->proTxHash, newState);
    
    auto updatedMN = list3.GetMN(mn1->proTxHash);
    BOOST_CHECK(updatedMN != nullptr);
    BOOST_CHECK_EQUAL(updatedMN->state.nLastPaidHeight, 200);
    
    // Test remove
    CDeterministicMNList list4 = list3.RemoveMN(mn1->proTxHash);
    BOOST_CHECK_EQUAL(list4.GetAllMNsCount(), 1);
    BOOST_CHECK(list4.GetMN(mn1->proTxHash) == nullptr);
    BOOST_CHECK(list4.GetMN(mn2->proTxHash) != nullptr);
}

BOOST_AUTO_TEST_CASE(deterministicmnlist_valid_count)
{
    CDeterministicMNList list(uint256(), 0);
    
    auto mn1 = std::make_shared<CDeterministicMN>();
    mn1->proTxHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    mn1->state.nPoSeBanHeight = -1;
    mn1->state.nRevocationReason = 0;
    
    auto mn2 = std::make_shared<CDeterministicMN>();
    mn2->proTxHash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    mn2->state.nPoSeBanHeight = 100; // Banned
    mn2->state.nRevocationReason = 0;
    
    auto mn3 = std::make_shared<CDeterministicMN>();
    mn3->proTxHash = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    mn3->state.nPoSeBanHeight = -1;
    mn3->state.nRevocationReason = 1; // Revoked
    
    list = list.AddMN(mn1);
    list = list.AddMN(mn2);
    list = list.AddMN(mn3);
    
    BOOST_CHECK_EQUAL(list.GetAllMNsCount(), 3);
    BOOST_CHECK_EQUAL(list.GetValidMNsCount(), 1); // Only mn1 is valid
}

BOOST_AUTO_TEST_CASE(deterministicmnlist_unique_properties)
{
    CDeterministicMNList list(uint256(), 0);
    
    auto mn1 = std::make_shared<CDeterministicMN>();
    mn1->proTxHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    mn1->collateralOutpoint = COutPoint(uint256S("aaaa"), 0);
    mn1->state.addr = CService("192.168.1.1:8770");
    mn1->state.keyIDOwner = CKeyID(uint160S("0123456789abcdef0123456789abcdef01234567"));
    
    list = list.AddMN(mn1);
    
    // Should have unique properties registered
    BOOST_CHECK(list.HasUniqueProperty(list.GetUniquePropertyHash(mn1->collateralOutpoint)));
    BOOST_CHECK(list.HasUniqueProperty(list.GetUniquePropertyHash(mn1->state.addr)));
    BOOST_CHECK(list.HasUniqueProperty(list.GetUniquePropertyHash(mn1->state.keyIDOwner)));
    
    // Non-existent property should not be found
    COutPoint nonExistent(uint256S("ffff"), 99);
    BOOST_CHECK(!list.HasUniqueProperty(list.GetUniquePropertyHash(nonExistent)));
}

BOOST_AUTO_TEST_CASE(deterministicmnlist_payment_selection)
{
    CDeterministicMNList list(uint256(), 100);
    
    // Create multiple valid MNs
    std::vector<CDeterministicMNCPtr> mns;
    for (int i = 1; i <= 5; i++) {
        auto mn = std::make_shared<CDeterministicMN>();
        std::stringstream ss;
        ss << std::setfill('0') << std::setw(64) << i;
        mn->proTxHash = uint256S(ss.str());
        mn->state.nPoSeBanHeight = -1;
        mn->state.nRevocationReason = 0;
        mns.push_back(mn);
        list = list.AddMN(mn);
    }
    
    BOOST_CHECK_EQUAL(list.GetValidMNsCount(), 5);
    
    // Get payee for a block
    uint256 blockHash = uint256S("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234");
    auto payee = list.GetMNPayee(blockHash);
    
    BOOST_CHECK(payee != nullptr);
    
    // Payee should be deterministic - same block hash should give same payee
    auto payee2 = list.GetMNPayee(blockHash);
    BOOST_CHECK(payee->proTxHash == payee2->proTxHash);
    
    // Different block should give different payee (usually, depending on hash)
    uint256 blockHash2 = uint256S("1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd");
    auto payee3 = list.GetMNPayee(blockHash2);
    BOOST_CHECK(payee3 != nullptr);
    // Note: They might be the same by chance, so we don't assert they're different
}

BOOST_AUTO_TEST_SUITE_END()

