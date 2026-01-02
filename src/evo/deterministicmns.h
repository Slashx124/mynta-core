// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_EVO_DETERMINISTICMNS_H
#define MYNTA_EVO_DETERMINISTICMNS_H

#include "arith_uint256.h"
#include "evo/evodb.h"
#include "netaddress.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlock;
class CBlockIndex;
class CValidationState;

// Forward declarations
class CDeterministicMN;
class CDeterministicMNState;
class CDeterministicMNList;
class CDeterministicMNManager;

using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;
using CDeterministicMNListCPtr = std::shared_ptr<const CDeterministicMNList>;

/**
 * CDeterministicMNState - State of a single deterministic masternode
 * 
 * This structure tracks all mutable state of a masternode that can
 * change through update transactions or consensus events.
 */
class CDeterministicMNState
{
public:
    int nRegisteredHeight{-1};
    int nLastPaidHeight{0};
    int nPoSePenalty{0};
    int nPoSeRevivedHeight{-1};
    int nPoSeBanHeight{-1};
    uint16_t nRevocationReason{0};

    // Keys and addresses
    CKeyID keyIDOwner;
    std::vector<unsigned char> vchOperatorPubKey;
    CKeyID keyIDVoting;
    CService addr;
    CScript scriptPayout;
    CScript scriptOperatorPayout;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nRegisteredHeight);
        READWRITE(nLastPaidHeight);
        READWRITE(nPoSePenalty);
        READWRITE(nPoSeRevivedHeight);
        READWRITE(nPoSeBanHeight);
        READWRITE(nRevocationReason);
        READWRITE(keyIDOwner);
        READWRITE(vchOperatorPubKey);
        READWRITE(keyIDVoting);
        READWRITE(addr);
        READWRITE(scriptPayout);
        READWRITE(scriptOperatorPayout);
    }

    // Check if masternode is banned
    bool IsBanned() const { return nPoSeBanHeight != -1; }
    
    // Get the effective payout script (considers operator payout)
    CScript GetPayoutScript(uint16_t operatorReward) const;

    // Compare for changes
    bool operator==(const CDeterministicMNState& other) const;
    bool operator!=(const CDeterministicMNState& other) const { return !(*this == other); }

    std::string ToString() const;
};

/**
 * CDeterministicMN - A deterministic masternode entry
 * 
 * Combines the immutable registration data with mutable state.
 */
class CDeterministicMN
{
public:
    uint256 proTxHash;                      // Registration transaction hash
    COutPoint collateralOutpoint;           // Collateral UTXO
    uint16_t nOperatorReward{0};            // Operator reward percentage
    CDeterministicMNState state;            // Mutable state

    // Internal management
    uint64_t internalId{std::numeric_limits<uint64_t>::max()};

    // Constructors
    CDeterministicMN() = default;
    
    template <typename Stream>
    CDeterministicMN(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(proTxHash);
        READWRITE(collateralOutpoint);
        READWRITE(nOperatorReward);
        READWRITE(state);
        READWRITE(internalId);
    }

    // Status checks
    bool IsValid() const { return !state.IsBanned() && state.nRevocationReason == 0; }
    
    // Calculate score for payment ordering
    arith_uint256 CalcScore(const uint256& blockHash) const;

    std::string ToString() const;
};

/**
 * CDeterministicMNList - The deterministic masternode list
 * 
 * This is the complete state of all registered masternodes at a given block.
 * It is computed deterministically from the blockchain and can be efficiently
 * diffed between blocks.
 */
class CDeterministicMNList
{
public:
    using MnMap = std::map<uint256, CDeterministicMNCPtr>;
    using MnUniquePropertyMap = std::map<uint256, uint256>; // property hash -> proTxHash

private:
    uint256 blockHash;
    int nHeight{-1};
    uint64_t nTotalRegisteredCount{0};
    
    MnMap mnMap;
    
    // Unique property indexes for fast lookups
    MnUniquePropertyMap mnUniquePropertyMap;

public:
    CDeterministicMNList() = default;
    explicit CDeterministicMNList(const uint256& _blockHash, int _nHeight)
        : blockHash(_blockHash), nHeight(_nHeight) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(blockHash);
        READWRITE(nHeight);
        READWRITE(nTotalRegisteredCount);
        READWRITE(mnMap);
        READWRITE(mnUniquePropertyMap);
    }

    // Getters
    const uint256& GetBlockHash() const { return blockHash; }
    int GetHeight() const { return nHeight; }
    size_t GetAllMNsCount() const { return mnMap.size(); }
    size_t GetValidMNsCount() const;
    uint64_t GetTotalRegisteredCount() const { return nTotalRegisteredCount; }
    void IncrementTotalRegisteredCount() { nTotalRegisteredCount++; }
    const MnMap& GetMnMap() const { return mnMap; }

    // Lookup functions
    CDeterministicMNCPtr GetMN(const uint256& proTxHash) const;
    CDeterministicMNCPtr GetMNByOperatorKey(const std::vector<unsigned char>& vchPubKey) const;
    CDeterministicMNCPtr GetMNByCollateral(const COutPoint& collateralOutpoint) const;
    CDeterministicMNCPtr GetMNByService(const CService& addr) const;

    // Check for unique property conflicts
    bool HasUniqueProperty(const uint256& propertyHash) const;
    uint256 GetUniquePropertyHash(const COutPoint& outpoint) const;
    uint256 GetUniquePropertyHash(const CService& addr) const;
    uint256 GetUniquePropertyHash(const CKeyID& keyId) const;

    // Get valid masternodes for payment
    std::vector<CDeterministicMNCPtr> GetValidMNsForPayment() const;

    // Calculate which masternode should be paid
    CDeterministicMNCPtr GetMNPayee(const uint256& blockHash) const;

    // Modification (returns new list, original is immutable)
    CDeterministicMNList AddMN(const CDeterministicMNCPtr& mn) const;
    CDeterministicMNList UpdateMN(const uint256& proTxHash, const CDeterministicMNState& newState) const;
    CDeterministicMNList RemoveMN(const uint256& proTxHash) const;

    // Apply block updates
    CDeterministicMNList ApplyDiff(const CBlock& block, const CBlockIndex* pindex) const;

    // Iterate over all masternodes
    template <typename Func>
    void ForEachMN(bool onlyValid, Func&& func) const
    {
        for (const auto& pair : mnMap) {
            if (onlyValid && !pair.second->IsValid()) {
                continue;
            }
            func(pair.second);
        }
    }

    std::string ToString() const;
};

/**
 * CDeterministicMNManager - Manages the deterministic masternode list
 * 
 * This is the main interface for accessing and updating the masternode list.
 * It maintains a cache of recent lists and handles persistence to the database.
 */
class CDeterministicMNManager
{
private:
    mutable CCriticalSection cs;
    CEvoDB& evoDb;

    // Cache of recent masternode lists (block hash -> list)
    std::map<uint256, CDeterministicMNListCPtr> mnListsCache;
    
    // The current tip's masternode list
    CDeterministicMNListCPtr tipList;

    // Maximum cache size
    static const size_t MAX_CACHE_SIZE = 100;

public:
    explicit CDeterministicMNManager(CEvoDB& _evoDb);
    ~CDeterministicMNManager() = default;

    // Prevent copying
    CDeterministicMNManager(const CDeterministicMNManager&) = delete;
    CDeterministicMNManager& operator=(const CDeterministicMNManager&) = delete;

    // Initialize from database
    bool Init();

    // Process a new block
    bool ProcessBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state, bool fJustCheck);
    
    // Undo a block during reorg
    bool UndoBlock(const CBlock& block, const CBlockIndex* pindex);

    // Get the masternode list at a specific block
    CDeterministicMNListCPtr GetListForBlock(const CBlockIndex* pindex);
    CDeterministicMNListCPtr GetListAtChainTip();

    // Shortcut accessors
    CDeterministicMNCPtr GetMN(const uint256& proTxHash) const;
    bool HasMN(const uint256& proTxHash) const;
    
    // Get masternode by collateral
    CDeterministicMNCPtr GetMNByCollateral(const COutPoint& outpoint) const;

    // Check if an output is a masternode collateral
    bool IsProTxWithCollateral(const COutPoint& outpoint) const;

    // Get the masternode that should be paid in a block
    CDeterministicMNCPtr GetMNPayee(const CBlockIndex* pindex) const;

    // Update chain tip
    void UpdatedBlockTip(const CBlockIndex* pindex);

private:
    // Build the initial list at genesis
    CDeterministicMNListCPtr BuildInitialList(const CBlockIndex* pindex);
    
    // Apply a block to the list
    CDeterministicMNListCPtr ApplyBlockToList(const CBlock& block, const CBlockIndex* pindex, 
                                               const CDeterministicMNListCPtr& prevList);

    // Persist list to database
    void SaveListToDb(const CDeterministicMNListCPtr& list);
    
    // Load list from database
    CDeterministicMNListCPtr LoadListFromDb(const uint256& blockHash);

    // Clean old entries from cache
    void CleanupCache();
};

// Global manager instance
extern std::unique_ptr<CDeterministicMNManager> deterministicMNManager;

// Consensus parameters for masternodes
namespace Consensus {
    struct MasternodeParams {
        CAmount collateralAmount{10000 * COIN}; // 10,000 MYNTA
        int collateralConfirmations{15};
        int activationHeight{1000};
        int posePenaltyIncrement{66};
        int poseBanThreshold{100};
        int poseRevivalHeight{720}; // ~12 hours at 1 min blocks
    };
}

#endif // MYNTA_EVO_DETERMINISTICMNS_H

