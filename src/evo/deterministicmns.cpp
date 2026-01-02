// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evo/deterministicmns.h"
#include "evo/providertx.h"
#include "evo/evodb.h"
#include "evo/specialtx.h"

#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "script/standard.h"
#include "util.h"
#include "validation.h"

#include <algorithm>
#include <sstream>

std::unique_ptr<CDeterministicMNManager> deterministicMNManager;

// Database keys
static const std::string DB_LIST_SNAPSHOT = "dmn_S";
static const std::string DB_LIST_DIFF = "dmn_D";

// ============================================================================
// CDeterministicMNState Implementation
// ============================================================================

CScript CDeterministicMNState::GetPayoutScript(uint16_t operatorReward) const
{
    // If operator reward is 100%, use operator payout address
    if (operatorReward == 10000 && !scriptOperatorPayout.empty()) {
        return scriptOperatorPayout;
    }
    return scriptPayout;
}

bool CDeterministicMNState::operator==(const CDeterministicMNState& other) const
{
    return nRegisteredHeight == other.nRegisteredHeight &&
           nLastPaidHeight == other.nLastPaidHeight &&
           nPoSePenalty == other.nPoSePenalty &&
           nPoSeRevivedHeight == other.nPoSeRevivedHeight &&
           nPoSeBanHeight == other.nPoSeBanHeight &&
           nRevocationReason == other.nRevocationReason &&
           keyIDOwner == other.keyIDOwner &&
           vchOperatorPubKey == other.vchOperatorPubKey &&
           keyIDVoting == other.keyIDVoting &&
           addr == other.addr &&
           scriptPayout == other.scriptPayout &&
           scriptOperatorPayout == other.scriptOperatorPayout;
}

std::string CDeterministicMNState::ToString() const
{
    std::ostringstream ss;
    ss << "CDeterministicMNState("
       << "registeredHeight=" << nRegisteredHeight
       << ", lastPaidHeight=" << nLastPaidHeight
       << ", PoSePenalty=" << nPoSePenalty
       << ", PoSeBanHeight=" << nPoSeBanHeight
       << ", addr=" << addr.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// CDeterministicMN Implementation
// ============================================================================

arith_uint256 CDeterministicMN::CalcScore(const uint256& blockHash) const
{
    // Score calculation for payment ordering
    // Lower score = higher priority for payment
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << proTxHash;
    hw << blockHash;
    return UintToArith256(hw.GetHash());
}

std::string CDeterministicMN::ToString() const
{
    std::ostringstream ss;
    ss << "CDeterministicMN("
       << "proTxHash=" << proTxHash.ToString()
       << ", collateral=" << collateralOutpoint.ToString()
       << ", operatorReward=" << nOperatorReward
       << ", valid=" << IsValid()
       << ", " << state.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// CDeterministicMNList Implementation
// ============================================================================

size_t CDeterministicMNList::GetValidMNsCount() const
{
    size_t count = 0;
    for (const auto& pair : mnMap) {
        if (pair.second->IsValid()) {
            count++;
        }
    }
    return count;
}

CDeterministicMNCPtr CDeterministicMNList::GetMN(const uint256& proTxHash) const
{
    auto it = mnMap.find(proTxHash);
    if (it == mnMap.end()) {
        return nullptr;
    }
    return it->second;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByOperatorKey(const std::vector<unsigned char>& vchPubKey) const
{
    for (const auto& pair : mnMap) {
        if (pair.second->state.vchOperatorPubKey == vchPubKey) {
            return pair.second;
        }
    }
    return nullptr;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByCollateral(const COutPoint& collateralOutpoint) const
{
    for (const auto& pair : mnMap) {
        if (pair.second->collateralOutpoint == collateralOutpoint) {
            return pair.second;
        }
    }
    return nullptr;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByService(const CService& addr) const
{
    for (const auto& pair : mnMap) {
        if (pair.second->state.addr == addr) {
            return pair.second;
        }
    }
    return nullptr;
}

bool CDeterministicMNList::HasUniqueProperty(const uint256& propertyHash) const
{
    return mnUniquePropertyMap.count(propertyHash) > 0;
}

uint256 CDeterministicMNList::GetUniquePropertyHash(const COutPoint& outpoint) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("utxo");
    hw << outpoint;
    return hw.GetHash();
}

uint256 CDeterministicMNList::GetUniquePropertyHash(const CService& addr) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("addr");
    hw << addr;
    return hw.GetHash();
}

uint256 CDeterministicMNList::GetUniquePropertyHash(const CKeyID& keyId) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("key");
    hw << keyId;
    return hw.GetHash();
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetValidMNsForPayment() const
{
    std::vector<CDeterministicMNCPtr> result;
    for (const auto& pair : mnMap) {
        if (pair.second->IsValid()) {
            result.push_back(pair.second);
        }
    }
    return result;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNPayee(const uint256& blockHashForPayment) const
{
    // Get all valid masternodes
    std::vector<CDeterministicMNCPtr> validMNs = GetValidMNsForPayment();
    if (validMNs.empty()) {
        return nullptr;
    }

    // Calculate scores and find the one with lowest score (highest priority)
    CDeterministicMNCPtr winner = nullptr;
    arith_uint256 lowestScore = arith_uint256();
    bool first = true;

    for (const auto& mn : validMNs) {
        arith_uint256 score = mn->CalcScore(blockHashForPayment);
        
        if (first || score < lowestScore) {
            winner = mn;
            lowestScore = score;
            first = false;
        }
    }

    return winner;
}

CDeterministicMNList CDeterministicMNList::AddMN(const CDeterministicMNCPtr& mn) const
{
    CDeterministicMNList result(*this);
    result.mnMap[mn->proTxHash] = mn;
    
    // Add unique property entries
    result.mnUniquePropertyMap[GetUniquePropertyHash(mn->collateralOutpoint)] = mn->proTxHash;
    result.mnUniquePropertyMap[GetUniquePropertyHash(mn->state.addr)] = mn->proTxHash;
    result.mnUniquePropertyMap[GetUniquePropertyHash(mn->state.keyIDOwner)] = mn->proTxHash;
    
    result.nTotalRegisteredCount++;
    return result;
}

CDeterministicMNList CDeterministicMNList::UpdateMN(const uint256& proTxHash, const CDeterministicMNState& newState) const
{
    auto mn = GetMN(proTxHash);
    if (!mn) {
        return *this; // No change if MN not found
    }

    CDeterministicMNList result(*this);
    
    // Remove old address from unique map if changed
    if (mn->state.addr != newState.addr) {
        result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.addr));
        result.mnUniquePropertyMap[GetUniquePropertyHash(newState.addr)] = proTxHash;
    }
    
    // Create updated MN entry
    auto newMN = std::make_shared<CDeterministicMN>(*mn);
    newMN->state = newState;
    result.mnMap[proTxHash] = newMN;
    
    return result;
}

CDeterministicMNList CDeterministicMNList::RemoveMN(const uint256& proTxHash) const
{
    auto mn = GetMN(proTxHash);
    if (!mn) {
        return *this;
    }

    CDeterministicMNList result(*this);
    result.mnMap.erase(proTxHash);
    
    // Remove from unique property map
    result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->collateralOutpoint));
    result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.addr));
    result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.keyIDOwner));
    
    return result;
}

std::string CDeterministicMNList::ToString() const
{
    std::ostringstream ss;
    ss << "CDeterministicMNList("
       << "blockHash=" << blockHash.ToString()
       << ", height=" << nHeight
       << ", totalMNs=" << mnMap.size()
       << ", validMNs=" << GetValidMNsCount()
       << ")";
    return ss.str();
}

// ============================================================================
// CDeterministicMNManager Implementation
// ============================================================================

CDeterministicMNManager::CDeterministicMNManager(CEvoDB& _evoDb)
    : evoDb(_evoDb)
{
}

bool CDeterministicMNManager::Init()
{
    LOCK(cs);
    // Initialize with empty list at genesis
    tipList = std::make_shared<CDeterministicMNList>();
    return true;
}

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, 
                                            CValidationState& state, bool fJustCheck)
{
    LOCK(cs);

    // Get the previous list
    CDeterministicMNListCPtr prevList;
    if (pindex->pprev) {
        prevList = GetListForBlock(pindex->pprev);
    }
    if (!prevList) {
        prevList = std::make_shared<CDeterministicMNList>();
    }

    // Build the new list by processing transactions
    CDeterministicMNList newList = *prevList;
    newList = CDeterministicMNList(pindex->GetBlockHash(), pindex->nHeight);
    
    // Copy existing masternodes
    for (const auto& pair : prevList->GetMnMap()) {
        newList = newList.AddMN(pair.second);
    }

    // Process each transaction in the block
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        
        if (!IsTxTypeSpecial(tx)) {
            continue;
        }

        TxType txType = GetTxType(tx);
        
        switch (txType) {
            case TxType::TRANSACTION_PROVIDER_REGISTER: {
                CProRegTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
                }

                // Create new masternode entry
                auto newMN = std::make_shared<CDeterministicMN>();
                newMN->proTxHash = tx.GetHash();
                newMN->collateralOutpoint = proTx.collateralOutpoint;
                newMN->nOperatorReward = proTx.nOperatorReward;
                newMN->state.nRegisteredHeight = pindex->nHeight;
                newMN->state.keyIDOwner = proTx.keyIDOwner;
                newMN->state.vchOperatorPubKey = proTx.vchOperatorPubKey;
                newMN->state.keyIDVoting = proTx.keyIDVoting;
                newMN->state.addr = proTx.addr;
                newMN->state.scriptPayout = proTx.scriptPayout;
                newMN->internalId = newList.GetTotalRegisteredCount();
                newList.IncrementTotalRegisteredCount();

                newList = newList.AddMN(newMN);
                
                LogPrintf("CDeterministicMNManager::%s -- New MN registered: %s\n", 
                         __func__, newMN->ToString());
                break;
            }
            
            case TxType::TRANSACTION_PROVIDER_UPDATE_SERVICE: {
                CProUpServTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
                }

                auto mn = newList.GetMN(proTx.proTxHash);
                if (!mn) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
                }

                CDeterministicMNState newState = mn->state;
                newState.addr = proTx.addr;
                if (!proTx.scriptOperatorPayout.empty()) {
                    newState.scriptOperatorPayout = proTx.scriptOperatorPayout;
                }

                newList = newList.UpdateMN(proTx.proTxHash, newState);
                
                LogPrintf("CDeterministicMNManager::%s -- MN service updated: %s\n", 
                         __func__, proTx.proTxHash.ToString());
                break;
            }
            
            case TxType::TRANSACTION_PROVIDER_UPDATE_REGISTRAR: {
                CProUpRegTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
                }

                auto mn = newList.GetMN(proTx.proTxHash);
                if (!mn) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
                }

                CDeterministicMNState newState = mn->state;
                if (!proTx.vchOperatorPubKey.empty()) {
                    newState.vchOperatorPubKey = proTx.vchOperatorPubKey;
                }
                if (!proTx.keyIDVoting.IsNull()) {
                    newState.keyIDVoting = proTx.keyIDVoting;
                }
                if (!proTx.scriptPayout.empty()) {
                    newState.scriptPayout = proTx.scriptPayout;
                }

                // Reset PoSe state when operator key changes
                if (proTx.vchOperatorPubKey != mn->state.vchOperatorPubKey) {
                    newState.nPoSePenalty = 0;
                    newState.nPoSeBanHeight = -1;
                    newState.nPoSeRevivedHeight = pindex->nHeight;
                }

                newList = newList.UpdateMN(proTx.proTxHash, newState);
                
                LogPrintf("CDeterministicMNManager::%s -- MN registrar updated: %s\n", 
                         __func__, proTx.proTxHash.ToString());
                break;
            }
            
            case TxType::TRANSACTION_PROVIDER_UPDATE_REVOKE: {
                CProUpRevTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
                }

                auto mn = newList.GetMN(proTx.proTxHash);
                if (!mn) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
                }

                CDeterministicMNState newState = mn->state;
                newState.nRevocationReason = proTx.nReason;
                newState.nPoSeBanHeight = pindex->nHeight;

                newList = newList.UpdateMN(proTx.proTxHash, newState);
                
                LogPrintf("CDeterministicMNManager::%s -- MN revoked: %s, reason=%d\n", 
                         __func__, proTx.proTxHash.ToString(), proTx.nReason);
                break;
            }
            
            default:
                break;
        }
    }

    if (!fJustCheck) {
        // Store the new list
        auto newListPtr = std::make_shared<CDeterministicMNList>(newList);
        mnListsCache[pindex->GetBlockHash()] = newListPtr;
        tipList = newListPtr;
        
        // Persist to database
        SaveListToDb(newListPtr);
        
        // Cleanup old cache entries
        CleanupCache();
    }

    return true;
}

bool CDeterministicMNManager::UndoBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs);

    // Remove the list for this block from cache
    mnListsCache.erase(pindex->GetBlockHash());

    // Set tip to previous block's list
    if (pindex->pprev) {
        tipList = GetListForBlock(pindex->pprev);
    } else {
        tipList = std::make_shared<CDeterministicMNList>();
    }

    return true;
}

CDeterministicMNListCPtr CDeterministicMNManager::GetListForBlock(const CBlockIndex* pindex)
{
    LOCK(cs);

    if (!pindex) {
        return std::make_shared<CDeterministicMNList>();
    }

    // Check cache first
    auto it = mnListsCache.find(pindex->GetBlockHash());
    if (it != mnListsCache.end()) {
        return it->second;
    }

    // Try to load from database
    auto list = LoadListFromDb(pindex->GetBlockHash());
    if (list) {
        mnListsCache[pindex->GetBlockHash()] = list;
        return list;
    }

    // Build from scratch if not found (shouldn't happen in normal operation)
    return std::make_shared<CDeterministicMNList>(pindex->GetBlockHash(), pindex->nHeight);
}

CDeterministicMNListCPtr CDeterministicMNManager::GetListAtChainTip()
{
    LOCK(cs);
    return tipList ? tipList : std::make_shared<CDeterministicMNList>();
}

CDeterministicMNCPtr CDeterministicMNManager::GetMN(const uint256& proTxHash) const
{
    LOCK(cs);
    if (!tipList) return nullptr;
    return tipList->GetMN(proTxHash);
}

bool CDeterministicMNManager::HasMN(const uint256& proTxHash) const
{
    return GetMN(proTxHash) != nullptr;
}

CDeterministicMNCPtr CDeterministicMNManager::GetMNByCollateral(const COutPoint& outpoint) const
{
    LOCK(cs);
    if (!tipList) return nullptr;
    return tipList->GetMNByCollateral(outpoint);
}

bool CDeterministicMNManager::IsProTxWithCollateral(const COutPoint& outpoint) const
{
    return GetMNByCollateral(outpoint) != nullptr;
}

CDeterministicMNCPtr CDeterministicMNManager::GetMNPayee(const CBlockIndex* pindex) const
{
    LOCK(cs);
    
    if (!pindex) return nullptr;
    
    auto list = const_cast<CDeterministicMNManager*>(this)->GetListForBlock(pindex);
    if (!list) return nullptr;
    
    return list->GetMNPayee(pindex->GetBlockHash());
}

void CDeterministicMNManager::UpdatedBlockTip(const CBlockIndex* pindex)
{
    LOCK(cs);
    tipList = GetListForBlock(pindex);
}

void CDeterministicMNManager::SaveListToDb(const CDeterministicMNListCPtr& list)
{
    evoDb.Write(std::make_pair(DB_LIST_SNAPSHOT, list->GetBlockHash()), *list);
}

CDeterministicMNListCPtr CDeterministicMNManager::LoadListFromDb(const uint256& blockHash)
{
    CDeterministicMNList list;
    if (evoDb.Read(std::make_pair(DB_LIST_SNAPSHOT, blockHash), list)) {
        return std::make_shared<CDeterministicMNList>(list);
    }
    return nullptr;
}

void CDeterministicMNManager::CleanupCache()
{
    while (mnListsCache.size() > MAX_CACHE_SIZE) {
        // Remove oldest entry (simple approach - could be improved with LRU)
        mnListsCache.erase(mnListsCache.begin());
    }
}

