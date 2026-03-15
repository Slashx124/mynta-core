// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evo/deterministicmns.h"
#include "evo/providertx.h"
#include "evo/evodb.h"
#include "evo/specialtx.h"
#include "evo/pose.h"

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

const int CDeterministicMNManager::CURRENT_DB_VERSION;
const size_t CDeterministicMNManager::MAX_CACHE_SIZE;

// Database keys
static const std::string DB_LIST_SNAPSHOT = "dmn_S";
static const std::string DB_LIST_DIFF = "dmn_D";

// ============================================================================
// Masternode Activation Helpers
// ============================================================================

bool IsMasternodeActivationHeight(int nHeight)
{
    const auto& consensusParams = GetParams().GetConsensus();
    return nHeight >= consensusParams.nMasternodeActivationHeight;
}

bool IsMasternodePaymentEnforced(int nHeight)
{
    const auto& consensusParams = GetParams().GetConsensus();
    
    // Payments not enforced before tiered activation height.
    // All blocks before nTieredMNActivationHeight were mined under v1.2.x
    // rules which did not enforce deterministic MN payments. Enforcing
    // payments on those historical blocks causes consensus failures because
    // the EvoDB rebuilt from scratch may differ from the state at mining time.
    if (nHeight < consensusParams.nTieredMNActivationHeight) {
        return false;
    }
    
    int gracePeriod = GetMasternodePaymentGracePeriod();
    return nHeight >= (consensusParams.nTieredMNActivationHeight + gracePeriod);
}

int GetMasternodeActivationHeight()
{
    const auto& consensusParams = GetParams().GetConsensus();
    return consensusParams.nMasternodeActivationHeight;
}

int GetMasternodePaymentGracePeriod()
{
    return GetParams().GetConsensus().nMasternodePaymentGracePeriod;
}

// ============================================================================
// Masternode Tier Helpers
// ============================================================================

uint8_t GetMasternodeTier(CAmount collateralAmount, int nHeight)
{
    const auto& cp = GetParams().GetConsensus();
    if (nHeight >= cp.nTieredMNActivationHeight) {
        if (collateralAmount == cp.nMasternodeCollateralTier3) return 3;
        if (collateralAmount == cp.nMasternodeCollateralTier2) return 2;
    }
    if (collateralAmount == cp.nMasternodeCollateral) return 1;
    return 0;
}

int GetTierWeight(uint8_t nTier)
{
    switch (nTier) {
        case 2:  return 10;
        case 3:  return 100;
        default: return 1;
    }
}

std::string GetTierName(uint8_t nTier)
{
    switch (nTier) {
        case 2:  return "super";
        case 3:  return "ultra";
        default: return "standard";
    }
}

bool IsValidCollateralAmount(CAmount amount, int nHeight)
{
    return GetMasternodeTier(amount, nHeight) != 0;
}

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
           nTier == other.nTier &&
           nLastServiceUpdateHeight == other.nLastServiceUpdateHeight &&
           nLastRegistrarUpdateHeight == other.nLastRegistrarUpdateHeight &&
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
       << ", tier=" << GetTierName(nTier)
       << ", addr=" << addr.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// CDeterministicMN Implementation
// ============================================================================

arith_uint256 CDeterministicMN::CalcScore(const uint256& blockHash, int currentHeight) const
{
    // Score calculation for payment ordering.
    // Lower score = higher priority for payment.
    //
    // Payment history is included so MNs that haven't been paid recently
    // are more likely to be selected.
    //
    // Tier weighting: the raw hash score is divided by the tier weight
    // (1 / 10 / 100).  Higher-tier nodes get a lower effective score,
    // making them proportionally more likely to win each round.
    // This uses arith_uint256 integer division — fully deterministic.

    int lastPaid = state.nLastPaidHeight > 0 ? state.nLastPaidHeight : state.nRegisteredHeight;
    int blocksSincePayment = std::max(0, currentHeight - lastPaid);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << proTxHash;
    hw << blockHash;
    hw << blocksSincePayment;

    arith_uint256 rawScore = UintToArith256(hw.GetHash());

    int weight = GetTierWeight(state.nTier);
    if (weight > 1) {
        rawScore /= weight;
    }

    return rawScore;
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
    uint256 propHash = GetOperatorKeyHash(vchPubKey);
    auto it = mnUniquePropertyMap.find(propHash);
    if (it != mnUniquePropertyMap.end()) {
        return GetMN(it->second);
    }
    return nullptr;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByCollateral(const COutPoint& collateralOutpoint) const
{
    uint256 propHash = GetUniquePropertyHash(collateralOutpoint);
    auto it = mnUniquePropertyMap.find(propHash);
    if (it != mnUniquePropertyMap.end()) {
        return GetMN(it->second);
    }
    return nullptr;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByService(const CService& addr) const
{
    uint256 propHash = GetUniquePropertyHash(addr);
    auto it = mnUniquePropertyMap.find(propHash);
    if (it != mnUniquePropertyMap.end()) {
        return GetMN(it->second);
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

uint256 CDeterministicMNList::GetUniquePropertyHash(const std::vector<unsigned char>& vchPubKey) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("operator");
    hw << vchPubKey;
    return hw.GetHash();
}

uint256 CDeterministicMNList::GetVotingKeyHash(const CKeyID& keyId) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("voting");
    hw << keyId;
    return hw.GetHash();
}

uint256 CDeterministicMNList::GetOperatorKeyHash(const std::vector<unsigned char>& vchPubKey) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("operator");
    hw << vchPubKey;
    return hw.GetHash();
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetValidMNsForPayment() const
{
    return GetValidMNsForPayment(nHeight);
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetValidMNsForPayment(int currentHeight) const
{
    const auto& consensusParams = GetParams().GetConsensus();
    std::vector<CDeterministicMNCPtr> result;
    
    for (const auto& pair : mnMap) {
        if (!pair.second->IsValid()) {
            continue;
        }

        // Reject MNs with invalid tier (nTier==0 means the collateral
        // didn't match any valid tier at registration time).
        if (pair.second->state.nTier == 0) {
            continue;
        }

        // Require confirmations before eligible for payment.
        int confirmations = currentHeight - pair.second->state.nRegisteredHeight;
        if (confirmations < consensusParams.nMasternodeCollateralConfirmations) {
            LogPrint(BCLog::MASTERNODE, "GetValidMNsForPayment: MN %s not mature yet (%d/%d confirmations)\n",
                     pair.second->proTxHash.ToString().substr(0, 16),
                     confirmations,
                     consensusParams.nMasternodeCollateralConfirmations);
            continue;
        }

        result.push_back(pair.second);
    }
    return result;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNPayee(const uint256& blockHashForPayment, int currentHeight) const
{
    std::vector<CDeterministicMNCPtr> validMNs = GetValidMNsForPayment(currentHeight);
    if (validMNs.empty()) {
        LogPrint(BCLog::MASTERNODE, "GetMNPayee(list): No valid MNs eligible at height %d (total=%zu)\n",
                 currentHeight, GetAllMNsCount());
        return nullptr;
    }

    LogPrint(BCLog::MASTERNODE, "GetMNPayee(list): scoring %zu eligible MNs at height=%d entropy=%s\n",
             validMNs.size(), currentHeight, blockHashForPayment.ToString().substr(0, 16));

    CDeterministicMNCPtr winner = nullptr;
    arith_uint256 lowestScore = arith_uint256();
    bool first = true;

    for (const auto& mn : validMNs) {
        arith_uint256 score = mn->CalcScore(blockHashForPayment, currentHeight);

        if (first || score < lowestScore ||
            (score == lowestScore && UintToArith256(mn->proTxHash) < UintToArith256(winner->proTxHash))) {
            winner = mn;
            lowestScore = score;
            first = false;
        }
    }

    if (winner) {
        LogPrint(BCLog::MASTERNODE, "GetMNPayee(list): winner=%s tier=%s lastPaid=%d score=%s height=%d\n",
                 winner->proTxHash.ToString().substr(0, 16), GetTierName(winner->state.nTier),
                 winner->state.nLastPaidHeight, lowestScore.GetHex().substr(0, 16), currentHeight);
    }

    return winner;
}

CDeterministicMNList CDeterministicMNList::AddMN(const CDeterministicMNCPtr& mn) const
{
    CDeterministicMNList result(*this);
    result.mnMap[mn->proTxHash] = mn;

    // Defense-in-depth: warn if a unique property already belongs to a different MN.
    // Validation should prevent this, but silent overwrites would corrupt the index.
    auto warnIfConflict = [&](const uint256& propHash, const char* label) {
        auto it = result.mnUniquePropertyMap.find(propHash);
        if (it != result.mnUniquePropertyMap.end() && it->second != mn->proTxHash) {
            LogPrintf("WARNING: AddMN: %s collision — existing MN %s, new MN %s\n",
                      label, it->second.ToString().substr(0, 16), mn->proTxHash.ToString().substr(0, 16));
        }
    };

    uint256 addrHash = GetUniquePropertyHash(mn->state.addr);
    uint256 collHash = GetUniquePropertyHash(mn->collateralOutpoint);
    uint256 ownerHash = GetUniquePropertyHash(mn->state.keyIDOwner);
    uint256 voteHash = GetVotingKeyHash(mn->state.keyIDVoting);
    uint256 opHash = GetOperatorKeyHash(mn->state.vchOperatorPubKey);

    warnIfConflict(addrHash, "service address");
    warnIfConflict(collHash, "collateral");
    warnIfConflict(ownerHash, "owner key");
    warnIfConflict(voteHash, "voting key");
    warnIfConflict(opHash, "operator key");

    result.mnUniquePropertyMap[collHash] = mn->proTxHash;
    result.mnUniquePropertyMap[addrHash] = mn->proTxHash;
    result.mnUniquePropertyMap[ownerHash] = mn->proTxHash;
    result.mnUniquePropertyMap[voteHash] = mn->proTxHash;
    result.mnUniquePropertyMap[opHash] = mn->proTxHash;

    result.nTotalRegisteredCount++;
    return result;
}

void CDeterministicMNList::AddMNInPlace(const CDeterministicMNCPtr& mn)
{
    mnMap[mn->proTxHash] = mn;

    auto warnIfConflict = [&](const uint256& propHash, const char* label) {
        auto it = mnUniquePropertyMap.find(propHash);
        if (it != mnUniquePropertyMap.end() && it->second != mn->proTxHash) {
            LogPrintf("WARNING: AddMNInPlace: %s collision — existing MN %s, new MN %s\n",
                      label, it->second.ToString().substr(0, 16), mn->proTxHash.ToString().substr(0, 16));
        }
    };

    uint256 addrHash = GetUniquePropertyHash(mn->state.addr);
    uint256 collHash = GetUniquePropertyHash(mn->collateralOutpoint);
    uint256 ownerHash = GetUniquePropertyHash(mn->state.keyIDOwner);
    uint256 voteHash = GetVotingKeyHash(mn->state.keyIDVoting);
    uint256 opHash = GetOperatorKeyHash(mn->state.vchOperatorPubKey);

    warnIfConflict(addrHash, "service address");
    warnIfConflict(collHash, "collateral");
    warnIfConflict(ownerHash, "owner key");
    warnIfConflict(voteHash, "voting key");
    warnIfConflict(opHash, "operator key");

    mnUniquePropertyMap[collHash] = mn->proTxHash;
    mnUniquePropertyMap[addrHash] = mn->proTxHash;
    mnUniquePropertyMap[ownerHash] = mn->proTxHash;
    mnUniquePropertyMap[voteHash] = mn->proTxHash;
    mnUniquePropertyMap[opHash] = mn->proTxHash;
}

CDeterministicMNList CDeterministicMNList::UpdateMN(const uint256& proTxHash, const CDeterministicMNState& newState) const
{
    auto mn = GetMN(proTxHash);
    if (!mn) {
        LogPrint(BCLog::MASTERNODE, "UpdateMN: MN %s not found in list at height %d, no-op\n",
                 proTxHash.ToString().substr(0, 16), nHeight);
        return *this;
    }

    // Pre-flight: reject the entire update if any changed property would
    // collide with a different MN.  A partial update (state written but map
    // not updated) would leave mnMap and mnUniquePropertyMap inconsistent.
    auto wouldConflict = [&](const uint256& newHash, const char* label) -> bool {
        auto it = mnUniquePropertyMap.find(newHash);
        if (it != mnUniquePropertyMap.end() && it->second != proTxHash) {
            LogPrintf("ERROR: UpdateMN: %s conflict — MN %s trying to claim property owned by MN %s\n",
                      label, proTxHash.ToString().substr(0, 16), it->second.ToString().substr(0, 16));
            return true;
        }
        return false;
    };

    uint256 newAddrHash = GetUniquePropertyHash(newState.addr);
    uint256 newVoteHash = GetVotingKeyHash(newState.keyIDVoting);
    uint256 newOpHash   = GetOperatorKeyHash(newState.vchOperatorPubKey);

    if ((mn->state.addr != newState.addr && wouldConflict(newAddrHash, "service address")) ||
        (mn->state.keyIDVoting != newState.keyIDVoting && wouldConflict(newVoteHash, "voting key")) ||
        (mn->state.vchOperatorPubKey != newState.vchOperatorPubKey && wouldConflict(newOpHash, "operator key"))) {
        return *this;
    }

    CDeterministicMNList result(*this);

    if (mn->state.addr != newState.addr) {
        result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.addr));
        result.mnUniquePropertyMap[newAddrHash] = proTxHash;
    }
    if (mn->state.keyIDVoting != newState.keyIDVoting) {
        result.mnUniquePropertyMap.erase(GetVotingKeyHash(mn->state.keyIDVoting));
        result.mnUniquePropertyMap[newVoteHash] = proTxHash;
    }
    if (mn->state.vchOperatorPubKey != newState.vchOperatorPubKey) {
        result.mnUniquePropertyMap.erase(GetOperatorKeyHash(mn->state.vchOperatorPubKey));
        result.mnUniquePropertyMap[newOpHash] = proTxHash;
    }

    auto newMN = std::make_shared<CDeterministicMN>(*mn);
    newMN->state = newState;
    result.mnMap[proTxHash] = newMN;

    return result;
}

CDeterministicMNList CDeterministicMNList::BatchUpdateMNStates(
    const std::vector<std::pair<uint256, CDeterministicMNState>>& updates) const
{
    if (updates.empty()) return *this;

    CDeterministicMNList result(*this);

    for (const auto& update : updates) {
        const uint256& proTxHash = update.first;
        const CDeterministicMNState& newState = update.second;

        auto it = result.mnMap.find(proTxHash);
        if (it == result.mnMap.end()) continue;

        const auto& oldState = it->second->state;

        // Pre-flight conflict check — skip this MN entirely if any
        // changed property would collide with a different MN.
        uint256 newAddrHash = GetUniquePropertyHash(newState.addr);
        uint256 newVoteHash = GetVotingKeyHash(newState.keyIDVoting);
        uint256 newOpHash   = GetOperatorKeyHash(newState.vchOperatorPubKey);

        auto wouldConflict = [&](const uint256& newHash, const char* label) -> bool {
            auto c = result.mnUniquePropertyMap.find(newHash);
            if (c != result.mnUniquePropertyMap.end() && c->second != proTxHash) {
                LogPrintf("ERROR: BatchUpdateMNStates: %s conflict — MN %s vs MN %s\n",
                          label, proTxHash.ToString().substr(0, 16), c->second.ToString().substr(0, 16));
                return true;
            }
            return false;
        };

        if ((oldState.addr != newState.addr && wouldConflict(newAddrHash, "service address")) ||
            (oldState.keyIDVoting != newState.keyIDVoting && wouldConflict(newVoteHash, "voting key")) ||
            (oldState.vchOperatorPubKey != newState.vchOperatorPubKey && wouldConflict(newOpHash, "operator key"))) {
            continue;
        }

        if (oldState.addr != newState.addr) {
            result.mnUniquePropertyMap.erase(GetUniquePropertyHash(oldState.addr));
            result.mnUniquePropertyMap[newAddrHash] = proTxHash;
        }
        if (oldState.keyIDVoting != newState.keyIDVoting) {
            result.mnUniquePropertyMap.erase(GetVotingKeyHash(oldState.keyIDVoting));
            result.mnUniquePropertyMap[newVoteHash] = proTxHash;
        }
        if (oldState.vchOperatorPubKey != newState.vchOperatorPubKey) {
            result.mnUniquePropertyMap.erase(GetOperatorKeyHash(oldState.vchOperatorPubKey));
            result.mnUniquePropertyMap[newOpHash] = proTxHash;
        }

        auto newMN = std::make_shared<CDeterministicMN>(*it->second);
        newMN->state = newState;
        result.mnMap[proTxHash] = newMN;
    }

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
    
    // Also remove voting and operator keys
    result.mnUniquePropertyMap.erase(GetVotingKeyHash(mn->state.keyIDVoting));
    result.mnUniquePropertyMap.erase(GetOperatorKeyHash(mn->state.vchOperatorPubKey));
    
    return result;
}

CDeterministicMNList CDeterministicMNList::BatchRemoveMNs(const std::vector<uint256>& proTxHashes) const
{
    if (proTxHashes.empty()) return *this;
    
    CDeterministicMNList result(*this);
    
    for (const uint256& proTxHash : proTxHashes) {
        auto it = result.mnMap.find(proTxHash);
        if (it == result.mnMap.end()) continue;
        
        const auto& mn = it->second;
        result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->collateralOutpoint));
        result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.addr));
        result.mnUniquePropertyMap.erase(GetUniquePropertyHash(mn->state.keyIDOwner));
        result.mnUniquePropertyMap.erase(GetVotingKeyHash(mn->state.keyIDVoting));
        result.mnUniquePropertyMap.erase(GetOperatorKeyHash(mn->state.vchOperatorPubKey));
        result.mnMap.erase(proTxHash);
    }
    
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

static const std::string DB_MN_VERSION = "dmn_ver";

bool CDeterministicMNManager::Init()
{
    LOCK(cs);

    int storedVersion = 0;
    evoDb.Read(DB_MN_VERSION, storedVersion);

    if (storedVersion < CURRENT_DB_VERSION) {
        LogPrintf("CDeterministicMNManager: DB version %d < %d, erasing stale EvoDB snapshots for resync\n",
                  storedVersion, CURRENT_DB_VERSION);
        mnListsCache.clear();

        {
            CDBWrapper& rawDb = evoDb.GetRawDB();
            std::unique_ptr<CDBIterator> pcursor(rawDb.NewIterator());
            auto prefix = std::make_pair(DB_LIST_SNAPSHOT, uint256());
            pcursor->Seek(prefix);

            std::vector<std::pair<std::string, uint256>> keysToErase;
            while (pcursor->Valid()) {
                std::pair<std::string, uint256> key;
                if (!pcursor->GetKey(key) || key.first != DB_LIST_SNAPSHOT) {
                    break;
                }
                keysToErase.push_back(key);
                pcursor->Next();
            }

            for (const auto& key : keysToErase) {
                evoDb.Erase(key);
            }
            LogPrintf("CDeterministicMNManager: Erased %d stale MN list snapshots from EvoDB\n",
                      keysToErase.size());
        }

        evoDb.Write(DB_MN_VERSION, CURRENT_DB_VERSION);
    }

    tipList = std::make_shared<CDeterministicMNList>();
    return true;
}

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, 
                                            CValidationState& state, bool fJustCheck)
{
    LOCK(cs);

    CDeterministicMNListCPtr prevList;
    if (pindex->pprev) {
        prevList = GetListForBlock(pindex->pprev);
    }
    if (!prevList) {
        prevList = std::make_shared<CDeterministicMNList>();
    }

    LogPrint(BCLog::MASTERNODE, "ProcessBlock: height=%d prevMNs=%zu prevRegistered=%llu\n",
             pindex->nHeight, prevList->GetAllMNsCount(), prevList->GetTotalRegisteredCount());

    CDeterministicMNList newList(pindex->GetBlockHash(), pindex->nHeight);
    newList.SetTotalRegisteredCount(prevList->GetTotalRegisteredCount());
    for (const auto& pair : prevList->GetMnMap()) {
        newList.AddMNInPlace(pair.second);
    }

    // ============================================================
    // MN v2 MIGRATION: At the migration height, wipe the entire MN
    // list.  All pre-v2 masternodes are invalidated; operators must
    // re-register with a new ProRegTx.  Collateral UTXOs are NOT
    // burned — they can be referenced by a fresh ProRegTx.
    // ============================================================
    const auto& cp = GetParams().GetConsensus();
    const bool fMigrationBlock = (pindex->nHeight == cp.nMNv2MigrationHeight);
    if (fMigrationBlock) {
        LogPrintf("CDeterministicMNManager: ========================================\n");
        LogPrintf("CDeterministicMNManager: MN v2 MIGRATION at height %d\n", pindex->nHeight);
        LogPrintf("CDeterministicMNManager: Invalidating %zu pre-v2 masternodes\n", newList.GetAllMNsCount());
        LogPrintf("CDeterministicMNManager: Operators must re-register after this block\n");
        LogPrintf("CDeterministicMNManager: ========================================\n");
        newList = CDeterministicMNList(pindex->GetBlockHash(), pindex->nHeight);
        newList.SetTotalRegisteredCount(0);
    }

    // ============================================================
    // CRITICAL FIX: Detect and remove masternodes with spent collateral
    // Skip on migration block — the list was just wiped.
    // ============================================================
    if (!fMigrationBlock) {
        std::vector<uint256> masternodesToRemove;
        
        for (size_t i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *block.vtx[i];
            
            if (tx.IsCoinBase()) {
                continue;
            }
            
            for (const CTxIn& txin : tx.vin) {
                auto mn = newList.GetMNByCollateral(txin.prevout);
                if (mn) {
                    LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- Collateral spent for MN %s "
                             "(collateral %s spent in tx %s)\n",
                             __func__,
                             mn->proTxHash.ToString(),
                             txin.prevout.ToString(),
                             tx.GetHash().ToString());
                    
                    masternodesToRemove.push_back(mn->proTxHash);
                }
            }
        }
        
        for (const uint256& proTxHash : masternodesToRemove) {
            LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- Removed MN %s due to spent collateral\n",
                     __func__, proTxHash.ToString());
        }
        newList = newList.BatchRemoveMNs(masternodesToRemove);
    }

    // Process each transaction in the block
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        
        if (!IsTxTypeSpecial(tx)) {
            continue;
        }
        LogPrint(BCLog::MASTERNODE, "ProcessBlock: special tx %s type=%d at height=%d\n",
                 tx.GetHash().ToString().substr(0, 16), tx.nType, pindex->nHeight);

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

                {
                    AssertLockHeld(cs_main);
                    const Coin& collCoin = pcoinsTip->AccessCoin(proTx.collateralOutpoint);
                    newMN->state.nTier = GetMasternodeTier(collCoin.out.nValue, pindex->nHeight);
                }

                newList = newList.AddMN(newMN);
                
                LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- New MN registered: %s (tier=%s)\n", 
                         __func__, newMN->ToString(), GetTierName(newMN->state.nTier));
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
                newState.nLastServiceUpdateHeight = pindex->nHeight;
                if (!proTx.scriptOperatorPayout.empty()) {
                    newState.scriptOperatorPayout = proTx.scriptOperatorPayout;
                }

                newList = newList.UpdateMN(proTx.proTxHash, newState);
                
                LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- MN service updated: %s\n", 
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
                newState.nLastRegistrarUpdateHeight = pindex->nHeight;
                if (!proTx.vchOperatorPubKey.empty()) {
                    newState.vchOperatorPubKey = proTx.vchOperatorPubKey;
                }
                if (!proTx.keyIDVoting.IsNull()) {
                    newState.keyIDVoting = proTx.keyIDVoting;
                }
                if (!proTx.scriptPayout.empty()) {
                    newState.scriptPayout = proTx.scriptPayout;
                }

                // Reset PoSe state when operator key changes, but NOT if the
                // MN was revoked — revocation is permanent and the owner
                // should not be able to undo it by churning operator keys.
                if (proTx.vchOperatorPubKey != mn->state.vchOperatorPubKey &&
                    mn->state.nRevocationReason == 0) {
                    newState.nPoSePenalty = 0;
                    newState.nPoSeBanHeight = -1;
                    newState.nPoSeRevivedHeight = pindex->nHeight;
                }

                newList = newList.UpdateMN(proTx.proTxHash, newState);
                
                LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- MN registrar updated: %s\n", 
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
                
                LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- MN revoked: %s, reason=%d\n", 
                         __func__, proTx.proTxHash.ToString(), proTx.nReason);
                break;
            }
            
            default:
                break;
        }
    }

    // ============================================================
    // Post-ProTx checks: collateral-spent, tier verification, payee
    // update, and PoSe processing.  All skipped on the migration
    // block because the list was wiped — only fresh ProRegTx from
    // this block exist, and there is no previous payee or PoSe state.
    // ============================================================
    if (!fMigrationBlock) {
        // Second-pass collateral-spent check: catch MNs registered in
        // this block whose collateral was ALSO spent in this block.
        {
            std::vector<uint256> lateRemovals;
            for (size_t i = 0; i < block.vtx.size(); i++) {
                const CTransaction& tx = *block.vtx[i];
                if (tx.IsCoinBase()) continue;
                for (const CTxIn& txin : tx.vin) {
                    auto mn = newList.GetMNByCollateral(txin.prevout);
                    if (mn) {
                        lateRemovals.push_back(mn->proTxHash);
                        LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- Late collateral-spent: MN %s "
                                 "(collateral %s spent in tx %s)\n",
                                 __func__, mn->proTxHash.ToString(),
                                 txin.prevout.ToString(), tx.GetHash().ToString());
                    }
                }
            }
            newList = newList.BatchRemoveMNs(lateRemovals);
        }

        // Verify collateral amounts still match stored tiers.
        {
            AssertLockHeld(cs_main);
            std::vector<uint256> tierMismatches;
            for (const auto& pair : newList.GetMnMap()) {
                const Coin& collCoin = pcoinsTip->AccessCoin(pair.second->collateralOutpoint);
                if (collCoin.IsSpent()) continue;
                uint8_t expectedTier = GetMasternodeTier(collCoin.out.nValue, pindex->nHeight);
                if (expectedTier == 0 || expectedTier != pair.second->state.nTier) {
                    tierMismatches.push_back(pair.first);
                    LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- Tier mismatch for MN %s: "
                             "stored=%d expected=%d (collateral value changed after reorg)\n",
                             __func__, pair.first.ToString().substr(0, 16),
                             pair.second->state.nTier, expectedTier);
                }
            }
            newList = newList.BatchRemoveMNs(tierMismatches);
        }

        // Update nLastPaidHeight for the paid masternode
        {
            if (prevList && prevList->GetValidMNsCount() > 0 && pindex->pprev) {
                assert(pindex->pprev->GetBlockHash() == prevList->GetBlockHash());
                CDeterministicMNCPtr payee = prevList->GetMNPayee(pindex->pprev->GetBlockHash(), pindex->nHeight);
                if (payee) {
                    auto paidMN = newList.GetMN(payee->proTxHash);
                    if (paidMN) {
                        CDeterministicMNState updatedState = paidMN->state;
                        updatedState.nLastPaidHeight = pindex->nHeight;
                        newList = newList.UpdateMN(payee->proTxHash, updatedState);
                        
                        LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- Updated nLastPaidHeight for MN %s to %d\n",
                                 __func__, payee->proTxHash.ToString().substr(0, 16), pindex->nHeight);
                    }
                }
            }
        }
        
        // Apply PoSe (Proof of Service) Penalties
        {
            const auto& consensusParams = GetParams().GetConsensus();

            if (poseManager) {
                std::vector<uint256> affectedMNs;
                for (const auto& penaltyPair : poseManager->GetAllPenalties()) {
                    affectedMNs.push_back(penaltyPair.first);
                }
                for (const auto& pair : newList.GetMnMap()) {
                    if (pair.second->state.IsBanned() &&
                        pair.second->state.nRevocationReason == 0 &&
                        (pindex->nHeight - pair.second->state.nPoSeBanHeight) >= consensusParams.nPoSeRevivalHeight) {
                        affectedMNs.push_back(pair.first);
                    }
                }
                if (!affectedMNs.empty()) {
                    poseManager->PrepareUndo(pindex->nHeight, affectedMNs);
                }

                newList = poseManager->CheckAndPunish(
                    newList,
                    pindex->nHeight,
                    consensusParams.nPoSePenaltyIncrement,
                    consensusParams.nPoSeBanThreshold);
            }
            
            // PoSe revival
            std::vector<uint256> mnsToRevive;
            for (const auto& pair : newList.GetMnMap()) {
                if (!pair.second->state.IsBanned()) continue;
                if (pair.second->state.nRevocationReason != 0) continue;

                int heightsSinceBan = pindex->nHeight - pair.second->state.nPoSeBanHeight;
                if (heightsSinceBan >= consensusParams.nPoSeRevivalHeight) {
                    mnsToRevive.push_back(pair.first);
                }
            }

            for (const uint256& proTxHash : mnsToRevive) {
                auto mn = newList.GetMN(proTxHash);
                if (!mn) continue;

                CDeterministicMNState revivedState = mn->state;
                revivedState.nPoSeBanHeight = -1;
                revivedState.nPoSePenalty = 0;
                revivedState.nPoSeRevivedHeight = pindex->nHeight;
                revivedState.nLastPaidHeight = pindex->nHeight;

                newList = newList.UpdateMN(proTxHash, revivedState);

                if (poseManager) {
                    poseManager->ResetPenalty(proTxHash);
                }

                LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager::%s -- MN %s revived after %d blocks (lastPaid reset)\n",
                         __func__, proTxHash.ToString().substr(0, 16),
                         pindex->nHeight - mn->state.nPoSeBanHeight);
            }
        }
    } // !fMigrationBlock

    if (!fJustCheck) {
        auto newListPtr = std::make_shared<CDeterministicMNList>(newList);

        // Wrap all EvoDB writes in a transaction so they are atomic.
        // If the node crashes before CommitTransaction, no partial
        // state is persisted, preventing EvoDB/block-index divergence.
        evoDb.BeginTransaction();
        try {
            SaveListToDb(newListPtr);
            if (poseManager) {
                poseManager->Flush();
            }
            evoDb.CommitTransaction();
        } catch (...) {
            evoDb.RollbackTransaction();
            return state.DoS(0, false, REJECT_INVALID, "evodb-write-failed");
        }

        mnListsCache[pindex->GetBlockHash()] = newListPtr;
        tipList = newListPtr;
        CleanupCache();

        LogPrint(BCLog::MASTERNODE, "ProcessBlock: height=%d COMMITTED — totalMNs=%zu validMNs=%zu registered=%llu cacheSize=%zu\n",
                 pindex->nHeight, newList.GetAllMNsCount(), newList.GetValidMNsCount(),
                 newList.GetTotalRegisteredCount(), mnListsCache.size());
    }

    return true;
}

bool CDeterministicMNManager::UndoBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs);

    LogPrint(BCLog::MASTERNODE, "UndoBlock: reverting height=%d hash=%s cacheSize=%zu\n",
             pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 16), mnListsCache.size());

    // Remove from cache AND delete the now-stale EvoDB snapshot so it
    // cannot be loaded on restart after a reorg.
    mnListsCache.erase(pindex->GetBlockHash());
    evoDb.Erase(std::make_pair(DB_LIST_SNAPSHOT, pindex->GetBlockHash()));

    if (pindex->pprev) {
        tipList = GetListForBlock(pindex->pprev);
        LogPrint(BCLog::MASTERNODE, "UndoBlock: tip now at height=%d MNs=%zu\n",
                 pindex->pprev->nHeight, tipList ? tipList->GetAllMNsCount() : 0);
    } else {
        tipList = std::make_shared<CDeterministicMNList>();
        LogPrint(BCLog::MASTERNODE, "UndoBlock: tip reset to genesis (empty list)\n");
    }

    return true;
}

CDeterministicMNListCPtr CDeterministicMNManager::GetListForBlock(const CBlockIndex* pindex)
{
    LOCK(cs);

    if (!pindex) {
        return std::make_shared<CDeterministicMNList>();
    }

    // Before masternode activation, return an empty list — no MNs exist yet.
    if (pindex->nHeight < GetMasternodeActivationHeight()) {
        return std::make_shared<CDeterministicMNList>(pindex->GetBlockHash(), pindex->nHeight);
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

    // Rebuild by walking back to the nearest available snapshot, then
    // replaying blocks forward.  NEVER return an empty list for a height
    // past activation — that silently disables MN payment enforcement.
    LogPrintf("CDeterministicMNManager::%s -- cache/DB miss at height %d, rebuilding from nearest snapshot\n",
              __func__, pindex->nHeight);

    // Walk backwards to find the nearest ancestor with a cached or persisted list
    std::vector<const CBlockIndex*> blocksToReplay;
    const CBlockIndex* cursor = pindex;
    CDeterministicMNListCPtr baseList;

    while (cursor) {
        auto cacheIt = mnListsCache.find(cursor->GetBlockHash());
        if (cacheIt != mnListsCache.end()) {
            baseList = cacheIt->second;
            break;
        }
        auto dbList = LoadListFromDb(cursor->GetBlockHash());
        if (dbList) {
            baseList = dbList;
            mnListsCache[cursor->GetBlockHash()] = dbList;
            break;
        }
        blocksToReplay.push_back(cursor);
        cursor = cursor->pprev;
    }

    if (!baseList) {
        // Fell all the way back to genesis — start with an empty list
        baseList = std::make_shared<CDeterministicMNList>();
    }

    // Replay blocks forward to reconstruct the list at pindex
    std::reverse(blocksToReplay.begin(), blocksToReplay.end());
    for (const CBlockIndex* replayIdx : blocksToReplay) {
        CBlock replayBlock;
        if (!ReadBlockFromDisk(replayBlock, replayIdx, GetParams().GetConsensus())) {
            LogPrintf("CDeterministicMNManager::%s -- CRITICAL: failed to read block at height %d during rebuild\n",
                      __func__, replayIdx->nHeight);
            break;
        }

        CValidationState dummyState;
        ProcessBlock(replayBlock, replayIdx, dummyState, false);

        auto rebuilt = mnListsCache.find(replayIdx->GetBlockHash());
        if (rebuilt != mnListsCache.end()) {
            baseList = rebuilt->second;
        }
    }

    // Final lookup — ProcessBlock should have populated the cache
    auto finalIt = mnListsCache.find(pindex->GetBlockHash());
    if (finalIt != mnListsCache.end()) {
        return finalIt->second;
    }

    // If rebuild still failed, return the best we have and log a critical warning
    LogPrintf("CDeterministicMNManager::%s -- WARNING: rebuild did not produce list for height %d, "
              "returning base list at height %d with %zu MNs\n",
              __func__, pindex->nHeight, baseList->GetHeight(), baseList->GetAllMNsCount());
    return baseList;
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
    if (!list) {
        LogPrint(BCLog::MASTERNODE, "GetMNPayee: no list for pindex height=%d hash=%s\n",
                 pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 16));
        return nullptr;
    }

    int nextHeight = pindex->nHeight + 1;
    LogPrint(BCLog::MASTERNODE, "GetMNPayee: listHeight=%d listMNs=%zu validMNs=%zu scoring for nextHeight=%d entropy=%s\n",
             list->GetHeight(), list->GetAllMNsCount(), list->GetValidMNsCount(),
             nextHeight, pindex->GetBlockHash().ToString().substr(0, 16));

    auto payee = list->GetMNPayee(pindex->GetBlockHash(), nextHeight);
    if (payee) {
        LogPrint(BCLog::MASTERNODE, "GetMNPayee: selected %s tier=%s lastPaid=%d for height=%d\n",
                 payee->proTxHash.ToString().substr(0, 16), GetTierName(payee->state.nTier),
                 payee->state.nLastPaidHeight, nextHeight);
    } else {
        LogPrint(BCLog::MASTERNODE, "GetMNPayee: NO payee found for height=%d\n", nextHeight);
    }
    return payee;
}

void CDeterministicMNManager::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    if (fInitialDownload || pindexNew == pindexFork) {
        // In IBD or blocks were disconnected without any new ones
        return;
    }
    LOCK(cs);
    tipList = GetListForBlock(pindexNew);
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
    // ============================================================
    // MEDIUM FIX: Use height-based eviction for deterministic behavior
    // The previous approach used map.begin() which is non-deterministic
    // because std::map orders by hash, not by height.
    // ============================================================
    while (mnListsCache.size() > MAX_CACHE_SIZE) {
        // Find the entry with the lowest height
        uint256 lowestHashToRemove;
        int lowestHeight = std::numeric_limits<int>::max();
        bool foundEntry = false;
        
        for (const auto& pair : mnListsCache) {
            if (pair.second && pair.second->GetHeight() < lowestHeight) {
                lowestHeight = pair.second->GetHeight();
                lowestHashToRemove = pair.first;
                foundEntry = true;
            }
        }
        
        if (foundEntry) {
            mnListsCache.erase(lowestHashToRemove);
            LogPrint(BCLog::MASTERNODE, "CDeterministicMNManager: Evicted cache entry at height %d\n", lowestHeight);
        } else {
            // No valid entry found — this should never happen.
            LogPrintf("CDeterministicMNManager::CleanupCache: WARNING — no valid cache entry for eviction, "
                      "cache size %zu exceeds max %zu\n", mnListsCache.size(), MAX_CACHE_SIZE);
            break;
        }
    }
}

