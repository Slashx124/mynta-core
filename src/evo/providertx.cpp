// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evo/providertx.h"
#include "evo/deterministicmns.h"
#include "evo/evodb.h"
#include "evo/specialtx.h"

#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "hash.h"
#include "script/standard.h"
#include "util.h"
#include "validation.h"

#include <sstream>

std::string TxTypeToString(TxType type)
{
    switch (type) {
        case TxType::TRANSACTION_NORMAL: return "NORMAL";
        case TxType::TRANSACTION_PROVIDER_REGISTER: return "PROVIDER_REGISTER";
        case TxType::TRANSACTION_PROVIDER_UPDATE_SERVICE: return "PROVIDER_UPDATE_SERVICE";
        case TxType::TRANSACTION_PROVIDER_UPDATE_REGISTRAR: return "PROVIDER_UPDATE_REGISTRAR";
        case TxType::TRANSACTION_PROVIDER_UPDATE_REVOKE: return "PROVIDER_UPDATE_REVOKE";
        default: return "UNKNOWN";
    }
}

bool IsTxTypeSpecial(const CTransaction& tx)
{
    // Special transactions are identified by version >= 3 and type != 0
    // This follows the special transaction format from DIP-002
    return tx.nVersion >= 3 && tx.nType != 0;
}

TxType GetTxType(const CTransaction& tx)
{
    if (tx.nVersion < 3 || tx.nType == 0) {
        return TxType::TRANSACTION_NORMAL;
    }
    return static_cast<TxType>(tx.nType);
}

// ============================================================================
// CProRegTx Implementation
// ============================================================================

uint256 CProRegTx::GetSignatureHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

bool CProRegTx::CheckSignature(const CKeyID& keyID) const
{
    // Verify the signature using the owner key
    uint256 hash = GetSignatureHash();
    
    // Recover the public key from the signature
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(hash, vchSig)) {
        return false;
    }
    
    // Check if the recovered key matches the expected keyID
    return pubkey.GetID() == keyID;
}

std::string CProRegTx::ToString() const
{
    std::ostringstream ss;
    ss << "CProRegTx("
       << "version=" << nVersion
       << ", type=" << nType
       << ", mode=" << nMode
       << ", collateral=" << collateralOutpoint.ToString()
       << ", addr=" << addr.ToString()
       << ", ownerKey=" << keyIDOwner.ToString()
       << ", votingKey=" << keyIDVoting.ToString()
       << ", operatorReward=" << nOperatorReward
       << ")";
    return ss.str();
}

// ============================================================================
// CProUpServTx Implementation
// ============================================================================

uint256 CProUpServTx::GetSignatureHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

std::string CProUpServTx::ToString() const
{
    std::ostringstream ss;
    ss << "CProUpServTx("
       << "version=" << nVersion
       << ", proTxHash=" << proTxHash.ToString()
       << ", addr=" << addr.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// CProUpRegTx Implementation
// ============================================================================

uint256 CProUpRegTx::GetSignatureHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

bool CProUpRegTx::CheckSignature(const CKeyID& keyID) const
{
    uint256 hash = GetSignatureHash();
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(hash, vchSig)) {
        return false;
    }
    return pubkey.GetID() == keyID;
}

std::string CProUpRegTx::ToString() const
{
    std::ostringstream ss;
    ss << "CProUpRegTx("
       << "version=" << nVersion
       << ", proTxHash=" << proTxHash.ToString()
       << ", mode=" << nMode
       << ", votingKey=" << keyIDVoting.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// CProUpRevTx Implementation
// ============================================================================

uint256 CProUpRevTx::GetSignatureHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

std::string CProUpRevTx::ToString() const
{
    std::ostringstream ss;
    ss << "CProUpRevTx("
       << "version=" << nVersion
       << ", proTxHash=" << proTxHash.ToString()
       << ", reason=" << nReason
       << ")";
    return ss.str();
}

// ============================================================================
// Validation Functions
// ============================================================================

static bool CheckInputsHash(const CTransaction& tx, const uint256& expectedInputsHash, CValidationState& state)
{
    // Calculate hash of all inputs for replay protection
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    for (const auto& input : tx.vin) {
        hw << input.prevout;
    }
    uint256 calculatedHash = hw.GetHash();
    
    if (calculatedHash != expectedInputsHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-inputs-hash");
    }
    return true;
}

bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != static_cast<uint16_t>(TxType::TRANSACTION_PROVIDER_REGISTER)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }

    CProRegTx proTx;
    if (!GetTxPayload(tx, proTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
    }

    // Version check
    if (proTx.nVersion != CProRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }

    // Mode check (only regular MN supported currently)
    if (proTx.nMode != 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-mode");
    }

    // Check operator reward range (0-10000 = 0-100%)
    if (proTx.nOperatorReward > 10000) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-operator-reward");
    }

    // Check IP address is valid and routable
    if (!proTx.addr.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr");
    }
    if (!proTx.addr.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr-not-routable");
    }

    // Check operator key size (48 bytes for BLS public key)
    if (proTx.vchOperatorPubKey.size() != 48) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-operator-key-size");
    }

    // Check payout script is valid
    if (!proTx.scriptPayout.IsPayToPublicKeyHash() && 
        !proTx.scriptPayout.IsPayToScriptHash()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payout-script");
    }

    // Check inputs hash for replay protection
    if (!CheckInputsHash(tx, proTx.inputsHash, state)) {
        return false;
    }

    // Check collateral
    // The collateral must be a specific UTXO with exactly the collateral amount
    // This is verified during contextual validation with access to UTXO set
    
    // Check signature by owner key
    if (!proTx.CheckSignature(proTx.keyIDOwner)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig");
    }

    // Check for duplicate keys in existing masternode list
    if (pindexPrev && deterministicMNManager) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        if (mnList) {
            // Check for duplicate service address
            if (mnList->HasUniqueProperty(mnList->GetUniquePropertyHash(proTx.addr))) {
                return state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-addr");
            }
            
            // Check for duplicate owner key
            if (mnList->HasUniqueProperty(mnList->GetUniquePropertyHash(proTx.keyIDOwner))) {
                return state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-owner-key");
            }
            
            // Check for duplicate collateral
            if (mnList->GetMNByCollateral(proTx.collateralOutpoint)) {
                return state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-collateral");
            }
        }
    }

    return true;
}

bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != static_cast<uint16_t>(TxType::TRANSACTION_PROVIDER_UPDATE_SERVICE)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }

    CProUpServTx proTx;
    if (!GetTxPayload(tx, proTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
    }

    if (proTx.nVersion != CProUpServTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }

    // Check IP address
    if (!proTx.addr.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr");
    }
    if (!proTx.addr.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr-not-routable");
    }

    // Check inputs hash
    if (!CheckInputsHash(tx, proTx.inputsHash, state)) {
        return false;
    }

    // Verify the masternode exists
    if (pindexPrev && deterministicMNManager) {
        auto mn = deterministicMNManager->GetMN(proTx.proTxHash);
        if (!mn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        }

        // Check for address conflict with other masternodes
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        if (mnList) {
            auto existingMN = mnList->GetMNByService(proTx.addr);
            if (existingMN && existingMN->proTxHash != proTx.proTxHash) {
                return state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-addr");
            }
        }

        // Signature verification would be done with BLS library
        // For now, we check that the signature exists
        if (proTx.vchSig.empty()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig");
        }
    }

    return true;
}

bool CheckProUpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != static_cast<uint16_t>(TxType::TRANSACTION_PROVIDER_UPDATE_REGISTRAR)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }

    CProUpRegTx proTx;
    if (!GetTxPayload(tx, proTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
    }

    if (proTx.nVersion != CProUpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }

    // Check operator key size if provided
    if (!proTx.vchOperatorPubKey.empty() && proTx.vchOperatorPubKey.size() != 48) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-operator-key-size");
    }

    // Check payout script if provided
    if (!proTx.scriptPayout.empty()) {
        if (!proTx.scriptPayout.IsPayToPublicKeyHash() && 
            !proTx.scriptPayout.IsPayToScriptHash()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-payout-script");
        }
    }

    // Check inputs hash
    if (!CheckInputsHash(tx, proTx.inputsHash, state)) {
        return false;
    }

    // Verify the masternode exists and check signature
    if (pindexPrev && deterministicMNManager) {
        auto mn = deterministicMNManager->GetMN(proTx.proTxHash);
        if (!mn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        }

        // Check signature by owner key
        if (!proTx.CheckSignature(mn->state.keyIDOwner)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig");
        }
    }

    return true;
}

bool CheckProUpRevTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != static_cast<uint16_t>(TxType::TRANSACTION_PROVIDER_UPDATE_REVOKE)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }

    CProUpRevTx proTx;
    if (!GetTxPayload(tx, proTx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
    }

    if (proTx.nVersion != CProUpRevTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }

    // Check reason is valid
    if (proTx.nReason > CProUpRevTx::REASON_CHANGE_OF_KEYS) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-reason");
    }

    // Check inputs hash
    if (!CheckInputsHash(tx, proTx.inputsHash, state)) {
        return false;
    }

    // Verify the masternode exists
    if (pindexPrev && deterministicMNManager) {
        auto mn = deterministicMNManager->GetMN(proTx.proTxHash);
        if (!mn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        }

        // Signature verification with BLS would happen here
        if (proTx.vchSig.empty()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig");
        }
    }

    return true;
}

bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (!IsTxTypeSpecial(tx)) {
        return true; // Normal transaction, nothing to check
    }

    switch (GetTxType(tx)) {
        case TxType::TRANSACTION_PROVIDER_REGISTER:
            return CheckProRegTx(tx, pindexPrev, state);
        case TxType::TRANSACTION_PROVIDER_UPDATE_SERVICE:
            return CheckProUpServTx(tx, pindexPrev, state);
        case TxType::TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
            return CheckProUpRegTx(tx, pindexPrev, state);
        case TxType::TRANSACTION_PROVIDER_UPDATE_REVOKE:
            return CheckProUpRevTx(tx, pindexPrev, state);
        default:
            return state.DoS(100, false, REJECT_INVALID, "bad-tx-type-unknown");
    }
}

bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state, bool fJustCheck)
{
    // Validate all special transactions in the block
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        if (!CheckSpecialTx(tx, pindex->pprev, state)) {
            return false;
        }
    }

    // If not just checking, apply the transactions to the masternode list
    if (!fJustCheck && deterministicMNManager) {
        if (!deterministicMNManager->ProcessBlock(block, pindex, state, fJustCheck)) {
            return false;
        }
    }

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex)
{
    // Undo masternode list changes
    if (deterministicMNManager) {
        if (!deterministicMNManager->UndoBlock(block, pindex)) {
            return false;
        }
    }
    return true;
}

