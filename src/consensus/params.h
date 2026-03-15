// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_CONSENSUS_PARAMS_H
#define MYNTA_CONSENSUS_PARAMS_H

#include "uint256.h"
#include "amount.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_ASSETS, // Deployment of RIP2
    DEPLOYMENT_MSG_REST_ASSETS, // Delpoyment of RIP5 and Restricted assets
    DEPLOYMENT_TRANSFER_SCRIPT_SIZE,
    DEPLOYMENT_ENFORCE_VALUE,
    DEPLOYMENT_COINBASE_ASSETS,
    // DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
//    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** Use to override the confirmation window on a specific BIP */
    uint32_t nOverrideMinerConfirmationWindow;
    /** Use to override the the activation threshold on a specific BIP */
    uint32_t nOverrideRuleChangeActivationThreshold;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    bool nBIP34Enabled;
    bool nBIP65Enabled;
    bool nBIP66Enabled;
    // uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    // int BIP65Height;
    /** Block height at which BIP66 becomes active */
    // int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 kawpowLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    bool nSegwitEnabled;
    bool nCSVEnabled;
    
    // =======================================================================
    // Proof of Work Algorithm Activation Times
    // These are the authoritative source for PoW algorithm selection.
    // The global nKAWPOWActivationTime is synchronized from these at startup.
    // =======================================================================
    
    /** Timestamp at which X16RV2 algorithm activates (0 = never) */
    uint32_t nX16RV2ActivationTime;
    
    /** Timestamp at which KawPoW algorithm activates (0 = never) */
    uint32_t nKawPowActivationTime;
    
    /** Chain start time - blocks cannot be mined before this timestamp.
     *  This allows pre-release distribution of binaries without premature mining.
     *  Set to 0 to disable (allow mining immediately). */
    int64_t nChainStartTime;
    
    // =======================================================================
    // Deterministic Masternode (DIP3) Consensus Parameters
    // =======================================================================
    
    /** Masternode collateral amount in satoshis (Tier 1 - Standard) */
    CAmount nMasternodeCollateral;
    
    /** Masternode collateral amount for Tier 2 (Super Node) in satoshis */
    CAmount nMasternodeCollateralTier2;
    
    /** Masternode collateral amount for Tier 3 (Ultra Node) in satoshis */
    CAmount nMasternodeCollateralTier3;
    
    /** Block height at which tiered masternodes (Tier 2/3) become valid */
    int nTieredMNActivationHeight;
    
    /** Required confirmations for collateral */
    int nMasternodeCollateralConfirmations;
    
    /** Block height at which masternode registration becomes active */
    int nMasternodeActivationHeight;
    
    /** Percentage of block reward paid to masternodes (0-100) */
    int nMasternodeRewardPercent;
    
    /** PoSe (Proof of Service) penalty increment per missed session */
    int nPoSePenaltyIncrement;
    
    /** PoSe ban threshold - masternode is banned when penalty reaches this */
    int nPoSeBanThreshold;
    
    /** Blocks until a banned masternode can be revived */
    int nPoSeRevivalHeight;
    
    /** Minimum blocks between ProUpServTx updates for the same MN */
    int nProUpServCooldown{10};
    
    /** Minimum blocks between ProUpRegTx updates for the same MN */
    int nProUpRegCooldown{10};
    
    /** Block height at which the MN v2 migration occurs.
     *  At this height, the entire MN list is wiped and all operators must
     *  re-register.  Defaults to nTieredMNActivationHeight on all networks. */
    int nMNv2MigrationHeight{0};
    
    /** Block height at which v1.5 consensus fixes activate.
     *  Gated fixes: ChainLock quorum selection, 100% operator reward,
     *  asset overflow checks, deterministic CheckAmountWithUnits,
     *  and safe reissue overflow comparison. */
    int nConsensusFixHeight{0};
    
    /** Grace period in blocks after MN activation before payment enforcement.
     *  Allows initial masternodes time to register before blocks are rejected
     *  for missing MN payments. */
    int nMasternodePaymentGracePeriod{100};
    
    // =======================================================================
    // LLMQ (Long-Living Masternode Quorum) Parameters
    // =======================================================================
    
    /** Minimum masternodes required to form a quorum */
    int nLLMQMinSize;
    
    /** Threshold for LLMQ signing (percentage of quorum size, e.g., 60 = 60%) */
    int nLLMQThreshold;
    
    /** Blocks a quorum remains active */
    int nLLMQDuration;
    
    /** Blocks for InstantSend lock timeout */
    int nInstantSendLockTimeout;
    
    /** Blocks to wait for ChainLock confirmation */
    int nChainLockConfirmations;
    
    // =======================================================================
    // Transaction Maturity Parameters
    // =======================================================================
    
    /** Coinbase maturity - blocks before mined coins can be spent */
    int nCoinbaseMaturity;
};
} // namespace Consensus

#endif // MYNTA_CONSENSUS_PARAMS_H
