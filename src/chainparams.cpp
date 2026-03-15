// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/devalloc.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

//TODO: Take these out
extern double algoHashTotal[16];
extern int algoHashHits[16];

// =============================================================================
// MYNTA GENESIS BLOCK - PERMANENTLY LOCKED
// =============================================================================
//
// GENESIS LOCK NOTICE:
// --------------------
// The genesis blocks for all networks (mainnet, testnet, regtest) were
// generated ONCE on January 13, 2026 and are now PERMANENTLY LOCKED.
// Any modification to genesis parameters requires a coordinated hard fork.
//
// PROVABLY FAIR LAUNCH DECLARATION:
// ---------------------------------
// The Mynta genesis block follows the same consensus rules as all subsequent
// blocks. There is NO premine - the genesis coinbase follows standard subsidy
// rules with the mandatory 3% development allocation.
//
// Genesis coinbase structure:
// - Output 0: Miner reward (97% of 5000 MYNTA = 4850 MYNTA)
// - Output 1: Dev allocation (3% of 5000 MYNTA = 150 MYNTA)
//
// This structure is IDENTICAL to all future blocks, ensuring provably fair
// issuance from the very first block.
//
// FIXED GENESIS PARAMETERS (ALL NETWORKS):
// ----------------------------------------
// Timestamp:   1768374000 (Jan 13, 2026 11:00 PM PST / Jan 14, 2026 07:00 UTC)
// Headline:    "Mynta 14/Jan/2026 - No premine. Equal rules from block zero."
// Subsidy:     5000 MYNTA
// Dev alloc:   150 MYNTA (3%)
// Miner share: 4850 MYNTA (97% - effectively burned in genesis)
//
// NETWORK-SPECIFIC PARAMETERS:
// ----------------------------
// Mainnet:  nonce=2151963, nBits=0x1e00ffff
//           hash=0x0000003435e201dbb29b89415444b9cc8adeefcec50ba2678c562ef8cc4928c5
// Testnet:  nonce=2151963, nBits=0x1e00ffff (same as mainnet)
//           hash=0x0000003435e201dbb29b89415444b9cc8adeefcec50ba2678c562ef8cc4928c5
// Regtest:  nonce=1,       nBits=0x207fffff (easy difficulty)
//           hash=0x504dbce9d1c9d323b561f64e6e6e522705887b4a51b4287e0843023b3e32be62
//
// Merkle Root (all networks): 0x428d2450b9481e0be4b98c0df7883b0e5692ac7134c7b474ecb639461a495877
//
// GENESIS WAS MINED ON JANUARY 13, 2026 USING X16R HASH ALGORITHM.
// GENESIS MINING CODE HAS BEEN PERMANENTLY REMOVED.
// =============================================================================

/**
 * Create the genesis block coinbase transaction with dev allocation.
 * 
 * Provably fair launch:
 * The genesis coinbase follows the same rules as all other blocks:
 * - Standard subsidy (5000 MYNTA at height 0)
 * - 3% dev allocation enforced (150 MYNTA)
 * - 97% to miner (4850 MYNTA)
 * - No premine, no special allocations, no hidden outputs
 */
static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& minerOutputScript, const CScript& devOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // Calculate dev allocation for genesis (3% of subsidy)
    CAmount devAllocation = genesisReward * Consensus::DEV_FEE_PERCENT / 100;
    CAmount minerReward = genesisReward - devAllocation;
    
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(2);  // Two outputs: miner + dev
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    
    // Output 0: Miner reward (97% of subsidy)
    txNew.vout[0].nValue = minerReward;
    txNew.vout[0].scriptPubKey = minerOutputScript;
    
    // Output 1: Dev allocation (3% of subsidy) - PROVABLY FAIR
    // This output exists in genesis and ALL future blocks equally
    txNew.vout[1].nValue = devAllocation;
    txNew.vout[1].scriptPubKey = devOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the Mynta genesis block with provably fair launch parameters.
 * 
 * GENESIS HEADLINE: "No premine. Equal rules from block zero."
 * 
 * This headline explicitly declares the provably fair launch model:
 * - No premine exists
 * - Rules are identical for all participants
 * - Dev allocation is mechanical and consensus-enforced
 * 
 * Provably fair launch:
 * The genesis block is NOT special - it follows the exact same
 * consensus rules as every other block on the network.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // =========================================================================
    // GENESIS HEADLINE - PROVABLY FAIR LAUNCH
    // =========================================================================
    // This message is embedded in the genesis coinbase and cannot be changed.
    // It explicitly declares the fair launch model for all to verify.
    // =========================================================================
    const char* pszTimestamp = "Mynta 14/Jan/2026 - No premine. Equal rules from block zero.";
    
    // Genesis miner output script (standard P2PK, matches Bitcoin genesis format)
    // This uses Satoshi's well-known genesis public key - the private key is unknown.
    // PROVABLY FAIR: The 4850 MYNTA miner reward in genesis is effectively BURNED.
    // Only the 150 MYNTA dev allocation (output 1) is spendable.
    // This ensures no hidden premine exists in the genesis block.
    const CScript minerOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    
    // Dev allocation output script (same as placeholder for Epoch 0)
    // This is the SAME script used for all dev allocations during Epoch 0
    // Genesis block uses the immutable genesis dev script (not wallet-derived)
    const CScript devOutputScript = Consensus::GetGenesisDevScript();
    
    return CreateGenesisBlock(pszTimestamp, minerOutputScript, devOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {
	consensus.nSegwitEnabled = false;
}

void CChainParams::TurnOffCSV() {
	consensus.nCSVEnabled = false;
}

void CChainParams::TurnOffBIP34() {
	consensus.nBIP34Enabled = false;
}

void CChainParams::TurnOffBIP65() {
	consensus.nBIP65Enabled = false;
}

void CChainParams::TurnOffBIP66() {
	consensus.nBIP66Enabled = false;
}

bool CChainParams::BIP34() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP65() {
	return consensus.nBIP65Enabled;
}

bool CChainParams::BIP66() {
	return consensus.nBIP66Enabled;
}

bool CChainParams::CSVEnabled() const{
	return consensus.nCSVEnabled;
}


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 2100000;  //~ 4 yrs at 1 min block time
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        
        // MYNTA LAUNCH: Chain start time - January 14, 2026 4:00 PM PST (00:00 UTC Jan 15)
        // No blocks can be mined before this time. This allows pre-release binary distribution.
        // Unix timestamp: 1768435200 = January 15, 2026 00:00:00 UTC = January 14, 2026 4:00 PM PST
        consensus.nChainStartTime = 1768435200;
        
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("00000064ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~100x easier starting difficulty for KawPoW
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
		consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1613; // Approx 80% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;
        // MYNTA: All features activated from genesis (new chain, no legacy compatibility needed)
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;  // Assets (RIP2) - 8MB blocks, native assets
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0; // Immediate activation
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1; // Activate after 1 block
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;  // Messaging & Restricted Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; // Immediate activation
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;  // Larger transfer scripts
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0; // Immediate activation
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;  // Asset value enforcement
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0; // Immediate activation
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;  // Coinbase asset minting
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0; // Immediate activation
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 1;


        // Mynta mainnet - new chain, no minimum chainwork yet
        consensus.nMinimumChainWork = uint256S("0x00");

        // Mynta mainnet - new chain, no assumevalid yet
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        // Mynta mainnet magic bytes: MYNA
        pchMessageStart[0] = 0x4d; // M
        pchMessageStart[1] = 0x59; // Y
        pchMessageStart[2] = 0x4e; // N
        pchMessageStart[3] = 0x41; // A
        nDefaultPort = 8770;  // Mynta mainnet P2P port
        nPruneAfterHeight = 100000;

        // =====================================================================
        // MAINNET GENESIS BLOCK - PROVABLY FAIR LAUNCH
        // =====================================================================
        // GENESIS WAS GENERATED ONCE AND IS NOW PERMANENTLY LOCKED.
        // DO NOT modify these parameters without a hard fork.
        //
        // Provably fair launch:
        // This genesis block is created with the SAME consensus rules as all
        // future blocks. The coinbase contains:
        // - Output 0: Miner reward (97% = 4850 MYNTA)
        // - Output 1: Dev allocation (3% = 150 MYNTA)
        //
        // There is NO premine. The genesis follows standard subsidy rules.
        //
        // Genesis parameters:
        // - nTime:     1768374000 (Jan 13, 2026 11:00 PM PST / Jan 14, 2026 07:00 UTC)
        // - nNonce:    2151963
        // - nBits:     0x1e00ffff
        // - nVersion:  4
        // - Subsidy:   5000 MYNTA
        //
        // Headline rationale:
        // "Mynta 14/Jan/2026 - No premine. Equal rules from block zero."
        // - Clearly signals a fair launch (no premine, equal rules)
        // - Mentions no people, brands, or hype
        // - Is timeless and factual
        // - Applies equally to all networks (mainnet, testnet, regtest)
        // - Date stamps the genesis for provenance (following Bitcoin tradition)
        //
        // Coinbase outputs:
        // - Output 0: 4850 MYNTA to Satoshi's unspendable public key (effectively burned)
        // - Output 1: 150 MYNTA to dev placeholder MUnwxykRqLsGctiHPEy8waP46L9oyUsztz
        //
        // GENESIS MINED ON: January 13, 2026 using X16R hash algorithm
        // REGENERATION OF GENESIS REQUIRES A HARD FORK.
        // =====================================================================
        
        // Genesis timestamp: January 13, 2026 11:00:00 PM PST (January 14, 2026 07:00:00 UTC)
        // This is a FIXED value. DO NOT use time(nullptr) or any runtime value.
        uint32_t nGenesisTime = 1768374000;  // LOCKED: Jan 13, 2026 11:00 PM PST
        
        genesis = CreateGenesisBlock(nGenesisTime, 2151963, 0x1e00ffff, 4, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        // Genesis verification - provably fair launch
        // Hash verified to meet target 0x000000ffff... (nBits 0x1e00ffff)
        assert(consensus.hashGenesisBlock == uint256S("0x0000003435e201dbb29b89415444b9cc8adeefcec50ba2678c562ef8cc4928c5"));
        assert(genesis.hashMerkleRoot == uint256S("0x428d2450b9481e0be4b98c0df7883b0e5692ac7134c7b474ecb639461a495877"));

        // DNS seeds for peer discovery
        vSeeds.clear();
        vSeeds.emplace_back("dns.myntacoin.org", true);

        // Mynta address prefixes - 'M' for mainnet
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,50);  // 'M' prefix
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,110); // 'm' prefix (P2SH)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Mynta BIP44 cointype in mainnet is '175'
        nExtCoinType = 175;

        // Fixed seed nodes for peer discovery
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        // Mynta mainnet checkpoints
        checkpointData = (CCheckpointData) {
            {
                { 10000, uint256S("0x0000000000ee5ee58012b64378a715ca1aa1427505e8b63403f4bd6653be6b19")},
            }
        };

        // Mynta mainnet chainTxData (updated at block 10000)
        chainTxData = ChainTxData{
            1768971937,    // timestamp of block 10000
            10178,         // total transactions at block 10000
            0.019          // tx rate (txs per second)
        };

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses - Mynta mainnet (MR prefix = Mynta Reserve)
        // These are provably unspendable addresses for asset operations
        strIssueAssetBurnAddress = "MRA1DeK1yCiJRsPVXAampd2XB5xFwah9f6";
        strReissueAssetBurnAddress = "MRBUCZXSCMQtwz6Dvk1soyKKwgLLfdgDQ7";
        strIssueSubAssetBurnAddress = "MRCXvyv1qjg35CpjC2h9hryMekj1Y9BLyb";
        strIssueUniqueAssetBurnAddress = "MRDgGujZL3u4iHybWJje6djaUw4CsqDuhP";
        strIssueMsgChannelAssetBurnAddress = "MRESYWD5JfxnRGRxHopEwzFckzD8AP3n2t";
        strIssueQualifierAssetBurnAddress = "MRFNefMQm2buZ1BQ7qaBJoFRWLGsjKSsoj";
        strIssueSubQualifierAssetBurnAddress = "MRG6hiRfgnE3jz3HkbMtRaAJm2YJ8iNYd5";
        strIssueRestrictedAssetBurnAddress = "MRHLry6K16n49cg6SiL6rBwxy678uCQ9or";
        strAddNullQualifierTagBurnAddress = "MRJ565JV1B4TRaUeVDe5b282FpV139tBx6";

        // Global Burn Address
        strGlobalBurnAddress = "MRKxSezjRVEYzBSA8tKKtmnVDS53EApS4q";

        // DGW Activation
        // Dark Gravity Wave activates at block 10 for faster difficulty adjustment
        nDGWActivationBlock = 10;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        // MYNTA: New chain - RPC features available from genesis
        // Note: Consensus activation still follows BIP9 (active at block 2)
        nAssetActivationHeight = 0; // Asset RPC scan start height
        nMessagingActivationBlock = 0; // Messaging RPC available from genesis
        nRestrictedActivationBlock = 0; // Restricted asset RPC available from genesis

        // =====================================================================
        // PoW Algorithm Activation Times - MAINNET
        // These are the AUTHORITATIVE source for algorithm selection.
        // The global nKAWPOWActivationTime is synchronized from these at startup.
        // =====================================================================
        
        // X16RV2 never activates on Mynta (we go directly X16R -> KawPoW)
        consensus.nX16RV2ActivationTime = 0;
        
        // KawPoW active immediately after genesis (genesis nTime + 1)
        // Genesis uses X16R hash, all subsequent blocks use KawPoW
        consensus.nKawPowActivationTime = nGenesisTime + 1;
        
        // Legacy: kept for backward compatibility during transition
        nKAAAWWWPOWActivationTime = consensus.nKawPowActivationTime;
        /** RVN End **/
        
        // =======================================================================
        // Deterministic Masternode (DIP3) Parameters - MAINNET
        // =======================================================================
        consensus.nMasternodeCollateral = 100000 * COIN;      // 100,000 MYNTA (Tier 1 - Standard)
        consensus.nMasternodeCollateralTier2 = 1000000 * COIN;  // 1,000,000 MYNTA (Tier 2 - Super)
        consensus.nMasternodeCollateralTier3 = 10000000 * COIN; // 10,000,000 MYNTA (Tier 3 - Ultra)
        consensus.nTieredMNActivationHeight = 90000;          // Tier 2/3 valid after block 90000
        consensus.nMNv2MigrationHeight = 90000;               // Wipe pre-v2 MN list at block 90000
        consensus.nConsensusFixHeight = 90000;                // v1.5 consensus fixes activate at block 90000
        consensus.nMasternodeCollateralConfirmations = 15;    // ~15 minutes
        consensus.nMasternodeActivationHeight = 50000;        // MNs active after block 50000 (~35 days from launch)
        consensus.nMasternodePaymentGracePeriod = 100;        // 100 blocks grace after activation
        consensus.nMasternodeRewardPercent = 45;              // 45% of block reward to MNs
        consensus.nPoSePenaltyIncrement = 10;                 // Penalty per missed session (10 misses = ban, matching Dash)
        consensus.nPoSeBanThreshold = 100;                    // Ban at 100 penalty points
        consensus.nPoSeRevivalHeight = 720;                   // ~12 hours for revival
        
        // LLMQ Parameters - MAINNET
        consensus.nLLMQMinSize = 50;                          // Minimum quorum size
        consensus.nLLMQThreshold = 60;                        // 60% threshold for signing
        consensus.nLLMQDuration = 24 * 60;                    // 24 hours
        consensus.nInstantSendLockTimeout = 15;               // 15 blocks for IS timeout
        consensus.nChainLockConfirmations = 8;                // 8 blocks for ChainLock
        
        // Transaction maturity - MAINNET
        consensus.nCoinbaseMaturity = 100;                    // 100 blocks for coinbase maturity
    }
};

/**
 * Testnet (v7)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;  //~ 4 yrs at 1 min block time
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        
        // MYNTA TESTNET v9: Ultra-low difficulty for wallet mining
        // January 27, 2026 00:00:00 UTC
        consensus.nChainStartTime = 1769472000;

        // TESTNET v9: Ultra-low difficulty for single-core wallet mining
        // 256x easier than v8 - allows ~20 second blocks at 200 H/s
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1310; // Approx 65% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;
        // MYNTA TESTNET: Features activate at block 100
        // BIP9 state machine: STARTED -> LOCKED_IN -> ACTIVE
        // With window=50 and threshold=40 (80%):
        //   Block 0-49:   First window, signaling collected
        //   Block 50:     Evaluate window 0, transition to LOCKED_IN if 40+ signaled
        //   Block 50-99:  LOCKED_IN state
        //   Block 100:    Transition to ACTIVE
        // This aligns BIP9 activation with DGW, masternode, and RPC activation at block 100.
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 5;  // Assets (RIP2)
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0; // Signaling from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 40;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 50;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 6;  // Messaging & Restricted Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; // Signaling from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 40;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 50;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;  // Larger transfer scripts
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0; // Signaling from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 40;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 50;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;  // Asset value enforcement
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0; // Signaling from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 40;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 50;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;  // Coinbase asset minting
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0; // Signaling from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 40;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 50;

        // Mynta testnet - new chain, no minimum chainwork yet
        consensus.nMinimumChainWork = uint256S("0x00");

        // Mynta testnet - new chain, no assumevalid yet
        consensus.defaultAssumeValid = uint256S("0x00");


        // Mynta testnet magic bytes: MYNT
        pchMessageStart[0] = 0x4d; // M
        pchMessageStart[1] = 0x59; // Y
        pchMessageStart[2] = 0x4e; // N
        pchMessageStart[3] = 0x54; // T
        nDefaultPort = 18770;
        nPruneAfterHeight = 1000;

        // TESTNET v9 Genesis - Ultra-low difficulty for wallet mining
        // Genesis timestamp: January 27, 2026 00:00:00 UTC
        uint32_t nGenesisTime = 1769472000;
        
        // TESTNET v9: Genesis with nBits = 0x1f0fffff (256x easier than v8)
        // Single-core wallet mining: ~20 seconds per block at 200 H/s
        // nNonce = 249 found via genesis mining
        genesis = CreateGenesisBlock(nGenesisTime, 249, 0x1f0fffff, 4, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        // TESTNET v9: Genesis verification
        assert(consensus.hashGenesisBlock == uint256S("0x00095c4826541cb43a2d4b668417f74f59f32ba6bfe30f2e68eb6008cbdb192a"));
        assert(genesis.hashMerkleRoot == uint256S("0x428d2450b9481e0be4b98c0df7883b0e5692ac7134c7b474ecb639461a495877"));

        vFixedSeeds.clear();
        
        // DNS seeds for testnet peer discovery
        vSeeds.clear();
        vSeeds.emplace_back("testnet-dns.myntacoin.org", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Mynta BIP44 cointype in testnet
        nExtCoinType = 1;

        // Fixed seed nodes for testnet peer discovery
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        // Mynta testnet - new chain, no checkpoints yet
        checkpointData = (CCheckpointData) {
            {
                // Checkpoints will be added as chain matures
            }
        };

        // Mynta testnet - new chain, initial chainTxData
        chainTxData = ChainTxData{
            nGenesisTime,  // timestamp
            0,             // total transactions
            0              // tx rate
        };

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses - Mynta testnet
        strIssueAssetBurnAddress = "n1A35ngXmPq6MhnkLJKei6CgDUEJv3HuSE";
        strReissueAssetBurnAddress = "n1Bwj4MXRhQC3chisWYUyCe6X12TU2Utga";
        strIssueSubAssetBurnAddress = "n1C6wYiGQ3mJQwAzw3pUVJwnNs3hwCuNoZ";
        strIssueUniqueAssetBurnAddress = "n1D23T6iUjzrQ7qQcQC2nBMEisB5Feku2U";
        strIssueMsgChannelAssetBurnAddress = "n1EvEPZqBnNHAMgFHjsm8atWiBTcnYFpF1";
        strIssueQualifierAssetBurnAddress = "n1FWV3dVFSCTGCAUUe7oB8DfrKAS8XvbY4";
        strIssueSubQualifierAssetBurnAddress = "n1GZHTKwy7sFEYgBxbMJ6SbWHaBTLpLGqi";
        strIssueRestrictedAssetBurnAddress = "n1HWp3BwpGcdUSBevrjVocfgoKgkfDaCZS";
        strAddNullQualifierTagBurnAddress = "n1JnvETYcwMtwnECzNLmFdS6TSj6HZeyow";

        // Global Burn Address
        strGlobalBurnAddress = "n1KSyqiGfCcYJHA8AHUiG9YUX68zZx5xcB";

        // DGW Activation
        // DGW requires ~180 blocks of history for proper difficulty calculation.
        // Activating at block 100 ensures stable chain behavior during early mining.
        nDGWActivationBlock = 100;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        // MYNTA TESTNET: Asset features activate at block 100
        // This ensures stable chain history before advanced features become active.
        nAssetActivationHeight = 100; // Asset RPC scan start height
        nMessagingActivationBlock = 100; // Messaging RPC available after block 100
        nRestrictedActivationBlock = 100; // Restricted asset RPC available after block 100

        // =====================================================================
        // PoW Algorithm Activation Times - TESTNET
        // These are the AUTHORITATIVE source for algorithm selection.
        // =====================================================================
        
        // X16RV2 never activates on Mynta testnet
        consensus.nX16RV2ActivationTime = 0;
        
        // KawPoW active immediately after genesis (genesis nTime + 1)
        consensus.nKawPowActivationTime = nGenesisTime + 1;
        
        // Legacy: kept for backward compatibility during transition
        nKAAAWWWPOWActivationTime = consensus.nKawPowActivationTime;
        /** RVN End **/
        
        // =======================================================================
        // Deterministic Masternode (DIP3) Parameters - TESTNET
        // Lower values for easier testing
        // =======================================================================
        consensus.nMasternodeCollateral = 1000 * COIN;        // 1,000 MYNTA (Tier 1 - Standard, lower for testing)
        consensus.nMasternodeCollateralTier2 = 10000 * COIN;   // 10,000 MYNTA (Tier 2 - Super)
        consensus.nMasternodeCollateralTier3 = 100000 * COIN;  // 100,000 MYNTA (Tier 3 - Ultra)
        consensus.nTieredMNActivationHeight = 6750;             // Tier 2/3 valid after block 6750
        consensus.nMNv2MigrationHeight = 6750;                // Wipe pre-v2 MN list at block 6750
        consensus.nConsensusFixHeight = 6750;                 // v1.5 consensus fixes activate at block 6750
        consensus.nMasternodeCollateralConfirmations = 2;     // 2 confirmations (fast testing)
        consensus.nMasternodeActivationHeight = 100;          // MNs active after block 100
        consensus.nMasternodePaymentGracePeriod = 100;        // 100 blocks grace after activation
        consensus.nMasternodeRewardPercent = 45;              // 45% of block reward to MNs
        consensus.nPoSePenaltyIncrement = 10;                 // Penalty per missed session (10 misses = ban, matching Dash)
        consensus.nPoSeBanThreshold = 100;                    // Ban at 100 penalty points
        consensus.nPoSeRevivalHeight = 720;                   // ~12 hours for revival
        
        // LLMQ Parameters - TESTNET
        consensus.nLLMQMinSize = 10;                          // Smaller quorums for testing
        consensus.nLLMQThreshold = 60;                        // 60% threshold for signing
        consensus.nLLMQDuration = 6 * 60;                     // 6 hours (faster for testing)
        consensus.nInstantSendLockTimeout = 15;               // 15 blocks for IS timeout
        consensus.nChainLockConfirmations = 2;                // 2 blocks for ChainLock (fast testing)
        
        // Transaction maturity - TESTNET (fast testing)
        consensus.nCoinbaseMaturity = 2;                      // 2 blocks for coinbase maturity
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        
        // REGTEST: No chain start time restriction - allows unit tests to run
        consensus.nChainStartTime = 0;
        
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;  // Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; // GMT: Sun Mar 3, 2019 5:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 999999999999ULL; // UTC: Wed Dec 25 2019 07:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 500;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x43; // C
        pchMessageStart[1] = 0x52; // R
        pchMessageStart[2] = 0x4F; // O
        pchMessageStart[3] = 0x57; // W
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        // =====================================================================
        // REGTEST GENESIS BLOCK - PROVABLY FAIR LAUNCH
        // =====================================================================
        // GENESIS WAS GENERATED ONCE AND IS NOW PERMANENTLY LOCKED.
        // DO NOT modify these parameters without a hard fork.
        //
        // Regtest follows the same fair launch rules with easy difficulty.
        // Coinbase contains miner reward (97%) + dev allocation (3%)
        //
        // Genesis parameters:
        // - nTime:     1768374000 (Jan 13, 2026 11:00 PM PST / Jan 14, 2026 07:00 UTC)
        // - nNonce:    0 (easy difficulty - nBits 0x207fffff meets target)
        // - nBits:     0x207fffff
        // - nVersion:  4
        // - Subsidy:   5000 MYNTA
        // - Headline:  "Mynta 14/Jan/2026 - No premine. Equal rules from block zero."
        //
        // REGENERATION OF GENESIS REQUIRES A HARD FORK.
        // =====================================================================
        // Genesis timestamp: January 13, 2026 11:00:00 PM PST (January 14, 2026 07:00:00 UTC)
        // This is a FIXED value. DO NOT use time(nullptr) or any runtime value.
        uint32_t nGenesisTime = 1768374000;  // LOCKED: Jan 13, 2026 11:00 PM PST
        genesis = CreateGenesisBlock(nGenesisTime, 1, 0x207fffff, 4, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();
        
        // Genesis verification - provably fair launch (regtest has easy difficulty)
        // Hash verified to meet target 0x7fffff... (nBits 0x207fffff)
        assert(consensus.hashGenesisBlock == uint256S("0x504dbce9d1c9d323b561f64e6e6e522705887b4a51b4287e0843023b3e32be62"));
        assert(genesis.hashMerkleRoot == uint256S("0x428d2450b9481e0be4b98c0df7883b0e5692ac7134c7b474ecb639461a495877"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Mynta BIP44 cointype in regtest
        nExtCoinType = 1;

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses - Mynta regtest (same as testnet)
        strIssueAssetBurnAddress = "n1A35ngXmPq6MhnkLJKei6CgDUEJv3HuSE";
        strReissueAssetBurnAddress = "n1Bwj4MXRhQC3chisWYUyCe6X12TU2Utga";
        strIssueSubAssetBurnAddress = "n1C6wYiGQ3mJQwAzw3pUVJwnNs3hwCuNoZ";
        strIssueUniqueAssetBurnAddress = "n1D23T6iUjzrQ7qQcQC2nBMEisB5Feku2U";
        strIssueMsgChannelAssetBurnAddress = "n1EvEPZqBnNHAMgFHjsm8atWiBTcnYFpF1";
        strIssueQualifierAssetBurnAddress = "n1FWV3dVFSCTGCAUUe7oB8DfrKAS8XvbY4";
        strIssueSubQualifierAssetBurnAddress = "n1GZHTKwy7sFEYgBxbMJ6SbWHaBTLpLGqi";
        strIssueRestrictedAssetBurnAddress = "n1HWp3BwpGcdUSBevrjVocfgoKgkfDaCZS";
        strAddNullQualifierTagBurnAddress = "n1JnvETYcwMtwnECzNLmFdS6TSj6HZeyow";

        // Global Burn Address
        strGlobalBurnAddress = "n1KSyqiGfCcYJHA8AHUiG9YUX68zZx5xcB";

        // DGW Activation
        nDGWActivationBlock = 200;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 0; // Asset activated block height
        nMessagingActivationBlock = 0; // Messaging activated block height
        nRestrictedActivationBlock = 0; // Restricted activated block height

        // =====================================================================
        // PoW Algorithm Activation Times - REGTEST
        // These are the AUTHORITATIVE source for algorithm selection.
        // MANDATORY: Regtest MUST use same PoW algorithm as mainnet.
        // =====================================================================
        
        // X16RV2 never activates on regtest
        consensus.nX16RV2ActivationTime = 0;
        
        // KawPoW active immediately after genesis (genesis nTime + 1)
        // KawPoW is memory-hard - unit tests must minimize block mining
        consensus.nKawPowActivationTime = nGenesisTime + 1;
        
        // Legacy: kept for backward compatibility during transition
        nKAAAWWWPOWActivationTime = consensus.nKawPowActivationTime;
        /** RVN End **/
        
        // =======================================================================
        // Deterministic Masternode (DIP3) Parameters - REGTEST
        // Minimal values for rapid unit testing
        // =======================================================================
        consensus.nMasternodeCollateral = 100 * COIN;         // 100 MYNTA (Tier 1 - Standard, minimal for tests)
        consensus.nMasternodeCollateralTier2 = 1000 * COIN;    // 1,000 MYNTA (Tier 2 - Super)
        consensus.nMasternodeCollateralTier3 = 10000 * COIN;   // 10,000 MYNTA (Tier 3 - Ultra)
        consensus.nTieredMNActivationHeight = 50;              // Tier 2/3 valid after block 50 (very low for tests)
        consensus.nMNv2MigrationHeight = 50;                  // Wipe pre-v2 MN list at block 50
        consensus.nConsensusFixHeight = 50;                   // v1.5 consensus fixes activate at block 50
        consensus.nMasternodeCollateralConfirmations = 1;     // 1 confirmation (instant)
        consensus.nMasternodeActivationHeight = 1;            // MNs active from block 1
        consensus.nMasternodePaymentGracePeriod = 10;         // 10 blocks grace for regtest
        consensus.nMasternodeRewardPercent = 45;              // 45% of block reward to MNs
        consensus.nPoSePenaltyIncrement = 10;                 // Penalty per missed session (10 misses = ban, matching Dash)
        consensus.nPoSeBanThreshold = 100;                    // Ban at 100 penalty points
        consensus.nPoSeRevivalHeight = 24;                    // Quick revival for testing
        consensus.nProUpServCooldown = 2;                     // 2 blocks cooldown for testing
        consensus.nProUpRegCooldown = 2;                      // 2 blocks cooldown for testing
        
        // LLMQ Parameters - REGTEST
        consensus.nLLMQMinSize = 3;                           // Minimal quorum for tests
        consensus.nLLMQThreshold = 60;                        // 60% threshold for signing
        consensus.nLLMQDuration = 60;                         // 1 hour
        consensus.nInstantSendLockTimeout = 5;                // 5 blocks (fast)
        consensus.nChainLockConfirmations = 2;                // 2 blocks (fast)
        
        // Transaction maturity - REGTEST (instant for testing)
        consensus.nCoinbaseMaturity = 1;                      // 1 block for coinbase maturity
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &GetParams() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network);
    
    // Always set the block network identifier for hash algorithm selection
    bNetwork.SetNetwork(network);
    
    globalChainParams = CreateChainParams(network);
    
    // =========================================================================
    // CRITICAL: Synchronize global nKAWPOWActivationTime from Consensus::Params
    // 
    // The global is required for CBlockHeader::GetHash() which cannot take
    // parameters due to serialization requirements. This synchronization
    // ensures the global always matches the authoritative consensus params.
    // 
    // WARNING: This must be done AFTER CreateChainParams() and the global
    // must never be modified elsewhere in the codebase.
    // =========================================================================
    nKAWPOWActivationTime = globalChainParams->GetConsensus().nKawPowActivationTime;
    
    LogPrintf("Chain params selected: %s (KawPoW activation: %u)\n", 
              network, nKAWPOWActivationTime);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void TurnOffSegwit(){
	globalChainParams->TurnOffSegwit();
}

void TurnOffCSV() {
	globalChainParams->TurnOffCSV();
}

void TurnOffBIP34() {
	globalChainParams->TurnOffBIP34();
}

void TurnOffBIP65() {
	globalChainParams->TurnOffBIP65();
}

void TurnOffBIP66() {
	globalChainParams->TurnOffBIP66();
}

// =============================================================================
// CONSENSUS-CRITICAL GLOBAL VALIDATION
// =============================================================================

/**
 * Validate that global consensus-critical variables match chain parameters.
 * 
 * This function should be called after SelectParams() and periodically during
 * runtime to ensure the globals haven't been inadvertently modified.
 * 
 * @return true if all globals match consensus params, false otherwise
 */
bool ValidateConsensusGlobals()
{
    if (!globalChainParams) {
        LogPrintf("ERROR: ValidateConsensusGlobals called before SelectParams()\n");
        return false;
    }
    
    const Consensus::Params& consensus = globalChainParams->GetConsensus();
    bool valid = true;
    
    // Validate KawPoW activation time
    if (nKAWPOWActivationTime != consensus.nKawPowActivationTime) {
        LogPrintf("CRITICAL ERROR: nKAWPOWActivationTime mismatch! "
                  "Global: %u, Consensus: %u\n",
                  nKAWPOWActivationTime, consensus.nKawPowActivationTime);
        valid = false;
    }
    
    // Validate network identifier matches
    std::string networkId = globalChainParams->NetworkIDString();
    bool expectedTestnet = (networkId == "test");
    bool expectedRegtest = (networkId == "regtest");
    
    if (bNetwork.fOnTestnet != expectedTestnet || bNetwork.fOnRegtest != expectedRegtest) {
        LogPrintf("CRITICAL ERROR: bNetwork mismatch! "
                  "Network: %s, bNetwork.fOnTestnet: %d (expected %d), "
                  "bNetwork.fOnRegtest: %d (expected %d)\n",
                  networkId, bNetwork.fOnTestnet, expectedTestnet,
                  bNetwork.fOnRegtest, expectedRegtest);
        valid = false;
    }
    
    if (valid) {
        LogPrint(BCLog::VALIDATION, "Consensus globals validated successfully\n");
    }
    
    return valid;
}

/**
 * Assert that consensus globals are valid.
 * 
 * This function should be called in debug builds at critical points
 * to catch any global corruption early.
 */
void AssertConsensusGlobals()
{
    assert(ValidateConsensusGlobals() && "Consensus globals validation failed!");
}
