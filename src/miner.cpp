// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"
#include "rpc/mining.h"

#include <atomic>

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/devalloc.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include "wallet/wallet.h"
//#include "wallet/rpcwallet.h"

#include "evo/deterministicmns.h"

#include <boost/thread.hpp>
#include <algorithm>
#include <queue>
#include <utility>


extern std::vector<CWalletRef> vpwallets;
//////////////////////////////////////////////////////////////////////////////
//
// MyntaMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;
uint64_t nMiningTimeStart = 0;
uint64_t nHashesPerSec = 0;
uint64_t nHashesDone = 0;

// Tracks whether mining threads are currently running (set by GenerateMyntas)
std::atomic<bool> fMiningActive{false};

bool IsMiningActive()
{
    return fMiningActive.load();
}


int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // MYNTA LAUNCH: Ensure block timestamp is not before chain start time
    // This allows Stratum servers to prepare work that will be valid at launch
    // Without this, blocks mined before launch would be rejected with "chain-not-started"
    if (consensusParams.nChainStartTime > 0 && nNewTime < consensusParams.nChainStartTime) {
        nNewTime = consensusParams.nChainStartTime;
    }

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = GetMaxBlockWeight() - 4000;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(GetMaxBlockWeight() - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions(const CChainParams& params)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight",  GetMaxBlockWeight() - 4000);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions(params)) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    
    CAmount nBlockSubsidy = GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    CAmount nBlockReward = nFees + nBlockSubsidy;
    
    const auto& consensusParams = chainparams.GetConsensus();
    
    // =========================================================================
    // DEVELOPMENT ALLOCATION - PROVABLY FAIR LAUNCH
    // =========================================================================
    //
    // Provably fair launch:
    // This development allocation is enforced at consensus and applies equally
    // to ALL blocks mined by ANY miner. It cannot be bypassed, altered, or
    // redirected without a network-wide hard fork.
    //
    // Calculation: DEV_FEE_PERCENT (3%) of block subsidy (not fees)
    // The dev allocation is deducted from the miner's share, not the total.
    // =========================================================================
    CAmount nDevAllocation = Consensus::GetDevAllocation(nHeight, nBlockSubsidy);
    CScript devScript = Consensus::GetDevScriptForHeight(nHeight);
    
    LogPrint(BCLog::VALIDATION, "CreateNewBlock: Dev allocation %s at height %d\n",
             FormatMoney(nDevAllocation), nHeight);
    
    // Calculate masternode payment (if active)
    // Masternode payment is calculated from subsidy only - fees go entirely to miner
    // This follows Dash Core behavior and ensures consistent, predictable MN payments
    CAmount nMasternodePayment = 0;
    CScript masternodePayoutScript;
    CAmount nOperatorPayment = 0;
    CScript operatorPayoutScript;
    bool bMasternodePayment = false;
    bool bOperatorPayment = false;
    
    // Use the SAME activation check as the validator (IsMasternodePaymentEnforced)
    // so the miner only includes MN payments when the validator will enforce them.
    if (IsMasternodePaymentEnforced(nHeight) && deterministicMNManager) {
        CDeterministicMNCPtr payee = deterministicMNManager->GetMNPayee(pindexPrev);
        if (payee) {
            CAmount nTotalMNPayment = nBlockSubsidy * consensusParams.nMasternodeRewardPercent / 100;
            
            // Split between operator and owner if operator reward is configured
            if (payee->nOperatorReward > 0 && !payee->state.scriptOperatorPayout.empty()) {
                nOperatorPayment = nTotalMNPayment * payee->nOperatorReward / 10000;
                if (nOperatorPayment > 0) {
                    operatorPayoutScript = payee->state.scriptOperatorPayout;
                    bOperatorPayment = true;
                }
            }
            
            // After nConsensusFixHeight, when operator gets 100%, send the
            // full payment to the operator script (no separate owner output).
            if (nHeight >= consensusParams.nConsensusFixHeight &&
                payee->nOperatorReward == 10000 && !payee->state.scriptOperatorPayout.empty()) {
                nMasternodePayment = nTotalMNPayment;
                masternodePayoutScript = payee->state.scriptOperatorPayout;
                nOperatorPayment = 0;
                bOperatorPayment = false;
            } else {
                nMasternodePayment = nTotalMNPayment - nOperatorPayment;
                masternodePayoutScript = payee->state.scriptPayout;
            }
            bMasternodePayment = true;
            
            CTxDestination payoutDest;
            std::string payoutAddr = "unknown";
            if (ExtractDestination(masternodePayoutScript, payoutDest)) {
                payoutAddr = EncodeDestination(payoutDest);
            }
            LogPrint(BCLog::MASTERNODE, "CreateNewBlock: MN payment to %s (%s), owner: %s, operator: %s\n",
                     payee->proTxHash.ToString().substr(0, 16), payoutAddr,
                     FormatMoney(nMasternodePayment), FormatMoney(nOperatorPayment));
        }
    }
    
    // =========================================================================
    // CREATE COINBASE OUTPUTS
    // =========================================================================
    //
    // Provably fair launch - output structure:
    // Output 0: Miner reward (subsidy - dev - masternode + all fees)
    // Output 1: Dev allocation (always present, consensus-enforced)
    // Output 2: Masternode payment (if masternodes active)
    //
    // The dev allocation output is MANDATORY for all blocks.
    // Blocks without correct dev allocation are rejected at consensus.
    // =========================================================================
    
    // Calculate miner's share: subsidy - dev allocation - masternode payment - operator payment + all fees
    CAmount nMinerReward = nBlockSubsidy - nDevAllocation - nMasternodePayment - nOperatorPayment + nFees;
    
    if (bMasternodePayment) {
        if (bOperatorPayment) {
            // Four outputs: miner, dev, MN owner, MN operator
            coinbaseTx.vout.resize(4);
            coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
            coinbaseTx.vout[0].nValue = nMinerReward;
            coinbaseTx.vout[1].scriptPubKey = devScript;
            coinbaseTx.vout[1].nValue = nDevAllocation;
            coinbaseTx.vout[2].scriptPubKey = masternodePayoutScript;
            coinbaseTx.vout[2].nValue = nMasternodePayment;
            coinbaseTx.vout[3].scriptPubKey = operatorPayoutScript;
            coinbaseTx.vout[3].nValue = nOperatorPayment;
        } else {
            // Three outputs: miner, dev, masternode
            coinbaseTx.vout.resize(3);
            coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
            coinbaseTx.vout[0].nValue = nMinerReward;
            coinbaseTx.vout[1].scriptPubKey = devScript;
            coinbaseTx.vout[1].nValue = nDevAllocation;
            coinbaseTx.vout[2].scriptPubKey = masternodePayoutScript;
            coinbaseTx.vout[2].nValue = nMasternodePayment;
        }
    } else {
        // Two outputs: miner, dev (no masternode payment yet)
        coinbaseTx.vout.resize(2);
        coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
        coinbaseTx.vout[0].nValue = nMinerReward;
        coinbaseTx.vout[1].scriptPubKey = devScript;
        coinbaseTx.vout[1].nValue = nDevAllocation;
    }
    
    LogPrint(BCLog::VALIDATION, "CreateNewBlock: Coinbase outputs - Miner: %s, Dev: %s, MN: %s\n",
             FormatMoney(nMinerReward), FormatMoney(nDevAllocation), FormatMoney(nMasternodePayment));
    
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblock->nNonce64         = 0;
    pblock->nHeight          = nHeight;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        if (state.IsTransactionError()) {
            if (gArgs.GetBoolArg("-autofixmempool", false)) {
                {
                    TRY_LOCK(mempool.cs, fLockMempool);
                    if (fLockMempool) {
                        LogPrintf("%s failed because of a transaction %s. -autofixmempool is set to true. Clearing the mempool\n", __func__,
                                  state.GetFailedTransaction().GetHex());
                        mempool.clear();
                    }
                }
            } else {
                {
                    TRY_LOCK(mempool.cs, fLockMempool);
                    if (fLockMempool) {
                        auto mempoolTx = mempool.get(state.GetFailedTransaction());
                        if (mempoolTx) {
                            LogPrintf("%s : Failed because of a transaction %s. Trying to remove the transaction from the mempool\n", __func__, state.GetFailedTransaction().GetHex());
                            mempool.removeRecursive(*mempoolTx, MemPoolRemovalReason::CONFLICT);
                        }
                    }
                }
            }
        }
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (const CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (const CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}


static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("ProcessBlockFound -- generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    //CValidationState state;
    //std::shared_ptr<CBlock> shared_pblock = std::make_shared<CBlock>(pblock);
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(chainparams, shared_pblock, true, nullptr))
        return error("ProcessBlockFound -- ProcessNewBlock() failed, block not accepted");

    return true;
}

CWallet *GetFirstWallet() {
#ifdef ENABLE_WALLET
    while(vpwallets.size() == 0){
        MilliSleep(100);

    }
    if (vpwallets.size() == 0)
        return(NULL);
    return(vpwallets[0]);
#endif
    return(NULL);
}

void static MyntaMiner(const CChainParams& chainparams)
{
    LogPrintf("MyntaMiner -- started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("mynta-miner");

    unsigned int nExtraNonce = 0;


    CWallet * pWallet = NULL;

#ifdef ENABLE_WALLET
    pWallet = GetFirstWallet();


    if (!EnsureWalletIsAvailable(pWallet, false)) {
        LogPrintf("MyntaMiner -- Wallet not available\n");
    }
#endif

    if (pWallet == NULL)
    {
        LogPrintf("pWallet is NULL\n");
        return;
    }


    std::shared_ptr<CReserveScript> coinbaseScript;

    pWallet->GetScriptForMining(coinbaseScript);

    //GetMainSignals().ScriptForMining(coinbaseScript);

    if (!coinbaseScript)
        LogPrintf("coinbaseScript is NULL\n");

    if (coinbaseScript->reserveScript.empty())
        LogPrintf("coinbaseScript is empty\n");

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty())
        {
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");
        }


        while (true) {

            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    break;
                    if ((g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) > 0) && !IsInitialBlockDownload()) {
                        break;
                    }

                    MilliSleep(1000);
                } while (true);
            }

            // MYNTA LAUNCH: Wait for chain start time before mining
            // This prevents premature mining while allowing pre-release binary distribution
            const Consensus::Params& consensusParams = chainparams.GetConsensus();
            if (consensusParams.nChainStartTime > 0) {
                int64_t nCurrentTime = GetTime();
                if (nCurrentTime < consensusParams.nChainStartTime) {
                    int64_t nWaitSeconds = consensusParams.nChainStartTime - nCurrentTime;
                    int64_t nDays = nWaitSeconds / 86400;
                    int64_t nHours = (nWaitSeconds % 86400) / 3600;
                    int64_t nMins = (nWaitSeconds % 3600) / 60;
                    LogPrintf("MyntaMiner -- Chain not started yet!\n");
                    LogPrintf("MyntaMiner -- Launch: January 14, 2026 4:00 PM PST\n");
                    LogPrintf("MyntaMiner -- Time until launch: %d days, %d hours, %d minutes\n", nDays, nHours, nMins);
                    LogPrintf("MyntaMiner -- Waiting for launch time...\n");
                    // Sleep for up to 60 seconds at a time, checking for thread interruption
                    while (GetTime() < consensusParams.nChainStartTime) {
                        boost::this_thread::interruption_point();
                        MilliSleep(60000); // Sleep 60 seconds
                    }
                    LogPrintf("MyntaMiner -- ***LAUNCH TIME REACHED!*** Mining can now begin!\n");
                }
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.Tip();
            if(!pindexPrev) break;



            std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(GetParams()).CreateNewBlock(coinbaseScript->reserveScript));

            if (!pblocktemplate.get())
            {
                LogPrintf("MyntaMiner -- Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("MyntaMiner -- Running miner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search
            //
            int64_t nStart = GetTime();
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            while (true)
            {

                uint256 hash;
                uint256 mix_hash;
                while (true)
                {
                    hash = pblock->GetHashFull(mix_hash);
                    if (UintToArith256(hash) <= hashTarget)
                    {
                        pblock->mix_hash = mix_hash;
                        // Found a solution
                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
                        LogPrintf("MyntaMiner:\n  proof-of-work found\n  hash: %s\n  target: %s\n", hash.GetHex(), hashTarget.GetHex());
                        ProcessBlockFound(pblock, chainparams);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        coinbaseScript->KeepScript();

                        // In regression test mode, stop mining after a block is found. This
                        // allows developers to controllably generate a block on demand.
                        if (chainparams.MineBlocksOnDemand())
                            throw boost::thread_interrupted();

                        break;
                    }
                    // Increment the appropriate nonce for the PoW algorithm
                    // KawPow uses 64-bit nonce, X16R uses 32-bit nonce
                    if (pblock->nTime >= nKAWPOWActivationTime && nKAWPOWActivationTime > 0) {
                        pblock->nNonce64 += 1;
                    } else {
                        pblock->nNonce += 1;
                    }
                    nHashesDone += 1;
                    
                    // Calculate hashrate: after first 1000 hashes, then every second
                    // Uses thread-local to track last update time (minimal overhead)
                    {
                        static thread_local int64_t nLastHashrateUpdate = 0;
                        int64_t nNow = GetTimeMicros();
                        bool shouldUpdate = (nHashesDone == 1000) ||  // First calculation at 1000 hashes
                                           (nNow - nLastHashrateUpdate >= 1000000);  // Then every second
                        if (shouldUpdate) {
                            int64_t nElapsedSec = (nNow - nMiningTimeStart) / 1000000;
                            if (nElapsedSec > 0) {
                                nHashesPerSec = nHashesDone / nElapsedSec;
                            }
                            nLastHashrateUpdate = nNow;
                        }
                    }
                    
                    // Break to check for interrupts - use appropriate nonce for algorithm
                    if (pblock->nTime >= nKAWPOWActivationTime && nKAWPOWActivationTime > 0) {
                        // KawPow: break every 256 hashes
                        if ((pblock->nNonce64 & 0xFF) == 0)
                            break;
                    } else {
                        // X16R: break every 256 hashes  
                        if ((pblock->nNonce & 0xFF) == 0)
                            break;
                    }
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();
                // Regtest mode doesn't require peers
                //if (vNodes.empty() && chainparams.MiningRequiresPeers())
                //    break;
                // Check nonce overflow based on algorithm
                if (pblock->nTime >= nKAWPOWActivationTime && nKAWPOWActivationTime > 0) {
                    // KawPow: unlikely to overflow 64-bit, but check anyway
                    if (pblock->nNonce64 >= 0xffffffffffff0000ULL)
                        break;
                } else {
                    // X16R: check 32-bit nonce overflow
                    if (pblock->nNonce >= 0xffff0000)
                        break;
                }
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                // Update nTime every few seconds
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0)
                    break; // Recreate the block if the clock has run backwards,
                           // so that we can use the correct time.
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks)
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("MyntaMiner -- terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("MyntaMiner -- runtime error: %s\n", e.what());
        return;
    }
}

int GenerateMyntas(bool fGenerate, int nThreads, const CChainParams& chainparams)
{

    static boost::thread_group* minerThreads = NULL;

    int numCores = GetNumCores();
    if (nThreads < 0)
        nThreads = numCores;

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
        fMiningActive.store(false);
    }

    if (nThreads == 0 || !fGenerate) {
        fMiningActive.store(false);
        return numCores;
    }

    minerThreads = new boost::thread_group();
    
    //Reset metrics
    nMiningTimeStart = GetTimeMicros();
    nHashesDone = 0;
    nHashesPerSec = 0;

    for (int i = 0; i < nThreads; i++){
        minerThreads->create_thread(boost::bind(&MyntaMiner, boost::cref(chainparams)));
    }
    
    fMiningActive.store(true);

    return(numCores);
}
