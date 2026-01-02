# MIP-001: Deterministic Masternodes

## Abstract

This proposal introduces deterministic masternodes to Mynta, providing a consensus-enforced masternode layer that enables reliable network services, fair reward distribution, and future governance capabilities.

## Motivation

Traditional masternode implementations rely on memory-only state and peer-to-peer announcements, leading to:
- Inconsistent masternode lists across nodes
- Non-deterministic payment selection
- Vulnerability to Sybil attacks
- Difficulty in proving masternode ownership

Deterministic masternodes solve these issues by anchoring all masternode state to the blockchain.

## Specification

### 1. Masternode Collateral

- **Collateral Amount**: 10,000 MYNTA (configurable via consensus params)
- **Collateral UTXO**: Must be a single unspent output of exactly the collateral amount
- **Collateral Lock**: UTXO remains spendable but spending invalidates masternode registration
- **Confirmations Required**: 15 blocks before masternode becomes active

### 2. Masternode Keys

Each masternode has three key pairs:

| Key | Purpose | Storage | Can Update |
|-----|---------|---------|------------|
| Owner Key | Signs registration, receives owner rights | Cold wallet | No |
| Operator Key | Signs service messages, runs node | Hot wallet on VPS | Yes |
| Voting Key | Participates in governance votes | Cold wallet | Yes |

### 3. Transaction Types

#### 3.1 ProRegTx (Provider Registration Transaction)

Registers a new masternode on the network.

```
Version: 1
Type: 1 (ProRegTx)
Fields:
  - version (uint16): Transaction version
  - type (uint16): Must be 1
  - mode (uint16): 0 = regular masternode
  - collateralOutpoint (COutPoint): Points to collateral UTXO
  - ipAddress (uint128): IPv4/IPv6 address
  - port (uint16): P2P port
  - ownerKeyId (CKeyID): Owner public key hash (P2PKH)
  - operatorPubKey (CBLSPublicKey): BLS public key for operator
  - votingKeyId (CKeyID): Voting public key hash
  - operatorReward (uint16): Operator reward percentage (0-10000 = 0-100%)
  - payoutAddress (CScript): Address for masternode rewards
  - inputsHash (uint256): Hash of all inputs (replay protection)
  - payloadSig (vector<uint8>): Signature by owner key
```

#### 3.2 ProUpServTx (Provider Update Service Transaction)

Updates the IP address and/or operator key.

```
Version: 1
Type: 2 (ProUpServTx)
Fields:
  - version (uint16): Transaction version
  - proTxHash (uint256): Hash of the ProRegTx
  - ipAddress (uint128): New IPv4/IPv6 address
  - port (uint16): New P2P port
  - operatorPubKey (CBLSPublicKey): New operator BLS key (optional)
  - inputsHash (uint256): Hash of all inputs
  - payloadSig (CBLSSignature): Signature by current operator key
```

#### 3.3 ProUpRegTx (Provider Update Registrar Transaction)

Updates voting key, operator key, or payout address.

```
Version: 1
Type: 3 (ProUpRegTx)
Fields:
  - version (uint16): Transaction version
  - proTxHash (uint256): Hash of the ProRegTx
  - mode (uint16): 0 = regular masternode
  - operatorPubKey (CBLSPublicKey): New operator key (optional)
  - votingKeyId (CKeyID): New voting key (optional)
  - payoutAddress (CScript): New payout address (optional)
  - inputsHash (uint256): Hash of all inputs
  - payloadSig (vector<uint8>): Signature by owner key
```

#### 3.4 ProUpRevTx (Provider Update Revocation Transaction)

Revokes the masternode registration.

```
Version: 1
Type: 4 (ProUpRevTx)
Fields:
  - version (uint16): Transaction version
  - proTxHash (uint256): Hash of the ProRegTx
  - reason (uint16): Revocation reason code
  - inputsHash (uint256): Hash of all inputs
  - payloadSig (CBLSSignature): Signature by operator key
```

### 4. Deterministic Masternode List (DML)

The DML is computed deterministically from the blockchain:

```cpp
class CDeterministicMN {
    uint256 proTxHash;           // Registration tx hash (unique ID)
    COutPoint collateralOutpoint; // Collateral UTXO
    uint16_t operatorReward;     // Operator reward share
    CDeterministicMNState state; // Current state
};

class CDeterministicMNState {
    int registeredHeight;        // Block where registered
    int lastPaidHeight;          // Last payment block
    int PoSePenalty;             // Proof of Service penalty score
    int PoSeRevivedHeight;       // Height when revived from PoSe ban
    int PoSeBanHeight;           // Height when banned (0 if not banned)
    uint16_t revocationReason;   // 0 if not revoked
    
    CKeyID ownerKeyId;
    CBLSPublicKey operatorPubKey;
    CKeyID votingKeyId;
    CService addr;               // IP:Port
    CScript payoutAddress;
    CScript operatorPayoutAddress;
};
```

### 5. Masternode State Machine

```
                    ┌─────────────┐
                    │   START     │
                    └──────┬──────┘
                           │ ProRegTx confirmed
                           ▼
                    ┌─────────────┐
                    │ REGISTERED  │ (waiting for confirmations)
                    └──────┬──────┘
                           │ 15 confirmations
                           ▼
                    ┌─────────────┐
         ┌─────────│   ENABLED   │◄────────┐
         │         └──────┬──────┘         │
         │                │                │
         │ PoSe           │ PoSe score     │ PoSe revived
         │ score=0        │ >= threshold   │
         │                ▼                │
         │         ┌─────────────┐         │
         └────────►│ POSE_BANNED │─────────┘
                   └──────┬──────┘
                          │ ProUpRevTx or
                          │ collateral spent
                          ▼
                   ┌─────────────┐
                   │   REVOKED   │
                   └─────────────┘
```

### 6. Payment Logic

Masternodes are paid deterministically based on:

1. **Eligibility**: Only ENABLED masternodes with confirmed collateral
2. **Selection Score**: `SHA256(SHA256(proTxHash || blockHash || blockHeight))`
3. **Round Robin**: Lowest score wins, excluding recently paid
4. **Payment Split**: 
   - Miners: 50% of block reward
   - Masternodes: 50% of block reward
   - Operator receives `operatorReward` percentage of MN share

### 7. Proof of Service (PoSe)

Masternodes must prove service availability:

- **Scoring Period**: 24 hours worth of blocks
- **Penalty Increment**: +66% per failed check
- **Ban Threshold**: Score >= 100
- **Revival**: Successful service proof after ban resets score

### 8. Consensus Rules

Block validation MUST:
1. Verify masternode payment amount and recipient
2. Verify the paid masternode is in ENABLED state
3. Verify the paid masternode had the winning score
4. Reject blocks with invalid masternode payments

Transaction validation MUST:
1. Verify all signatures on ProRegTx/ProUpServTx/ProUpRegTx/ProUpRevTx
2. Verify collateral UTXO exists and has correct amount
3. Verify no duplicate registrations (same collateral or keys)
4. Verify IP:Port is unique among active masternodes

### 9. Network Protocol

New message types:

| Message | Description |
|---------|-------------|
| `MNLISTDIFF` | Masternode list diff between two block hashes |
| `GETMNLISTD` | Request masternode list diff |

### 10. Activation

- **Activation Height**: Block 1000 (mainnet)
- **Testnet Activation**: Block 1
- **Regtest**: Always active

## Backwards Compatibility

This is a hard fork. All nodes must upgrade before activation height.

## Reference Implementation

See `src/evo/` and `src/masternode/` directories.

## Copyright

This document is placed in the public domain.

