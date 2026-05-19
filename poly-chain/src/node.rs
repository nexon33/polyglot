//! Local single-process testnet node.
//!
//! [`Testnet`] maintains the verify-only chain ([`GlobalState`] + a block list)
//! together with an **off-chain balance ledger**. The chain itself only stores
//! opaque wallet commitment hashes — it never tracks balances — so a full node
//! must hold real [`WalletState`] balances and enforce them itself. This node
//! does exactly that, then commits the chain's view via `validate_transaction`.

use poly_verified::types::{Hash, ZERO_HASH};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::block::Block;
use crate::error::{ChainError, Result};
use crate::identity::Tier;
use crate::primitives::*;
use crate::state::GlobalState;
use crate::transaction::Transaction;
use crate::validation::validate_transaction;
use crate::wallet::WalletState;

/// An off-chain account: the real balance the verify-only chain does not track.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Account id, hex-encoded.
    pub account_id: String,
    /// Optional human label (e.g. the wallet name that faucet-funded it).
    pub label: String,
    /// Full off-chain wallet state, including the authoritative balance.
    pub wallet: WalletState,
}

/// Outcome of mining one block.
#[derive(Clone, Debug)]
pub struct BlockReport {
    pub height: BlockHeight,
    pub accepted: usize,
    /// `(short tx hash, reason)` for every rejected transaction.
    pub rejected: Vec<(String, String)>,
}

/// A recorded faucet mint.
///
/// Faucet operations carry no transaction, so they are logged here instead.
/// Replaying the allocations then the block history reconstructs the whole
/// state from genesis — see [`Testnet::verify_integrity`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Funded account id, hex-encoded.
    pub account_id: String,
    pub label: String,
    pub amount: Amount,
    pub timestamp: Timestamp,
}

/// The complete testnet: chain, state, mempool and off-chain ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Testnet {
    pub chain: Vec<Block>,
    pub state: GlobalState,
    pub mempool: Vec<Transaction>,
    pub ledger: Vec<LedgerEntry>,
    /// Recorded faucet mints, applied before any block when reconstructing
    /// state from genesis. `#[serde(default)]` keeps older files loadable.
    #[serde(default)]
    pub genesis_allocations: Vec<GenesisAllocation>,
}

impl Testnet {
    /// Create a fresh testnet with a genesis block at `now` and a random,
    /// network-unique chain id.
    pub fn new(now: Timestamp) -> Self {
        let mut chain_id = [0u8; 32];
        // A failure here would only weaken cross-chain replay protection, not
        // correctness; the ZERO fallback is acceptable.
        let _ = getrandom::getrandom(&mut chain_id);
        Self::with_genesis(now, chain_id)
    }

    /// Construct a testnet with an explicit genesis timestamp and chain id.
    /// Used by [`new`](Self::new) and by replay reconstruction.
    fn with_genesis(now: Timestamp, chain_id: Hash) -> Self {
        let mut state = GlobalState::genesis();
        state.chain_id = chain_id;
        let genesis = Block::genesis(state.state_root(), now);
        Self {
            chain: vec![genesis],
            state,
            mempool: Vec::new(),
            ledger: Vec::new(),
            genesis_allocations: Vec::new(),
        }
    }

    /// Height of the chain head.
    pub fn height(&self) -> BlockHeight {
        // The chain always contains at least the genesis block.
        self.chain.last().map(|b| b.header.height).unwrap_or(0)
    }

    /// The chain head block.
    pub fn head(&self) -> &Block {
        self.chain
            .last()
            .expect("testnet chain always has a genesis block")
    }

    fn ledger_index(&self, account: &AccountId) -> Option<usize> {
        let key = hex_encode(account);
        self.ledger.iter().position(|e| e.account_id == key)
    }

    /// Look up an account's off-chain entry.
    pub fn account(&self, account: &AccountId) -> Option<&LedgerEntry> {
        self.ledger_index(account).map(|i| &self.ledger[i])
    }

    /// Authoritative off-chain balance, or `None` if the account is unknown.
    pub fn balance(&self, account: &AccountId) -> Option<Amount> {
        self.account(account).map(|e| e.wallet.balance)
    }

    /// The sender's current on-chain wallet commitment — the `state_pre` a new
    /// transfer must carry. `None` if the account has no on-chain wallet.
    pub fn on_chain_pre(&self, account: &AccountId) -> Option<Hash> {
        self.state.get_wallet(account)
    }

    /// The next nonce the chain expects from `account`.
    pub fn next_nonce(&self, account: &AccountId) -> Nonce {
        self.state.get_nonce(account)
    }

    /// Whether the mempool already holds a transaction paid for by `account`.
    ///
    /// A second transfer from the same payer can only be built once the first
    /// is mined (nonce / `state_pre` would otherwise be stale), so the CLI
    /// uses this to refuse a premature second send.
    pub fn has_pending_from(&self, account: &AccountId) -> bool {
        self.mempool
            .iter()
            .any(|tx| tx.fee_payer().as_ref() == Some(account))
    }

    /// Admin / genesis op: credit testnet funds to an account.
    ///
    /// Only permitted before the first block is mined, so the recorded
    /// allocations plus the block history fully determine the state (the chain
    /// stays reconstructible from genesis). Each mint is logged in
    /// `genesis_allocations`.
    pub fn faucet(
        &mut self,
        account: AccountId,
        label: &str,
        amount: Amount,
        now: Timestamp,
    ) -> Result<()> {
        if self.chain.len() > 1 {
            return Err(ChainError::InvalidEncoding(
                "faucet is only allowed before the first block is mined".into(),
            ));
        }
        self.genesis_allocations.push(GenesisAllocation {
            account_id: hex_encode(&account),
            label: label.to_string(),
            amount,
            timestamp: now,
        });
        self.apply_faucet(account, label, amount, now);
        Ok(())
    }

    /// Apply a faucet mint to state + ledger, without recording it. Shared by
    /// [`faucet`](Self::faucet) and replay reconstruction.
    fn apply_faucet(&mut self, account: AccountId, label: &str, amount: Amount, now: Timestamp) {
        match self.ledger_index(&account) {
            Some(i) => {
                self.ledger[i].wallet.balance =
                    self.ledger[i].wallet.balance.saturating_add(amount);
                // Refresh this one account's committed hash so chain state
                // keeps reflecting the real balance.
                let hash = self.ledger[i].wallet.state_hash();
                self.state.set_wallet(account, hash);
            }
            None => {
                let mut wallet = WalletState::new(ZERO_HASH, Tier::Anonymous, now);
                wallet.balance = amount;
                // The on-chain commitment is set once, at account creation, so
                // existing nonce / state_pre chains are never disturbed.
                self.state.set_wallet(account, wallet.state_hash());
                self.ledger.push(LedgerEntry {
                    account_id: hex_encode(&account),
                    label: label.to_string(),
                    wallet,
                });
            }
        }
    }

    /// Add a transaction to the mempool. Only `CashTransfer` is supported by
    /// the testnet CLI today.
    pub fn submit(&mut self, tx: Transaction) -> Result<()> {
        match &tx {
            Transaction::CashTransfer(_) => {
                self.mempool.push(tx);
                Ok(())
            }
            other => Err(ChainError::InvalidEncoding(format!(
                "testnet node only accepts CashTransfer, got tag 0x{:02x}",
                other.tag()
            ))),
        }
    }

    /// Drain the mempool into a new block.
    ///
    /// Each transaction is validated against the chain *and* against the
    /// off-chain ledger (balances the chain does not track). Accepted
    /// transactions are applied; rejected ones are reported and dropped.
    ///
    /// If no transaction is accepted, no block is appended (the returned
    /// report has `height` unchanged) — empty blocks would otherwise be
    /// unreplayable, since the chain stores only accepted transactions.
    pub fn produce_block(&mut self, now: Timestamp) -> Result<BlockReport> {
        if self.mempool.is_empty() {
            return Err(ChainError::InvalidEncoding(
                "mempool is empty — nothing to mine".into(),
            ));
        }

        let pending = std::mem::take(&mut self.mempool);
        let next_height = self
            .height()
            .checked_add(1)
            .ok_or(ChainError::BlockHeightOverflow)?;

        let mut accepted: Vec<Transaction> = Vec::new();
        let mut rejected: Vec<(String, String)> = Vec::new();

        for tx in pending {
            let short = hex_encode(&tx.tx_hash()[..4]);
            match self.try_apply(&tx, now, next_height) {
                Ok(()) => accepted.push(tx),
                Err(e) => rejected.push((short, e.to_string())),
            }
        }

        if accepted.is_empty() {
            // Nothing applied — do not append an (unreplayable) empty block.
            return Ok(BlockReport {
                height: self.height(),
                accepted: 0,
                rejected,
            });
        }

        let block = Block::try_new(
            &self.head().header,
            accepted.clone(),
            self.state.state_root(),
            now,
        )?;
        let height = block.header.height;
        self.chain.push(block);

        Ok(BlockReport {
            height,
            accepted: accepted.len(),
            rejected,
        })
    }

    /// Validate one transaction and, if it passes, apply both the chain state
    /// transition and the off-chain balance movement.
    fn try_apply(&mut self, tx: &Transaction, now: Timestamp, height: BlockHeight) -> Result<()> {
        let transfer = match tx {
            Transaction::CashTransfer(t) => t.clone(),
            other => {
                return Err(ChainError::InvalidEncoding(format!(
                    "unsupported transaction tag 0x{:02x}",
                    other.tag()
                )))
            }
        };

        // 1. Off-chain solvency — the chain itself never checks this.
        let total_debit = transfer
            .amount
            .checked_add(transfer.fee)
            .ok_or(ChainError::ComplianceViolation("amount + fee overflow".into()))?;
        let sender_idx = self
            .ledger_index(&transfer.from)
            .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&transfer.from[..4])))?;
        let recipient_idx = self
            .ledger_index(&transfer.to)
            .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&transfer.to[..4])))?;
        let available = self.ledger[sender_idx].wallet.balance;
        if available < total_debit {
            return Err(ChainError::InsufficientBalance {
                needed: total_debit,
                available,
            });
        }

        // 2. Chain validation — real proof + signature verification.
        let new_state = validate_transaction(tx, &self.state, now, height)?;

        // 3. Commit: chain state, then off-chain balances.
        self.state = new_state;

        let sender = &mut self.ledger[sender_idx].wallet;
        sender.maybe_reset_rolling(now);
        sender.balance -= total_debit;
        sender.nonce = sender.nonce.saturating_add(1);
        sender.rolling_24h_total = sender.rolling_24h_total.saturating_add(transfer.amount);

        let recipient = &mut self.ledger[recipient_idx].wallet;
        recipient.balance = recipient.balance.saturating_add(transfer.amount);

        // Commit the *real*, balance-inclusive wallet hashes into chain state.
        // `validate_cash_transfer` writes only an opaque `H(from||nonce||amount)`
        // commitment that does not bind the balance; overwriting it with
        // `WalletState::state_hash()` makes `state_root` a complete commitment
        // to every balance. Every participant replaying these blocks derives an
        // identical root, so a forged balance changes the root and is instantly
        // detectable — no off-chain trust required.
        let sender_hash = self.ledger[sender_idx].wallet.state_hash();
        let recipient_hash = self.ledger[recipient_idx].wallet.state_hash();
        self.state.set_wallet(transfer.from, sender_hash);
        self.state.set_wallet(transfer.to, recipient_hash);

        Ok(())
    }

    /// Persist the testnet to `path` as JSON (atomically).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ChainError::InvalidEncoding(format!("testnet encode: {e}")))?;
        write_atomic(path, json.as_bytes())
    }

    /// Load a testnet from `path` and verify its integrity.
    ///
    /// A testnet file may have been hand-edited or received from an untrusted
    /// peer, so loading without verification would let a forged file through.
    /// [`verify_integrity`](Self::verify_integrity) re-checks every invariant.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| ChainError::Io(format!("read {}: {e}", path.display())))?;
        let net: Testnet = serde_json::from_slice(&bytes)
            .map_err(|e| ChainError::InvalidEncoding(format!("testnet decode: {e}")))?;
        net.verify_integrity()?;
        Ok(net)
    }

    /// Re-verify every structural invariant of the testnet.
    ///
    /// This is the trust boundary for a deserialized [`Testnet`]: it does not
    /// assume the bytes came from this node's own `save`. It checks the chain
    /// links, that the mempool only holds supported transactions, and — most
    /// importantly — that the off-chain `ledger` exactly matches the on-chain
    /// committed state. `SparseMerkleTree` recomputes its root on
    /// deserialization (see state.rs), so `state_root()` here already reflects
    /// the real leaves rather than any wire-supplied value.
    pub fn verify_integrity(&self) -> Result<()> {
        // 1. Non-empty chain rooted at a well-formed genesis block.
        let genesis = self.chain.first().ok_or_else(|| {
            ChainError::InvalidEncoding("chain has no genesis block".into())
        })?;
        if genesis.header.height != 0 || genesis.header.prev_block_hash != ZERO_HASH {
            return Err(ChainError::InvalidEncoding(
                "malformed genesis block".into(),
            ));
        }
        if !genesis.verify_transactions_root() {
            return Err(ChainError::InvalidEncoding(
                "genesis transactions_root mismatch".into(),
            ));
        }

        // 2. Every later block links to its parent (hash chain, height
        //    continuity, timestamp ordering, tx_count, transactions_root).
        for i in 1..self.chain.len() {
            self.chain[i].validate_against_parent(&self.chain[i - 1].header)?;
        }

        // 3. The mempool may only hold transactions this node can process.
        for tx in &self.mempool {
            if !matches!(tx, Transaction::CashTransfer(_)) {
                return Err(ChainError::InvalidEncoding(format!(
                    "mempool holds unsupported transaction tag 0x{:02x}",
                    tx.tag()
                )));
            }
        }

        // 4. The off-chain ledger must match the on-chain committed state
        //    exactly: same accounts, and each account's committed hash and
        //    nonce equal the ledger wallet's. This is what prevents a forged
        //    chain.json from claiming a balance the chain does not commit to.
        if self.state.wallets.len() != self.ledger.len() {
            return Err(ChainError::InvalidEncoding(format!(
                "ledger/chain account count mismatch: {} ledger vs {} on-chain",
                self.ledger.len(),
                self.state.wallets.len()
            )));
        }
        for entry in &self.ledger {
            let id = decode_account(&entry.account_id)?;
            let committed = self.state.get_wallet(&id).ok_or_else(|| {
                ChainError::AccountNotFound(format!(
                    "ledger account {} has no on-chain wallet",
                    &entry.account_id
                ))
            })?;
            let real = entry.wallet.state_hash();
            if committed != real {
                return Err(ChainError::StateHashMismatch {
                    expected: hex_encode(&real),
                    actual: hex_encode(&committed),
                });
            }
            if self.state.get_nonce(&id) != entry.wallet.nonce {
                return Err(ChainError::InvalidNonce {
                    expected: self.state.get_nonce(&id),
                    actual: entry.wallet.nonce,
                });
            }
        }

        // 5. Full from-genesis replay: the stored state must be exactly what
        //    the recorded genesis allocations plus the block history produce.
        //    This is what makes the chain independently verifiable — a forged
        //    state that is internally self-consistent still fails here unless
        //    it is the genuine result of the recorded history.
        let rebuilt = self.rebuild()?;
        if rebuilt.chain.len() != self.chain.len() {
            return Err(ChainError::InvalidEncoding(format!(
                "replay produced {} blocks, file has {}",
                rebuilt.chain.len(),
                self.chain.len()
            )));
        }
        if rebuilt.state.state_root() != self.state.state_root() {
            return Err(ChainError::StateHashMismatch {
                expected: hex_encode(&rebuilt.state.state_root()),
                actual: hex_encode(&self.state.state_root()),
            });
        }
        Ok(())
    }

    /// Reconstruct the testnet from scratch: replay the recorded genesis
    /// allocations, then re-apply every recorded block's transactions. The
    /// result is what the history *should* produce, independent of the stored
    /// `state` / `ledger` fields.
    fn rebuild(&self) -> Result<Testnet> {
        let genesis = self.chain.first().ok_or_else(|| {
            ChainError::InvalidEncoding("chain has no genesis block".into())
        })?;
        let mut fresh = Testnet::with_genesis(genesis.header.timestamp, self.state.chain_id);
        for alloc in &self.genesis_allocations {
            let id = decode_account(&alloc.account_id)?;
            fresh.apply_faucet(id, &alloc.label, alloc.amount, alloc.timestamp);
        }
        for block in self.chain.iter().skip(1) {
            for tx in &block.transactions {
                fresh.submit(tx.clone())?;
            }
            fresh.produce_block(block.header.timestamp)?;
        }
        Ok(fresh)
    }
}

/// Decode a 64-hex account id string into raw bytes.
fn decode_account(hex_id: &str) -> Result<AccountId> {
    let bytes = hex::decode(hex_id)
        .map_err(|e| ChainError::InvalidEncoding(format!("bad account id hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ChainError::InvalidEncoding(format!("account id wrong length: {} bytes", v.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{build_cash_transfer, CashTransferParams};
    use crate::keys::Keypair;

    fn transfer_params(node: &Testnet, from: &AccountId, to: AccountId, amount: Amount) -> CashTransferParams {
        let wallet = &node.account(from).unwrap().wallet;
        CashTransferParams {
            to,
            amount,
            fee: 100,
            nonce: node.next_nonce(from),
            timestamp: 20_000,
            state_pre: node.on_chain_pre(from).unwrap(),
            sender_tier: Tier::Anonymous,
            sender_identity_hash: ZERO_HASH,
            recipient_identity_hash: ZERO_HASH,
            chain_id: node.state.chain_id,
            rolling_24h_total_after: wallet.rolling_24h_total + amount,
            jurisdiction: 0,
        }
    }

    #[test]
    fn genesis_has_one_block() {
        let net = Testnet::new(1_000);
        assert_eq!(net.height(), 0);
        assert_eq!(net.chain.len(), 1);
    }

    #[test]
    fn faucet_creates_account() {
        let mut net = Testnet::new(1_000);
        let kp = Keypair::generate().unwrap();
        net.faucet(kp.account_id(), "alice", 50_000, 1_000).unwrap();
        assert_eq!(net.balance(&kp.account_id()), Some(50_000));
        assert!(net.on_chain_pre(&kp.account_id()).is_some());
    }

    #[test]
    fn faucet_twice_accumulates() {
        let mut net = Testnet::new(1_000);
        let kp = Keypair::generate().unwrap();
        net.faucet(kp.account_id(), "alice", 10_000, 1_000).unwrap();
        net.faucet(kp.account_id(), "alice", 5_000, 1_000).unwrap();
        assert_eq!(net.balance(&kp.account_id()), Some(15_000));
    }

    #[test]
    fn transfer_moves_balance_and_mines() {
        let mut net = Testnet::new(1_000);
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        net.faucet(alice.account_id(), "alice", 50_000, 1_000).unwrap();
        net.faucet(bob.account_id(), "bob", 0, 1_000).unwrap();

        let params = transfer_params(&net, &alice.account_id(), bob.account_id(), 10_000);
        let tx = build_cash_transfer(&alice, &params).unwrap();
        net.submit(tx).unwrap();

        let report = net.produce_block(20_000).unwrap();
        assert_eq!(report.height, 1);
        assert_eq!(report.accepted, 1);
        assert!(report.rejected.is_empty());

        // amount + fee debited from alice; amount credited to bob.
        assert_eq!(net.balance(&alice.account_id()), Some(50_000 - 10_000 - 100));
        assert_eq!(net.balance(&bob.account_id()), Some(10_000));
        assert_eq!(net.next_nonce(&alice.account_id()), 1);
    }

    #[test]
    fn transfer_replaces_only_affected_account_hashes() {
        let mut net = Testnet::new(1_000);
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        let carol = Keypair::generate().unwrap();
        net.faucet(alice.account_id(), "alice", 50_000, 1_000).unwrap();
        net.faucet(bob.account_id(), "bob", 0, 1_000).unwrap();
        net.faucet(carol.account_id(), "carol", 9_000, 1_000).unwrap();

        let carol_before = net.on_chain_pre(&carol.account_id()).unwrap();

        let params = transfer_params(&net, &alice.account_id(), bob.account_id(), 10_000);
        let tx = build_cash_transfer(&alice, &params).unwrap();
        net.submit(tx).unwrap();
        net.produce_block(20_000).unwrap();

        // Carol was not involved — her committed hash is untouched.
        assert_eq!(net.on_chain_pre(&carol.account_id()).unwrap(), carol_before);

        // Sender and recipient hashes were replaced with their real,
        // balance-inclusive WalletState hashes.
        let alice_wallet = &net.account(&alice.account_id()).unwrap().wallet;
        let bob_wallet = &net.account(&bob.account_id()).unwrap().wallet;
        assert_eq!(
            net.on_chain_pre(&alice.account_id()).unwrap(),
            alice_wallet.state_hash()
        );
        assert_eq!(
            net.on_chain_pre(&bob.account_id()).unwrap(),
            bob_wallet.state_hash()
        );
    }

    #[test]
    fn independent_replay_yields_identical_state_root() {
        // Two participants performing the same operations must derive the
        // exact same state root — the basis for instant cheat detection.
        fn run() -> Testnet {
            // Same chain id: this models two participants on the SAME chain,
            // not two independently-created (and thus distinct) testnets.
            let mut net = Testnet::with_genesis(1_000, [42u8; 32]);
            let alice = Keypair::from_secret_bytes(&[7u8; 32]);
            let bob = Keypair::from_secret_bytes(&[9u8; 32]);
            net.faucet(alice.account_id(), "alice", 50_000, 1_000).unwrap();
            net.faucet(bob.account_id(), "bob", 1_000, 1_000).unwrap();
            let params = transfer_params(&net, &alice.account_id(), bob.account_id(), 4_000);
            let tx = build_cash_transfer(&alice, &params).unwrap();
            net.submit(tx).unwrap();
            net.produce_block(20_000).unwrap();
            net
        }
        let a = run();
        let b = run();
        assert_eq!(a.state.state_root(), b.state.state_root());
        assert_eq!(
            a.head().header.block_hash(),
            b.head().header.block_hash()
        );
    }

    #[test]
    fn forged_balance_changes_state_root() {
        // A participant who tampers with a balance produces a divergent root.
        let mut honest = Testnet::new(1_000);
        let alice = Keypair::from_secret_bytes(&[3u8; 32]);
        honest.faucet(alice.account_id(), "alice", 10_000, 1_000).unwrap();

        let mut cheater = honest.clone();
        let idx = cheater.ledger_index(&alice.account_id()).unwrap();
        cheater.ledger[idx].wallet.balance = 999_999;
        let hash = cheater.ledger[idx].wallet.state_hash();
        cheater.state.set_wallet(alice.account_id(), hash);

        assert_ne!(honest.state.state_root(), cheater.state.state_root());
    }

    #[test]
    fn insufficient_balance_is_rejected() {
        let mut net = Testnet::new(1_000);
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        net.faucet(alice.account_id(), "alice", 500, 1_000).unwrap();
        net.faucet(bob.account_id(), "bob", 0, 1_000).unwrap();

        let params = transfer_params(&net, &alice.account_id(), bob.account_id(), 10_000);
        let tx = build_cash_transfer(&alice, &params).unwrap();
        net.submit(tx).unwrap();

        let report = net.produce_block(20_000).unwrap();
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected.len(), 1);
        // Balances unchanged.
        assert_eq!(net.balance(&alice.account_id()), Some(500));
        assert_eq!(net.balance(&bob.account_id()), Some(0));
    }

    #[test]
    fn second_transfer_after_mining_works() {
        let mut net = Testnet::new(1_000);
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        net.faucet(alice.account_id(), "alice", 50_000, 1_000).unwrap();
        net.faucet(bob.account_id(), "bob", 0, 1_000).unwrap();

        for _ in 0..2 {
            let params = transfer_params(&net, &alice.account_id(), bob.account_id(), 5_000);
            let tx = build_cash_transfer(&alice, &params).unwrap();
            net.submit(tx).unwrap();
            let report = net.produce_block(20_000).unwrap();
            assert_eq!(report.accepted, 1, "rejected: {:?}", report.rejected);
        }
        assert_eq!(net.balance(&bob.account_id()), Some(10_000));
        assert_eq!(net.next_nonce(&alice.account_id()), 2);
    }

    #[test]
    fn save_load_roundtrip() {
        let mut net = Testnet::new(1_000);
        let alice = Keypair::generate().unwrap();
        net.faucet(alice.account_id(), "alice", 7_777, 1_000).unwrap();

        let dir = std::env::temp_dir().join(format!("pc-node-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chain.json");
        net.save(&path).unwrap();

        let loaded = Testnet::load(&path).unwrap();
        assert_eq!(loaded.balance(&alice.account_id()), Some(7_777));
        assert_eq!(loaded.height(), net.height());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_mempool_mine_errors() {
        let mut net = Testnet::new(1_000);
        assert!(net.produce_block(2_000).is_err());
    }
}
