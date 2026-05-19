//! `poly-chain` — local testnet CLI.
//!
//! Manages Ed25519 wallets and runs a single-process verify-only testnet:
//! genesis, faucet, build/sign/submit transfers, mine blocks, query balances.
//!
//! Testnet only: keyfiles store secret keys in plaintext and the faucet mints
//! funds freely. Do not point this at anything holding real value.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use poly_chain::builder::{build_cash_transfer, CashTransferParams};
use poly_chain::error::{ChainError, Result};
use poly_chain::identity::Tier;
use poly_chain::keys::Keypair;
use poly_chain::keystore::Keyfile;
use poly_chain::node::Testnet;
use poly_chain::primitives::{hex_encode, AccountId};
use poly_verified::types::ZERO_HASH;

#[derive(Parser)]
#[command(name = "poly-chain", about = "Poly-chain local testnet & wallet")]
struct Cli {
    /// Directory holding the chain and wallet keyfiles.
    #[arg(long, global = true, default_value = "testnet-data")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wallet key management.
    Wallet {
        #[command(subcommand)]
        action: WalletCmd,
    },
    /// Initialize a new testnet (genesis block).
    Init,
    /// Mint testnet funds to an account (admin op, no block).
    Faucet {
        /// Recipient: a wallet label or a 64-hex account id.
        #[arg(long)]
        to: String,
        /// Amount in smallest units (1 MANA = 10000 units).
        #[arg(long)]
        amount: u64,
    },
    /// Show an account's balance.
    Balance {
        /// A wallet label or a 64-hex account id.
        #[arg(long)]
        account: String,
    },
    /// Build, sign and submit a transfer to the mempool.
    Send {
        /// Sender wallet label (its keyfile signs the transfer).
        #[arg(long)]
        from: String,
        /// Recipient: a wallet label or a 64-hex account id.
        #[arg(long)]
        to: String,
        /// Amount in smallest units.
        #[arg(long)]
        amount: u64,
        /// Fee in smallest units (minimum 100).
        #[arg(long, default_value_t = 100)]
        fee: u64,
    },
    /// Mine the mempool into a new block.
    Mine,
    /// Show chain status.
    Status,
    /// Print just the state root — compare it with other participants to
    /// detect divergence (any cheating changes this hash).
    Root,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Generate a new wallet keypair.
    New {
        #[arg(long)]
        label: String,
    },
    /// List all wallets in the data directory.
    List,
    /// Show a wallet's address.
    Show {
        #[arg(long)]
        label: String,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Exclusive advisory lock over a data directory.
///
/// Every mutating command does a load → modify → save sequence; without a lock,
/// two concurrent processes lost-update each other (a transfer or mint silently
/// vanishes). The lock file is removed on drop.
struct LockGuard {
    path: PathBuf,
}

impl LockGuard {
    fn acquire(data_dir: &Path) -> Result<Self> {
        ensure_dir(data_dir)?;
        let path = data_dir.join(".lock");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(LockGuard { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(ChainError::Io(
                format!(
                    "another poly-chain process is using {} (delete {} if it is stale)",
                    data_dir.display(),
                    path.display()
                ),
            )),
            Err(e) => Err(ChainError::Io(format!("lock {}: {e}", path.display()))),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn run(cli: Cli) -> Result<()> {
    // Serialize every command that mutates chain.json behind a lock file.
    let needs_lock = matches!(
        cli.command,
        Command::Init | Command::Faucet { .. } | Command::Send { .. } | Command::Mine
    );
    let _lock = if needs_lock {
        Some(LockGuard::acquire(&cli.data_dir)?)
    } else {
        None
    };

    match cli.command {
        Command::Wallet { action } => match action {
            WalletCmd::New { label } => wallet_new(&cli.data_dir, &label),
            WalletCmd::List => wallet_list(&cli.data_dir),
            WalletCmd::Show { label } => wallet_show(&cli.data_dir, &label),
        },
        Command::Init => node_init(&cli.data_dir),
        Command::Faucet { to, amount } => faucet(&cli.data_dir, &to, amount),
        Command::Balance { account } => balance(&cli.data_dir, &account),
        Command::Send {
            from,
            to,
            amount,
            fee,
        } => send(&cli.data_dir, &from, &to, amount, fee),
        Command::Mine => mine(&cli.data_dir),
        Command::Status => status(&cli.data_dir),
        Command::Root => root(&cli.data_dir),
    }
}

// --- paths -----------------------------------------------------------------

fn wallets_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("wallets")
}

/// Reject wallet labels that are empty, over-long, or contain anything other
/// than `[A-Za-z0-9_-]`. Without this, `--label ../../chain` would let a
/// keyfile path escape the `wallets/` directory and overwrite arbitrary files.
fn validate_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 64 {
        return Err(ChainError::InvalidEncoding(
            "wallet label must be 1-64 characters".into(),
        ));
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ChainError::InvalidEncoding(
            "wallet label may only contain letters, digits, '-' and '_'".into(),
        ));
    }
    Ok(())
}

fn keyfile_path(data_dir: &Path, label: &str) -> Result<PathBuf> {
    validate_label(label)?;
    Ok(wallets_dir(data_dir).join(format!("{label}.json")))
}

fn chain_path(data_dir: &Path) -> PathBuf {
    data_dir.join("chain.json")
}

fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| ChainError::Io(format!("create {}: {e}", path.display())))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve an account argument: a 64-hex account id, or a wallet label.
fn resolve_account(data_dir: &Path, s: &str) -> Result<AccountId> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(s)
            .map_err(|e| ChainError::InvalidEncoding(format!("bad account hex: {e}")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        return Ok(id);
    }
    let keyfile = Keyfile::load(&keyfile_path(data_dir, s)?)?;
    keyfile.account_id_bytes()
}

fn load_node(data_dir: &Path) -> Result<Testnet> {
    let path = chain_path(data_dir);
    if !path.exists() {
        return Err(ChainError::Io(format!(
            "no testnet at {} — run `poly-chain init` first",
            path.display()
        )));
    }
    Testnet::load(&path)
}

// --- commands --------------------------------------------------------------

fn wallet_new(data_dir: &Path, label: &str) -> Result<()> {
    let path = keyfile_path(data_dir, label)?;
    ensure_dir(&wallets_dir(data_dir))?;
    if path.exists() {
        return Err(ChainError::Io(format!(
            "wallet '{label}' already exists at {}",
            path.display()
        )));
    }
    let keypair = Keypair::generate()?;
    let keyfile = Keyfile::from_keypair(label, &keypair);
    keyfile.save(&path)?;
    println!("created wallet '{label}'");
    println!("  address: {}", keyfile.account_id);
    println!("  keyfile: {}", path.display());
    Ok(())
}

fn wallet_list(data_dir: &Path) -> Result<()> {
    let dir = wallets_dir(data_dir);
    if !dir.exists() {
        println!("no wallets yet — create one with `poly-chain wallet new --label <name>`");
        return Ok(());
    }
    let mut found = false;
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| ChainError::Io(format!("read {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(keyfile) = Keyfile::load(&path) {
            println!("{:<16} {}", keyfile.label, keyfile.account_id);
            found = true;
        }
    }
    if !found {
        println!("no wallets yet — create one with `poly-chain wallet new --label <name>`");
    }
    Ok(())
}

fn wallet_show(data_dir: &Path, label: &str) -> Result<()> {
    let keyfile = Keyfile::load(&keyfile_path(data_dir, label)?)?;
    println!("wallet '{}'", keyfile.label);
    println!("  address:    {}", keyfile.account_id);
    println!("  public key: {}", keyfile.public_key);
    Ok(())
}

fn node_init(data_dir: &Path) -> Result<()> {
    ensure_dir(data_dir)?;
    let path = chain_path(data_dir);
    if path.exists() {
        return Err(ChainError::Io(format!(
            "testnet already exists at {}",
            path.display()
        )));
    }
    let net = Testnet::new(now());
    net.save(&path)?;
    println!("initialized testnet at {}", path.display());
    println!("  genesis state root: {}", hex_encode(&net.state.state_root()));
    Ok(())
}

fn faucet(data_dir: &Path, to: &str, amount: u64) -> Result<()> {
    let mut net = load_node(data_dir)?;
    let account = resolve_account(data_dir, to)?;
    let label = wallet_label_for(data_dir, &account).unwrap_or_else(|| "external".to_string());
    net.faucet(account, &label, amount, now())?;
    net.save(&chain_path(data_dir))?;
    println!("faucet: credited {amount} to {}", hex_encode(&account));
    println!("  balance: {}", net.balance(&account).unwrap_or(0));
    Ok(())
}

fn balance(data_dir: &Path, account: &str) -> Result<()> {
    let net = load_node(data_dir)?;
    let id = resolve_account(data_dir, account)?;
    match net.account(&id) {
        Some(entry) => {
            println!("account {}", entry.account_id);
            println!("  label:   {}", entry.label);
            println!("  balance: {}", entry.wallet.balance);
            println!("  nonce:   {}", entry.wallet.nonce);
        }
        None => println!("account {} is unknown to this testnet", hex_encode(&id)),
    }
    Ok(())
}

fn send(data_dir: &Path, from: &str, to: &str, amount: u64, fee: u64) -> Result<()> {
    let mut net = load_node(data_dir)?;
    let keyfile = Keyfile::load(&keyfile_path(data_dir, from)?)?;
    let sender = keyfile.keypair()?;
    let sender_id = sender.account_id();
    let recipient = resolve_account(data_dir, to)?;

    if net.has_pending_from(&sender_id) {
        return Err(ChainError::InvalidEncoding(format!(
            "wallet '{from}' already has a pending transfer — run `poly-chain mine` first"
        )));
    }
    let sender_entry = net
        .account(&sender_id)
        .ok_or_else(|| ChainError::AccountNotFound(format!("sender '{from}' has no funds")))?;
    if net.account(&recipient).is_none() {
        return Err(ChainError::AccountNotFound(format!(
            "recipient {} is not on this testnet — faucet it first",
            hex_encode(&recipient)
        )));
    }
    let state_pre = net
        .on_chain_pre(&sender_id)
        .ok_or_else(|| ChainError::AccountNotFound(format!("sender '{from}' has no wallet")))?;

    let params = CashTransferParams {
        to: recipient,
        amount,
        fee,
        nonce: net.next_nonce(&sender_id),
        timestamp: now(),
        state_pre,
        sender_tier: Tier::Anonymous,
        sender_identity_hash: ZERO_HASH,
        recipient_identity_hash: ZERO_HASH,
        chain_id: net.state.chain_id,
        rolling_24h_total_after: sender_entry.wallet.rolling_24h_total.saturating_add(amount),
        jurisdiction: 0,
    };
    let tx = build_cash_transfer(&sender, &params)?;
    net.submit(tx)?;
    net.save(&chain_path(data_dir))?;

    println!("queued transfer of {amount} (fee {fee}) from '{from}' to {}", hex_encode(&recipient));
    println!("  mempool size: {}", net.mempool.len());
    println!("  run `poly-chain mine` to include it in a block");
    Ok(())
}

fn mine(data_dir: &Path) -> Result<()> {
    let mut net = load_node(data_dir)?;
    let report = net.produce_block(now())?;
    net.save(&chain_path(data_dir))?;

    if report.accepted == 0 {
        println!("no block produced — every queued transaction was rejected");
    } else {
        println!("mined block {}", report.height);
    }
    println!("  accepted: {}", report.accepted);
    if report.rejected.is_empty() {
        println!("  rejected: 0");
    } else {
        println!("  rejected: {}", report.rejected.len());
        for (tx, reason) in &report.rejected {
            println!("    tx {tx}: {reason}");
        }
    }
    Ok(())
}

fn status(data_dir: &Path) -> Result<()> {
    let net = load_node(data_dir)?;
    let head = net.head();
    println!("testnet status");
    println!("  height:      {}", net.height());
    println!("  head hash:   {}", hex_encode(&head.header.block_hash()));
    println!("  state root:  {}", hex_encode(&net.state.state_root()));
    println!("  mempool:     {} transaction(s)", net.mempool.len());
    println!("  accounts:    {}", net.ledger.len());
    for entry in &net.ledger {
        println!(
            "    {:<16} {}  balance {}",
            entry.label,
            &entry.account_id[..16],
            entry.wallet.balance
        );
    }
    Ok(())
}

fn root(data_dir: &Path) -> Result<()> {
    let net = load_node(data_dir)?;
    println!("{}", hex_encode(&net.state.state_root()));
    Ok(())
}

/// Find the wallet label whose keyfile matches `account`, if any.
fn wallet_label_for(data_dir: &Path, account: &AccountId) -> Option<String> {
    let dir = wallets_dir(data_dir);
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        if let Ok(keyfile) = Keyfile::load(&entry.path()) {
            if keyfile.account_id_bytes().ok().as_ref() == Some(account) {
                return Some(keyfile.label);
            }
        }
    }
    None
}
