use anyhow::{Context, Result};

use crate::bitcoin::{
    self, consensus::deserialize, consensus::encode::serialize_hex, hashes::hex::FromHex, Amount,
    BlockHash, Transaction, Txid,
};
use crate::types::Auth;
use serde::Serialize;
use serde_json::{json, value::RawValue, Value};

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{config::Config, signals::ExitFlag};

/// Prune lock id used by electrs (stored by bitcoind as "user:electrs")
const PRUNE_LOCK_ID: &str = "electrs";
/// Prune lock id created by bitcoind's `-prunelockheight` option
const INIT_PRUNE_LOCK_ID: &str = "init";

/// How long to wait for a peer to send a block requested with `getblockfrompeer`
const BLOCK_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to check whether a requested block has arrived
const BLOCK_FETCH_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How many peers to try before giving up on fetching a block
const BLOCK_FETCH_MAX_PEERS: usize = 3;

enum PollResult {
    Done(Result<()>),
    Retry,
}

#[derive(Deserialize)]
pub struct GetMempoolEntryResultFees {
    /// Transaction fee in BTC
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,
}

#[derive(Deserialize)]
pub struct GetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "size")]
    pub vsize: u64,
    /// Fee information
    pub fees: GetMempoolEntryResultFees,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<bitcoin::Txid>,
}

#[derive(Deserialize)]
pub struct GetBlockchainInfoResult {
    pub blocks: u64,
    pub headers: u64,
    pub initialblockdownload: bool,
    pub pruned: bool,
    /// The first unpruned block (only present if pruning is enabled)
    pub pruneheight: Option<u64>,
}

#[derive(Deserialize)]
pub struct EstimateSmartFeeResult {
    /// Estimate fee rate in BTC/kB.
    #[serde(
        default,
        rename = "feerate",
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_btc::opt"
    )]
    pub fee_rate: Option<Amount>,
}

#[derive(Deserialize)]
pub struct GetNetworkInfoResult {
    #[serde(rename = "relayfee", with = "bitcoin::amount::serde::as_btc")]
    pub relay_fee: Amount,
}

#[derive(Deserialize)]
pub struct GetMempoolInfoResult {
    /// True if the mempool is fully loaded
    pub loaded: Option<bool>,
}

fn read_cookie(path: &Path) -> Result<(String, String)> {
    // Load username and password from bitcoind cookie file:
    // * https://github.com/bitcoin/bitcoin/pull/6388/commits/71cbeaad9a929ba6a7b62d9b37a09b214ae00c1a
    // * https://bitcoin.stackexchange.com/questions/46782/rpc-cookie-authentication
    let mut file = File::open(path)
        .with_context(|| format!("failed to open bitcoind cookie file: {}", path.display()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("failed to read bitcoind cookie from {}", path.display()))?;

    let parts: Vec<&str> = contents.splitn(2, ':').collect();
    ensure!(
        parts.len() == 2,
        "failed to parse bitcoind cookie - missing ':' separator"
    );
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}

fn jsonrpc_client(config: &Config) -> Result<jsonrpc::Client> {
    let rpc_url = format!("http://{}", config.daemon_rpc_addr);
    // Allow RPC calls to take longer before timing out.
    // See https://github.com/romanz/electrs/issues/495 for more details.
    let builder = jsonrpc::simple_http::SimpleHttpTransport::builder()
        .url(&rpc_url)?
        .timeout(config.jsonrpc_timeout);
    let builder = match config.daemon_auth.get_auth() {
        Auth::UserPass(user, pass) => builder.auth(user, Some(pass)),
        Auth::CookieFile(path) => {
            let (user, pass) = read_cookie(&path)?;
            builder.auth(user, Some(pass))
        }
    };
    Ok(jsonrpc::Client::with_transport(builder.build()))
}

#[derive(Deserialize)]
struct GetPeerInfoResult {
    id: i64,
    inbound: bool,
    #[serde(default)]
    servicesnames: Vec<String>,
}

pub struct Daemon {
    client: jsonrpc::Client,
    pruned: AtomicBool,
    /// Serializes fetching pruned blocks from peers (see `fetch_pruned_block()`)
    block_fetch_lock: Mutex<()>,
}

impl Daemon {
    /// `prune_lock_height` is the first block not indexed yet: on a pruned node, a prune lock is
    /// set at this height before waiting for block download, so the blocks needed for indexing
    /// are kept.
    pub(crate) fn connect(
        config: &Config,
        exit_flag: &ExitFlag,
        prune_lock_height: usize,
    ) -> Result<Self> {
        let daemon = Daemon {
            client: jsonrpc_client(config)?,
            pruned: AtomicBool::new(false),
            block_fetch_lock: Mutex::new(()),
        };

        loop {
            exit_flag
                .poll()
                .context("bitcoin RPC polling interrupted")?;
            match daemon.rpc_poll(
                config.skip_block_download_wait,
                config.pruned,
                prune_lock_height,
            ) {
                PollResult::Done(result) => {
                    result.context("bitcoind RPC polling failed")?;
                    break; // on success, finish polling
                }
                PollResult::Retry => {
                    std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit before polling
                }
            }
        }

        Ok(daemon)
    }

    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T, jsonrpc::Error> {
        let raw = serde_json::value::to_raw_value(args)?;
        let req = self.client.build_request(cmd, Some(&*raw));
        let resp = self.client.send_request(req)?;
        resp.result()
    }

    fn batch_request<T>(&self, name: &str, items: &[T]) -> Result<Vec<Option<jsonrpc::Response>>>
    where
        T: Serialize,
    {
        debug!("calling {} on {} items", name, items.len());
        let args: Vec<Box<RawValue>> = items
            .iter()
            .map(|item| jsonrpc::try_arg([item]).context("failed to serialize into JSON"))
            .collect::<Result<Vec<_>>>()?;
        let reqs: Vec<jsonrpc::Request> = args
            .iter()
            .map(|arg| self.client.build_request(name, Some(arg)))
            .collect();
        match self.client.send_batch(&reqs) {
            Ok(values) => {
                assert_eq!(items.len(), values.len());
                Ok(values)
            }
            Err(err) => bail!("batch {} request failed: {}", name, err),
        }
    }

    fn rpc_poll(
        &self,
        skip_block_download_wait: bool,
        allow_pruned: bool,
        prune_lock_height: usize,
    ) -> PollResult {
        match self.call::<GetBlockchainInfoResult>("getblockchaininfo", &[]) {
            Ok(info) => {
                if info.pruned {
                    if !allow_pruned {
                        return PollResult::Done(Err(anyhow!(
                            "electrs requires non-pruned bitcoind node (use --pruned to allow it)"
                        )));
                    }
                    let first_poll = !self.pruned.swap(true, Ordering::Relaxed);
                    if let Err(err) = self.set_prune_lock(prune_lock_height) {
                        return PollResult::Done(Err(err));
                    }
                    if first_poll {
                        // our own lock is set, so the `-prunelockheight` lock is not needed anymore
                        if let Err(err) = self.remove_init_prune_lock() {
                            return PollResult::Done(Err(err));
                        }
                    }
                    if let Some(pruneheight) = info.pruneheight {
                        if pruneheight > prune_lock_height as u64 {
                            return PollResult::Done(Err(anyhow!(
                                "bitcoind already pruned blocks needed for indexing (pruneheight={}, next block to index={}): reindex bitcoind",
                                pruneheight,
                                prune_lock_height
                            )));
                        }
                    }
                }
                if skip_block_download_wait {
                    // bitcoind RPC is available, don't wait for block download to finish
                    return PollResult::Done(Ok(()));
                }
                let left_blocks = info.headers - info.blocks;
                if info.initialblockdownload || left_blocks > 0 {
                    info!(
                        "waiting for {} blocks to download{}",
                        left_blocks,
                        if info.initialblockdownload {
                            " (IBD)"
                        } else {
                            ""
                        }
                    );
                    return PollResult::Retry;
                }
                PollResult::Done(Ok(()))
            }
            Err(err) => {
                if let Some(e) = extract_bitcoind_error(&err) {
                    if e.code == -28 {
                        debug!("waiting for RPC warmup: {}", e.message);
                        return PollResult::Retry;
                    }
                }
                PollResult::Done(Err(err).context("daemon not available"))
            }
        }
    }

    /// Move the prune lock to `height` (the first block not indexed yet).
    /// Does nothing if bitcoind is not pruned.
    pub(crate) fn update_prune_lock(&self, height: usize) -> Result<()> {
        if !self.pruned.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.set_prune_lock(height)
    }

    fn set_prune_lock(&self, height: usize) -> Result<()> {
        // Requires bitcoind with the `setprunelock` RPC
        self.call::<Value>(
            "setprunelock",
            &[json!(PRUNE_LOCK_ID), json!("add"), json!(height)],
        )
        .with_context(|| format!("failed to set prune lock at height {}", height))?;
        debug!("prune lock set at height {}", height);
        Ok(())
    }

    /// Remove the prune lock created by bitcoind's `-prunelockheight` option, if present.
    fn remove_init_prune_lock(&self) -> Result<()> {
        let res = self.call::<Value>(
            "setprunelock",
            &[json!(INIT_PRUNE_LOCK_ID), json!("remove")],
        );
        if let Err(jsonrpc::Error::Rpc(jsonrpc::error::RpcError { code: -8, .. })) = res {
            return Ok(()); // the lock is not present
        }
        res.context("failed to remove initial prune lock")?;
        info!("removed bitcoind initial prune lock (set by -prunelockheight)");
        Ok(())
    }

    pub(crate) fn estimate_fee(&self, nblocks: u16) -> Result<Option<Amount>> {
        let res =
            self.call::<EstimateSmartFeeResult>("estimatesmartfee", &[json!(nblocks), Value::Null]);
        if let Err(jsonrpc::Error::Rpc(jsonrpc::error::RpcError { code: -32603, .. })) = res {
            return Ok(None); // don't fail when fee estimation is disabled (e.g. with `-blocksonly=1`)
        }
        Ok(res.context("failed to estimate fee")?.fee_rate)
    }

    pub(crate) fn get_relay_fee(&self) -> Result<Amount> {
        Ok(self
            .call::<GetNetworkInfoResult>("getnetworkinfo", &[])
            .context("failed to get relay fee")?
            .relay_fee)
    }

    pub(crate) fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.call("sendrawtransaction", &[json!(serialize_hex(tx))])
            .context("failed to broadcast transaction")
    }

    pub(crate) fn submitpackage(&self, txs: &[Transaction]) -> Result<Value> {
        let package: Vec<String> = txs.iter().map(serialize_hex).collect();
        self.call("submitpackage", &[json!(package)])
            .context("failed to submitpackage package")
    }

    pub(crate) fn get_transaction(
        &self,
        txid: &Txid,
        blockhash: Option<BlockHash>,
        verbose: bool,
    ) -> Result<Value> {
        let call = || {
            self.call(
                "getrawtransaction",
                &[json!(txid), json!(verbose), json!(blockhash)],
            )
        };
        match blockhash {
            Some(blockhash) => self.call_with_block(blockhash, call),
            None => call().map_err(anyhow::Error::from),
        }
        .context("failed to get transaction")
    }

    pub(crate) fn get_block_txids(&self, blockhash: BlockHash) -> Result<Vec<Txid>> {
        #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
        struct GetBlockResult {
            pub tx: Vec<bitcoin::Txid>,
        }
        let res: GetBlockResult = self
            .call_with_block(blockhash, || {
                self.call("getblock", &[json!(blockhash), json!(1)])
            })
            .context("failed to get block txids")?;
        Ok(res.tx)
    }

    /// Whether bitcoind is pruned (known after connecting)
    pub(crate) fn is_pruned(&self) -> bool {
        self.pruned.load(Ordering::Relaxed)
    }

    /// Run an RPC call that needs the data of block `blockhash`. If it fails because the
    /// block's data is not available (it has been pruned), fetch the block from a peer and
    /// retry once.
    fn call_with_block<T>(
        &self,
        blockhash: BlockHash,
        call: impl Fn() -> Result<T, jsonrpc::Error>,
    ) -> Result<T> {
        match call() {
            Err(err) if self.is_pruned() && is_block_not_available(&err) => {
                debug!("block {} not available: {}", blockhash, err);
                self.fetch_pruned_block(blockhash)?;
                Ok(call()?)
            }
            res => Ok(res?),
        }
    }

    /// Fetch a block whose data has been pruned from a peer (using `getblockfrompeer`), and
    /// wait until bitcoind has stored it. The block is kept until bitcoind prunes it again.
    ///
    /// Fetches are serialized, so that concurrent requests for the same block don't ask
    /// peers for it more than once.
    pub(crate) fn fetch_pruned_block(&self, blockhash: BlockHash) -> Result<()> {
        let _guard = self.block_fetch_lock.lock().unwrap();
        if self.has_block_data(blockhash) {
            return Ok(()); // fetched in the meantime, or never pruned
        }
        let peers = self.block_serving_peers()?;
        if peers.is_empty() {
            bail!(
                "block {} is pruned, and no connected peer serves old blocks",
                blockhash
            );
        }
        for peer_id in peers.into_iter().take(BLOCK_FETCH_MAX_PEERS) {
            info!("fetching pruned block {} from peer {}", blockhash, peer_id);
            if let Err(err) =
                self.call::<Value>("getblockfrompeer", &[json!(blockhash), json!(peer_id)])
            {
                if self.has_block_data(blockhash) {
                    return Ok(()); // e.g. "Block already downloaded"
                }
                warn!(
                    "failed to request block {} from peer {}: {}",
                    blockhash, peer_id, err
                );
                continue;
            }
            let deadline = Instant::now() + BLOCK_FETCH_TIMEOUT;
            while Instant::now() < deadline {
                if self.has_block_data(blockhash) {
                    info!("fetched pruned block {}", blockhash);
                    return Ok(());
                }
                std::thread::sleep(BLOCK_FETCH_POLL_INTERVAL);
            }
            warn!(
                "peer {} did not send block {} within {:?}",
                peer_id, blockhash, BLOCK_FETCH_TIMEOUT
            );
        }
        bail!("failed to fetch pruned block {} from peers", blockhash)
    }

    /// Whether bitcoind has the data of block `blockhash`
    fn has_block_data(&self, blockhash: BlockHash) -> bool {
        self.call::<String>("getblock", &[json!(blockhash), json!(0)])
            .is_ok()
    }

    /// Ids of connected peers that serve the full block chain (not only recent blocks),
    /// outbound peers first.
    fn block_serving_peers(&self) -> Result<Vec<i64>> {
        let mut peers: Vec<GetPeerInfoResult> = self
            .call("getpeerinfo", &[])
            .context("failed to get peer info")?;
        peers.retain(|peer| peer.servicesnames.iter().any(|s| s == "NETWORK"));
        peers.sort_by_key(|peer| peer.inbound);
        Ok(peers.into_iter().map(|peer| peer.id).collect())
    }

    pub(crate) fn get_mempool_info(&self) -> Result<GetMempoolInfoResult> {
        self.call("getmempoolinfo", &[])
            .context("failed to get mempool info")
    }

    pub(crate) fn get_mempool_txids(&self) -> Result<Vec<Txid>> {
        self.call("getrawmempool", &[])
            .context("failed to get mempool txids")
    }

    pub(crate) fn get_mempool_entries(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Option<GetMempoolEntryResult>>> {
        let results = self.batch_request("getmempoolentry", txids)?;
        Ok(results
            .into_iter()
            .map(|r| match r?.result::<GetMempoolEntryResult>() {
                Ok(entry) => Some(entry),
                Err(err) => {
                    debug!("failed to get mempool entry: {}", err); // probably due to RBF
                    None
                }
            })
            .collect())
    }

    pub(crate) fn get_mempool_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Option<Transaction>>> {
        let results = self.batch_request("getrawtransaction", txids)?;
        Ok(results
            .into_iter()
            .map(|r| -> Option<Transaction> {
                let tx_hex = match r?.result::<String>() {
                    Ok(tx_hex) => Some(tx_hex),
                    Err(err) => {
                        debug!("failed to get mempool tx: {}", err); // probably due to RBF
                        None
                    }
                }?;
                let tx_bytes = match Vec::from_hex(&tx_hex) {
                    Ok(tx_bytes) => Some(tx_bytes),
                    Err(err) => {
                        warn!("got non-hex transaction {}: {}", tx_hex, err);
                        None
                    }
                }?;
                match deserialize(&tx_bytes) {
                    Ok(tx) => Some(tx),
                    Err(err) => {
                        warn!("got invalid tx {}: {}", tx_hex, err);
                        None
                    }
                }
            })
            .collect())
    }
}

/// Whether an RPC error says that a block's data is not available, e.g.
/// "Block not available (pruned data)" from `getblock` (and `getrawtransaction` with a block
/// hash), or "Transaction may be in pruned block ..." from `getrawtransaction` in newer
/// versions of bitcoind.
fn is_block_not_available(err: &jsonrpc::Error) -> bool {
    extract_bitcoind_error(err)
        .is_some_and(|e| e.message.contains("not available") || e.message.contains("pruned block"))
}

pub(crate) fn extract_bitcoind_error(err: &jsonrpc::Error) -> Option<&jsonrpc::error::RpcError> {
    match err {
        jsonrpc::error::Error::Rpc(e) => Some(e),
        _ => None,
    }
}
