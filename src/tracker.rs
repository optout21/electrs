use crate::bitcoin::{BlockHash, Txid};
use crate::bitcoin_slices::{bsl, EmptyVisitor, Visit};
use anyhow::{Context, Result};
use bindex::{IndexedChain, Location};

use crate::{
    config::Config,
    daemon::Daemon,
    mempool::{FeeHistogram, Mempool},
    metrics::Metrics,
    signals::ExitFlag,
    status::{Balance, ScriptHashStatus, UnspentEntry},
};

/// Electrum protocol subscriptions' tracker
pub struct Tracker {
    index: IndexedChain,
    mempool: Mempool,
    ignore_mempool: bool,
    /// Height of the last prune lock set on bitcoind
    prune_lock_height: Option<usize>,
}

impl Tracker {
    pub fn new(config: &Config, metrics: Metrics) -> Result<Self> {
        let url = format!("http://{}", config.daemon_rpc_addr);
        let options = bindex::Options {
            // the REST API check needs the genesis block, which may be pruned
            skip_rest_api_check: config.pruned,
        };
        let index =
            IndexedChain::open_with_options(&config.db_dir, config.network, Some(url), options)
                .context("failed to open index")?;
        Ok(Self {
            index,
            mempool: Mempool::new(&metrics),
            ignore_mempool: config.ignore_mempool,
            prune_lock_height: None,
        })
    }

    pub(crate) fn headers(&self) -> &bindex::Headers {
        self.index.headers()
    }

    /// Height of the first block not indexed yet
    pub(crate) fn next_height(&self) -> usize {
        self.index
            .headers()
            .tip_height()
            .map_or(0, |height| height + 1)
    }

    pub(crate) fn fees_histogram(&self) -> &FeeHistogram {
        self.mempool.fees_histogram()
    }

    pub(crate) fn get_unspent(&self, status: &ScriptHashStatus) -> Vec<UnspentEntry> {
        status.get_unspent()
    }

    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        exit_flag.poll()?;
        let stats = self.index.sync(1000)?;
        // keep the blocks that are not indexed yet from being pruned
        let next_height = self.next_height();
        if self.prune_lock_height != Some(next_height) {
            daemon.update_prune_lock(next_height)?;
            self.prune_lock_height = Some(next_height);
        }
        let done = stats.indexed_blocks == 0;
        if done && !self.ignore_mempool {
            self.mempool.sync(daemon, exit_flag);
            // TODO: double check tip - and retry on diff
        }
        Ok(done)
    }

    pub(crate) fn status(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) fn update_scripthash_status(
        &self,
        daemon: &Daemon,
        status: &mut ScriptHashStatus,
    ) -> Result<bool> {
        let prev_statushash = status.statushash();
        status.sync(&self.index, &self.mempool, |location| {
            self.get_tx_bytes(daemon, location)
        })?;
        Ok(prev_statushash != status.statushash())
    }

    pub(crate) fn get_balance(&self, status: &ScriptHashStatus) -> Balance {
        status.get_balance()
    }

    pub(crate) fn lookup_transaction(
        &self,
        daemon: &Daemon,
        txid: Txid,
    ) -> Result<Option<(BlockHash, Box<[u8]>)>> {
        // Note: there are two blocks with coinbase transactions having same txid (see BIP-30)
        for loc in self.index.locations_by_txid(&txid)? {
            let tx_bytes = self.get_tx_bytes(daemon, &loc)?;
            if txid == compute_txid(&tx_bytes)? {
                return Ok(Some((loc.block_hash(), tx_bytes.into_boxed_slice())));
            }
        }
        Ok(None)
    }

    /// Fetch a confirmed transaction's bytes from bitcoind. On a pruned node, if the data of its
    /// block is not available anymore, fetch the block from a peer and retry.
    fn get_tx_bytes(&self, daemon: &Daemon, location: &Location) -> Result<Vec<u8>> {
        match self.index.get_tx_bytes(location) {
            Err(err) if err.is_not_found() && daemon.is_pruned() => {
                debug!("block {} not available: {}", location.block_hash(), err);
                daemon.fetch_pruned_block(location.block_hash())?;
                Ok(self.index.get_tx_bytes(location)?)
            }
            res => Ok(res?),
        }
    }
}

fn compute_txid(tx_bytes: &[u8]) -> Result<Txid> {
    let mut visit = EmptyVisitor {};
    let res = bsl::Transaction::visit(tx_bytes, &mut visit)
        .map_err(|err| anyhow!("invalid transaction: {:?}", err))?;
    ensure!(res.remaining().is_empty(), "non-empty remaining bytes");
    Ok(Txid::from_raw_hash(res.parsed().txid()))
}
