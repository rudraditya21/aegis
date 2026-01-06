use crate::{
    Dataplane, DataplaneCapabilities, DataplaneError, DataplaneStats, FrameView, RssConfig,
    RssHashField, TxLease,
};

pub use aegis_dpdk::{DpdkDataplane, DpdkFrame, DpdkTxLease};

impl FrameView for DpdkFrame<'_> {
    fn bytes(&self) -> &[u8] {
        self.bytes()
    }

    fn timestamp(&self) -> Option<std::time::SystemTime> {
        None
    }
}

impl Dataplane for DpdkDataplane {
    type Frame<'a> = DpdkFrame<'a>;
    type Tx<'a> = DpdkTxLease<'a>;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError> {
        self.next_frame().map_err(map_err)
    }

    fn lease_tx(&mut self, len: usize) -> Result<Self::Tx<'_>, DataplaneError> {
        DpdkDataplane::lease_tx(self, len).map_err(map_err)
    }

    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError> {
        self.send_frame(frame).map_err(map_err)
    }

    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError> {
        let stats = self.stats().map_err(map_err)?;
        Ok(DataplaneStats {
            received: stats.rx,
            dropped: stats.rx_dropped,
            if_dropped: stats.imissed,
            transmitted: stats.tx,
        })
    }

    fn configure_rss(&mut self, rss: &RssConfig) -> Result<(), DataplaneError> {
        let cfg = aegis_dpdk::DpdkRssConfig {
            enabled: rss.enabled,
            symmetric: rss.symmetric,
            hash_fields: rss
                .hash_fields
                .iter()
                .copied()
                .map(map_hash_field)
                .collect(),
            seed: rss.seed,
            queues: rss.queues.clone(),
        };
        self.configure_rss(&cfg).map_err(map_err)
    }

    fn capabilities(&self) -> DataplaneCapabilities {
        DataplaneCapabilities {
            supports_zero_copy_rx: true,
            supports_zero_copy_tx: true,
            supports_rss: true,
            supports_tx: true,
            supports_filters: false,
        }
    }
}

impl TxLease for DpdkTxLease<'_> {
    fn buffer(&mut self) -> &mut [u8] {
        DpdkTxLease::buffer(self)
    }

    fn commit(self, len: usize) -> Result<(), DataplaneError> {
        DpdkTxLease::commit(self, len).map_err(map_err)
    }
}

fn map_err(err: aegis_dpdk::DpdkError) -> DataplaneError {
    match err {
        aegis_dpdk::DpdkError::Unsupported(msg) => DataplaneError::Unsupported(msg),
        aegis_dpdk::DpdkError::Backend(msg) => DataplaneError::Backend(msg),
        aegis_dpdk::DpdkError::Config(msg) => DataplaneError::Config(msg),
    }
}

fn map_hash_field(field: RssHashField) -> aegis_dpdk::DpdkRssHashField {
    match field {
        RssHashField::Ipv4 => aegis_dpdk::DpdkRssHashField::Ipv4,
        RssHashField::Ipv6 => aegis_dpdk::DpdkRssHashField::Ipv6,
        RssHashField::Tcp => aegis_dpdk::DpdkRssHashField::Tcp,
        RssHashField::Udp => aegis_dpdk::DpdkRssHashField::Udp,
    }
}
