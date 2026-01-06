use crate::{
    Dataplane, DataplaneCapabilities, DataplaneError, DataplaneStats, FrameView, PcapConfig,
    RssConfig, UnsupportedTxLease,
};
use pcap_shim::Capture;
use std::time::SystemTime;

#[derive(Debug)]
pub struct PcapDataplane {
    capture: Capture,
}

#[derive(Debug)]
pub struct PcapFrame<'a> {
    data: &'a [u8],
    timestamp: SystemTime,
}

impl PcapDataplane {
    pub fn open_live(iface: &str, cfg: &PcapConfig) -> Result<Self, DataplaneError> {
        let capture = Capture::open_live(iface, cfg.snaplen, cfg.promisc, cfg.timeout_ms)
            .map_err(DataplaneError::Backend)?;
        Ok(PcapDataplane { capture })
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<(), DataplaneError> {
        self.capture
            .set_filter(filter)
            .map_err(DataplaneError::Backend)
    }
}

impl FrameView for PcapFrame<'_> {
    fn bytes(&self) -> &[u8] {
        self.data
    }

    fn timestamp(&self) -> Option<SystemTime> {
        Some(self.timestamp)
    }
}

impl Dataplane for PcapDataplane {
    type Frame<'a> = PcapFrame<'a>;
    type Tx<'a> = UnsupportedTxLease<'a>;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError> {
        match self.capture.next() {
            Ok(Some(pkt)) => Ok(Some(PcapFrame {
                data: pkt.data,
                timestamp: pkt.ts,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(DataplaneError::Backend(e)),
        }
    }

    fn lease_tx(&mut self, _len: usize) -> Result<Self::Tx<'_>, DataplaneError> {
        Err(DataplaneError::Unsupported(
            "pcap backend does not support tx leasing",
        ))
    }

    fn send_frame(&mut self, _frame: &Self::Frame<'_>) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported(
            "pcap transmit is not available via pcap-shim",
        ))
    }

    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError> {
        let stats = self.capture.stats().map_err(DataplaneError::Backend)?;
        Ok(DataplaneStats {
            received: stats.received as u64,
            dropped: stats.dropped as u64,
            if_dropped: stats.if_dropped as u64,
            transmitted: 0,
        })
    }

    fn configure_rss(&mut self, _rss: &RssConfig) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported(
            "pcap does not expose rss configuration",
        ))
    }

    fn capabilities(&self) -> DataplaneCapabilities {
        DataplaneCapabilities {
            supports_zero_copy_rx: false,
            supports_zero_copy_tx: false,
            supports_rss: false,
            supports_tx: false,
            supports_filters: true,
        }
    }
}
