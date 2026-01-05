use crate::{Dataplane, DataplaneCapabilities, DataplaneError, DataplaneStats, FrameView, RssConfig};

pub use aegis_af_xdp::{AfXdpDataplane, AfXdpFrame, XdpAttachFlags, XdpAttachMode};

impl FrameView for AfXdpFrame<'_> {
    fn bytes(&self) -> &[u8] {
        self.bytes()
    }

    fn timestamp(&self) -> Option<std::time::SystemTime> {
        None
    }
}

impl Dataplane for AfXdpDataplane {
    type Frame<'a> = AfXdpFrame<'a>;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError> {
        self.next_frame().map_err(map_err)
    }

    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError> {
        self.send_frame(frame).map_err(map_err)
    }

    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError> {
        let stats = self.stats().map_err(map_err)?;
        Ok(DataplaneStats {
            received: self.rx_count(),
            dropped: stats.rx_dropped,
            if_dropped: stats.rx_ring_full + stats.rx_fill_ring_empty,
            transmitted: self.tx_count(),
        })
    }

    fn configure_rss(&mut self, _rss: &RssConfig) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported(
            "af-xdp rss requires driver configuration",
        ))
    }

    fn capabilities(&self) -> DataplaneCapabilities {
        DataplaneCapabilities {
            supports_zero_copy_rx: true,
            supports_zero_copy_tx: true,
            supports_rss: false,
            supports_tx: true,
            supports_filters: false,
        }
    }
}

fn map_err(err: aegis_af_xdp::AfXdpError) -> DataplaneError {
    match err {
        aegis_af_xdp::AfXdpError::Unsupported(msg) => DataplaneError::Unsupported(msg),
        aegis_af_xdp::AfXdpError::Backend(msg) => DataplaneError::Backend(msg),
        aegis_af_xdp::AfXdpError::Config(msg) => DataplaneError::Config(msg),
    }
}
