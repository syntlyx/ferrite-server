//! A smoltcp `phy::Device` that is just two packet queues. The tunnel loop fills
//! `inbound` with IP packets decrypted from the peer and drains `outbound` to
//! encrypt and send. No real NIC — medium is `Ip` (point-to-point, no L2).

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub struct WgDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl WgDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            mtu,
        }
    }

    /// Queue a decrypted IP packet for smoltcp to receive.
    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    /// Pop an IP packet smoltcp wants to transmit (to be encrypted + sent).
    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

pub struct WgRxToken {
    packet: Vec<u8>,
}

impl RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct WgTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for WgTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.outbound.push_back(buf);
        r
    }
}

impl Device for WgDevice {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            WgRxToken { packet },
            WgTxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::from_micros(0)
    }

    #[test]
    fn shuttles_inbound_and_outbound_packets() {
        let mut dev = WgDevice::new(1420);
        // Nothing queued → no RX.
        assert!(dev.receive(now()).is_none());

        // A decrypted packet pushed in is handed to smoltcp via the RxToken.
        dev.push_inbound(vec![1, 2, 3]);
        {
            let (rx, _tx) = dev.receive(now()).unwrap();
            assert_eq!(rx.consume(|p| p.to_vec()), vec![1, 2, 3]);
        }

        // A TxToken's written packet shows up in the outbound queue to encrypt.
        let tx = dev.transmit(now()).unwrap();
        tx.consume(4, |buf| buf.copy_from_slice(&[9, 9, 9, 9]));
        assert_eq!(dev.take_outbound(), Some(vec![9, 9, 9, 9]));
        assert_eq!(dev.take_outbound(), None);
    }

    #[test]
    fn capabilities_report_ip_medium_and_mtu() {
        let caps = WgDevice::new(1380).capabilities();
        assert_eq!(caps.max_transmission_unit, 1380);
        assert!(matches!(caps.medium, Medium::Ip));
    }
}
