//! A box's end of the relay: one QUIC connection out to the relay — through
//! any NAT, no port forwarded — kept up and made again when it drops, and
//! the device connections the relay passes on over it, each handed to
//! [`Inbound`] with whose it is.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::io::BufReader;

use crate::identity::{Identity, parse_pin};
use crate::proto::{self, Control, Opening, PROTOCOL};
use crate::tls;

/// A connection the relay passed on, both directions.
pub type Stream = tokio::io::Join<quinn::RecvStream, quinn::SendStream>;

/// What a box does with a connection the relay passed on.
pub trait Inbound: Send + Sync + 'static {
    fn serve(&self, stream: Stream, opening: Opening) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Where the box stands with its relay.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub connected: bool,
    /// The box's name under the relay's zone, once welcomed.
    pub name: Option<String>,
    /// Every name the relay passes on to it.
    pub names: Vec<String>,
    /// Why it isn't connected, last time it tried.
    pub error: Option<String>,
    /// Unix seconds since when it has been connected.
    pub since: Option<i64>,
}

pub struct Client {
    identity: Identity,
    /// `host:port` of the relay's QUIC side.
    server: String,
    relay_key: [u8; 32],
    software: String,
    status: Mutex<Status>,
}

/// The first wait after a drop, and the longest.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);
/// A session this long was a good one: the next drop starts the waits over.
const STEADY: Duration = Duration::from_secs(60);
const WELCOME: Duration = Duration::from_secs(10);

impl Client {
    pub fn new(
        identity: Identity,
        server: &str,
        pin: &str,
        software: &str,
    ) -> Result<Self, String> {
        let relay_key =
            parse_pin(pin).ok_or_else(|| format!("{pin} isn't a pin like sha256:<64 hex>"))?;
        Ok(Client {
            identity,
            server: server.trim().to_string(),
            relay_key,
            software: software.to_string(),
            status: Mutex::new(Status::default()),
        })
    }

    pub fn id(&self) -> &str {
        &self.identity.id
    }

    pub fn status(&self) -> Status {
        self.status.lock().clone()
    }

    /// Stay connected until the task is dropped.
    pub async fn run(self: Arc<Self>, inbound: Arc<dyn Inbound>) {
        let mut wait = RETRY_FIRST;
        loop {
            let started = Instant::now();
            let why = match self.session(&inbound).await {
                Ok(()) => "the relay closed the connection".to_string(),
                Err(e) => e,
            };
            {
                let mut st = self.status.lock();
                st.connected = false;
                st.since = None;
                st.error = Some(why.clone());
            }
            tracing::warn!("relay {}: {why}", self.server);
            if started.elapsed() >= STEADY {
                wait = RETRY_FIRST;
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(RETRY_MAX);
        }
    }

    async fn session(&self, inbound: &Arc<dyn Inbound>) -> Result<(), String> {
        let addr = tokio::net::lookup_host(&self.server)
            .await
            .map_err(|e| format!("couldn't find {}: {e}", self.server))?
            .next()
            .ok_or_else(|| format!("{} has no address", self.server))?;
        let local: std::net::SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().unwrap_or_else(|_| unreachable!())
        } else {
            "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!())
        };
        let mut endpoint = quinn::Endpoint::client(local).map_err(|e| e.to_string())?;
        endpoint.set_default_client_config(tls::box_config(&self.identity, self.relay_key)?);
        let conn = endpoint
            .connect(addr, "relay")
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| format!("couldn't connect: {e}"))?;

        let (mut control, recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        proto::send(
            &mut control,
            &Control::Hello {
                protocol: PROTOCOL,
                software: self.software.clone(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut recv = BufReader::new(recv);
        match tokio::time::timeout(WELCOME, proto::recv(&mut recv)).await {
            Ok(Ok(Some(Control::Welcome { name, names, .. }))) => {
                tracing::info!("relay {}: connected as {name}", self.server);
                *self.status.lock() = Status {
                    connected: true,
                    name: Some(name),
                    names,
                    error: None,
                    since: Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                    ),
                };
            }
            Ok(Ok(Some(Control::Refused { reason }))) => return Err(format!("refused: {reason}")),
            Ok(Ok(_)) => return Err("the relay didn't say welcome".into()),
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("the relay didn't answer".into()),
        }

        // The control stream stays open (`control` held) for as long as the
        // box is here; every other stream is a device's connection.
        loop {
            let (send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| format!("lost the relay: {e}"))?;
            let inbound = Arc::clone(inbound);
            tokio::spawn(async move {
                let Ok(opening) = Opening::read(&mut recv).await else {
                    return;
                };
                inbound.serve(tokio::io::join(recv, send), opening).await;
            });
            let _ = &control;
        }
    }
}
