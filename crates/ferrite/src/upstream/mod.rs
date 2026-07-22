pub mod doh;
pub mod doq;
pub mod egress;
pub mod hickory_util;
pub mod plain;
pub mod pool;
pub mod stream;
pub mod tunneled;
pub mod zone_router;

pub use egress::{
    EgressConn, EgressConnectError, EgressConnectFuture, EgressConnector, ProxyHandle, no_proxy,
};
pub use pool::UpstreamPool;
pub use zone_router::ZoneRouter;
