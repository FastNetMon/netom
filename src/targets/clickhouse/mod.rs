//! Durable ClickHouse observation history.
mod config;
mod event;
mod spool;
mod target;
mod transport;
pub use target::ClickHouse;
