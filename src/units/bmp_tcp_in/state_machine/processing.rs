use bytes::Bytes;

use crate::payload::Update;

use super::machine::BmpState;

#[derive(Debug)]
pub struct ProcessingResult {
    pub message_type: MessageType,
    pub next_state: BmpState,
}

impl ProcessingResult {
    pub fn new(message_type: MessageType, next_state: BmpState) -> Self {
        Self {
            message_type,
            next_state,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum MessageType {
    InvalidMessage {
        known_peer: Option<bool>, // is the peer known or not?
        msg_bytes: Option<Bytes>, // do we have a copy of the message?
        err: String,
    },

    Other,

    RoutingUpdate {
        update: Update,
        /// Verbatim message bytes for the bmp-out fastpath
        /// (`Update::RouteMonitoringRaw`), forwarded on the gate alongside
        /// `update` when the unit's `forward_raw_updates` config is set.
        /// Only present for Route Monitoring messages that parsed cleanly;
        /// see the emission guards in `machine::route_monitoring`.
        raw: Option<Update>,
    },

    StateTransition,

    Aborted,
}
