//! Why a monitored router's BGP session went down.
//!
//! A router sends a BMP Peer Down Notification (RFC 7854 §4.9) when one of
//! its own BGP sessions goes down. Besides the per-peer header identifying
//! the session, it carries a reason code and, depending on the reason, the
//! BGP NOTIFICATION the router sent or received, or the FSM event that
//! closed the session. This module turns that into a [`PeerDownInfo`] for
//! the ingress register.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use routecore::bgp::message::notification::{CeaseSubcode, Details};
use routecore::bmp::message::PeerDownNotification;

use crate::ingress::register::{PeerDownInfo, PeerDownReason};

/// Offset of the reason code: common header (6) plus per-peer header (42).
const REASON_OFFSET: usize = 48;

/// Offset of the NOTIFICATION data: header (19) plus code and subcode.
const NOTIFICATION_DATA_OFFSET: usize = 21;

/// Decode a Peer Down Notification into a [`PeerDownInfo`].
///
/// `received` is used as the time when the router sent a zero per-peer
/// header timestamp, which some exporters do.
pub(super) fn peer_down_info(
    msg: &PeerDownNotification<Bytes>,
    received: DateTime<Utc>,
) -> PeerDownInfo {
    let pph_time = msg.per_peer_header().timestamp();
    let time = if pph_time.timestamp() > 0 {
        pph_time
    } else {
        received
    };

    // routecore's PeerDownReason has no numeric value and folds RFC 9069's
    // code 6 into Unknown, so read the code itself. The byte is always
    // there: PeerDownNotification::check() parses it.
    let reason_code =
        msg.as_ref().get(REASON_OFFSET).copied().unwrap_or_default();
    let reason = PeerDownReason::from_code(reason_code);

    let mut info = PeerDownInfo {
        time,
        reason,
        reason_code,
        notification_code: None,
        notification_subcode: None,
        shutdown_communication: None,
        fsm_event: None,
        description: String::new(),
    };

    info.description = match reason {
        PeerDownReason::LocalNotification
        | PeerDownReason::RemoteNotification => {
            let side = if reason == PeerDownReason::LocalNotification {
                "local"
            } else {
                "remote"
            };
            match msg.notification() {
                Some(notification)
                    if notification.as_ref().len()
                        >= NOTIFICATION_DATA_OFFSET =>
                {
                    let details = notification.details();
                    let [code, subcode] = details.raw();
                    info.notification_code = Some(code);
                    info.notification_subcode = Some(subcode);

                    // routecore's data() runs to the end of the buffer,
                    // which here is the end of the BMP message; bound it
                    // by the NOTIFICATION's own length.
                    let bytes = notification.as_ref();
                    let end =
                        usize::from(notification.length()).min(bytes.len());
                    let data = bytes
                        .get(NOTIFICATION_DATA_OFFSET..end)
                        .unwrap_or_default();
                    info.shutdown_communication =
                        shutdown_communication(details, data);

                    // Same wording as the NOTIFICATIONs of sessions netom
                    // terminates itself (bgp_tcp_in's last_error).
                    match &info.shutdown_communication {
                        Some(text) => format!(
                            "{side} NOTIFICATION: {details:?} \"{text}\""
                        ),
                        None => format!("{side} NOTIFICATION: {details:?}"),
                    }
                }
                _ => format!("{side} NOTIFICATION (not included)"),
            }
        }
        PeerDownReason::LocalFsm => {
            info.fsm_event = msg.fsm();
            match info.fsm_event {
                Some(event) => format!("local FSM event {event}"),
                None => "local FSM event (not included)".to_string(),
            }
        }
        PeerDownReason::RemoteNoData => {
            "remote closed without NOTIFICATION".to_string()
        }
        PeerDownReason::PeerDeconfigured => "peer de-configured".to_string(),
        PeerDownReason::LocalTlv => "local close with TLV data".to_string(),
        PeerDownReason::Reserved | PeerDownReason::Unknown => {
            format!("reason code {reason_code}")
        }
    };

    info
}

/// The shutdown communication of a Cease Administrative Shutdown or
/// Administrative Reset NOTIFICATION (RFC 8203, length limit raised to 255
/// by RFC 9003): a length byte followed by that many bytes of UTF-8.
///
/// A missing, empty or truncated communication yields `None`; invalid UTF-8
/// is replaced rather than dropped, since this is for display only.
fn shutdown_communication(details: Details, data: &[u8]) -> Option<String> {
    if !matches!(
        details,
        Details::Cease(
            CeaseSubcode::AdministrativeShutdown
                | CeaseSubcode::AdministrativeReset
        )
    ) {
        return None;
    }
    let (&len, rest) = data.split_first()?;
    let text = rest.get(..usize::from(len)).filter(|t| !t.is_empty())?;
    Some(String::from_utf8_lossy(text).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::encode::{
        mk_bgp_notification_msg, mk_peer_down_notification_msg_with,
        mk_per_peer_header,
    };

    fn decode(reason: u8, data: &[u8]) -> PeerDownInfo {
        let pph = mk_per_peer_header("10.0.0.1", 65001);
        let bytes = mk_peer_down_notification_msg_with(&pph, reason, data);
        let msg = PeerDownNotification::from_octets(bytes).unwrap();
        peer_down_info(&msg, DateTime::<Utc>::MIN_UTC)
    }

    fn shutdown_data(text: &[u8]) -> Vec<u8> {
        let mut data = vec![text.len() as u8];
        data.extend_from_slice(text);
        data
    }

    #[test]
    fn remote_notification_with_shutdown_communication() {
        let notification =
            mk_bgp_notification_msg(6, 2, &shutdown_data(b"maintenance"));
        let info = decode(3, &notification);
        assert_eq!(info.reason, PeerDownReason::RemoteNotification);
        assert_eq!(info.reason_code, 3);
        assert_eq!(info.notification_code, Some(6));
        assert_eq!(info.notification_subcode, Some(2));
        assert_eq!(
            info.shutdown_communication.as_deref(),
            Some("maintenance")
        );
        assert_eq!(
            info.description,
            "remote NOTIFICATION: Cease(AdministrativeShutdown) \
             \"maintenance\""
        );
    }

    #[test]
    fn local_max_prefix_notification() {
        let info = decode(1, &mk_bgp_notification_msg(6, 1, &[]));
        assert_eq!(info.reason, PeerDownReason::LocalNotification);
        assert_eq!(info.shutdown_communication, None);
        assert_eq!(
            info.description,
            "local NOTIFICATION: Cease(MaximumPrefixesReached)"
        );
    }

    #[test]
    fn notification_data_is_bounded_by_its_length() {
        // Bytes after the NOTIFICATION (here a stray trailer) must not be
        // read as part of the shutdown communication.
        let mut data =
            mk_bgp_notification_msg(6, 2, &shutdown_data(b"bye")).to_vec();
        data.extend_from_slice(b"trailer");
        let info = decode(3, &data);
        assert_eq!(info.shutdown_communication.as_deref(), Some("bye"));
    }

    #[test]
    fn truncated_or_invalid_shutdown_communication() {
        // Claims 10 bytes, carries 3: not a valid communication.
        let short = mk_bgp_notification_msg(6, 2, &[10, b'a', b'b', b'c']);
        assert_eq!(decode(3, &short).shutdown_communication, None);

        let invalid =
            mk_bgp_notification_msg(6, 4, &shutdown_data(&[b'o', 0xFF]));
        assert_eq!(
            decode(3, &invalid).shutdown_communication.as_deref(),
            Some("o\u{FFFD}")
        );

        // Only Cease shutdown/reset carry a communication.
        let other = mk_bgp_notification_msg(4, 0, &shutdown_data(b"x"));
        let info = decode(1, &other);
        assert_eq!(info.shutdown_communication, None);
        assert_eq!(info.description, "local NOTIFICATION: HoldTimerExpired");
    }

    #[test]
    fn fsm_event_and_reasons_without_data() {
        let info = decode(2, &18u16.to_be_bytes());
        assert_eq!(info.reason, PeerDownReason::LocalFsm);
        assert_eq!(info.fsm_event, Some(18));
        assert_eq!(info.description, "local FSM event 18");

        for (code, reason, description) in [
            (
                4,
                PeerDownReason::RemoteNoData,
                "remote closed without NOTIFICATION",
            ),
            (5, PeerDownReason::PeerDeconfigured, "peer de-configured"),
            (6, PeerDownReason::LocalTlv, "local close with TLV data"),
            (9, PeerDownReason::Unknown, "reason code 9"),
        ] {
            let info = decode(code, &[]);
            assert_eq!(info.reason, reason);
            assert_eq!(info.reason_code, code);
            assert_eq!(info.description, description);
        }
    }

    #[test]
    fn missing_notification_is_reported_as_such() {
        let info = decode(3, &[]);
        assert_eq!(info.notification_code, None);
        assert_eq!(info.description, "remote NOTIFICATION (not included)");
    }

    #[test]
    fn per_peer_header_timestamp_is_used_when_set() {
        let info = decode(4, &[]);
        // mk_per_peer_header stamps the current time, not 0.
        assert!(info.time > DateTime::<Utc>::MIN_UTC);
    }
}
