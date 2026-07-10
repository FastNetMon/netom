//! FlowSpec rule storage.
//!
//! FlowSpec routes (RFC 8955/8956, SAFI 133) are keyed in a dedicated
//! `StarCastRib` on their destination-prefix component — or the family
//! default route when no usable destination prefix exists (absent component,
//! or an RFC 8956 pattern offset != 0). Several distinct rules can share one
//! destination prefix from one peer, and the store overwrites whole records
//! per `(prefix, mui)`, so the record value is a [`FlowSpecRuleSet`]: an
//! ordered list of rules encoded into one `Meta` byte blob, where each
//! rule's identity is its full raw NLRI bytes.
//!
//! Blob layout (all integers big-endian):
//!
//! ```text
//! blob  := ver:u8 (=1) , entry*
//! entry := flags:u8 , nlri_len:u16 , pa_len:u32 , nlri_bytes , pamap_raw
//! flags := bits 0-1: FlowSpecValidity; bits 2-7 reserved (0)
//! ```
//!
//! `nlri_bytes` is `FlowSpecNlri::raw()` (no length header; max 4095 bytes
//! per RFC 8955 §4.1, so `u16` is safe). `pamap_raw` is the full
//! `RotondaPaMap` backing bytes (rpki byte, pdu-parse-info byte, raw path
//! attribute blob), so a decoded entry needs nothing outside the blob.

use rotonda_store::prefix_record::Meta;
use rotonda_store::rib::config::MemoryOnlyConfig;
use rotonda_store::rib::StarCastRib;
use std::fmt;

use crate::payload::RotondaPaMap;

pub type FlowSpecStore = StarCastRib<FlowSpecRuleSet, MemoryOnlyConfig>;

/// RFC 8955 §6 validation state of a stored FlowSpec rule.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlowSpecValidity {
    /// Not (yet) validated.
    NotValidated = 0,
    /// Passed the RFC 8955 §6 originator/more-specifics checks.
    Valid = 1,
    /// Failed validation — the interesting signal for a monitor; stored,
    /// never rejected.
    Invalid = 2,
    /// Cannot be validated: no destination-prefix component, or an
    /// RFC 8956 pattern offset anchors the prefix mid-address.
    Unvalidatable = 3,
}

impl FlowSpecValidity {
    fn from_flags(flags: u8) -> Self {
        match flags & 0x03 {
            1 => FlowSpecValidity::Valid,
            2 => FlowSpecValidity::Invalid,
            3 => FlowSpecValidity::Unvalidatable,
            _ => FlowSpecValidity::NotValidated,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FlowSpecValidity::NotValidated => "not-validated",
            FlowSpecValidity::Valid => "valid",
            FlowSpecValidity::Invalid => "invalid",
            FlowSpecValidity::Unvalidatable => "unvalidatable",
        }
    }
}

impl fmt::Display for FlowSpecValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One decoded rule out of a [`FlowSpecRuleSet`].
#[derive(Clone, Debug)]
pub struct FlowSpecRule {
    pub validity: FlowSpecValidity,
    /// Raw FlowSpec NLRI bytes (the rule identity).
    pub nlri: Vec<u8>,
    pub pamap: RotondaPaMap,
}

/// One `(store key, peer, rule)` row of a flowspec query, for the HTTP API.
#[derive(Clone, Debug)]
pub struct FlowSpecQueryRow {
    pub key_prefix: inetnum::addr::Prefix,
    pub ingress_id: crate::ingress::IngressId,
    pub rule: FlowSpecRule,
}

const BLOB_VERSION: u8 = 1;
const ENTRY_HEADER: usize = 1 + 2 + 4; // flags + nlri_len + pa_len

/// All FlowSpec rules of one `(dst-prefix, mui)`, as one store `Meta` blob.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowSpecRuleSet {
    raw: Vec<u8>,
}

impl FlowSpecRuleSet {
    /// Iterate the decoded rules. Tolerant: decoding stops silently at the
    /// first malformed entry (a truncated blob yields the entries before
    /// the truncation).
    pub fn iter(&self) -> FlowSpecRuleIter<'_> {
        let body = match self.raw.first() {
            Some(&BLOB_VERSION) => &self.raw[1..],
            _ => &[],
        };
        FlowSpecRuleIter { body, pos: 0 }
    }

    /// Add `nlri` with `pamap`, replacing any existing entry with the same
    /// NLRI. Returns `true` when an entry was replaced.
    pub fn upsert(
        &mut self,
        nlri: &[u8],
        pamap: &RotondaPaMap,
        validity: FlowSpecValidity,
    ) -> bool {
        let replaced = self.remove(nlri);
        if self.raw.is_empty() {
            self.raw.push(BLOB_VERSION);
        }
        let pa = pamap.raw_arc();
        self.raw.push(validity as u8);
        self.raw
            .extend_from_slice(&(nlri.len() as u16).to_be_bytes());
        self.raw
            .extend_from_slice(&(pa.len() as u32).to_be_bytes());
        self.raw.extend_from_slice(nlri);
        self.raw.extend_from_slice(&pa);
        replaced
    }

    /// Remove the entry whose NLRI equals `nlri`. Returns `true` when an
    /// entry was removed.
    pub fn remove(&mut self, nlri: &[u8]) -> bool {
        if self.raw.first() != Some(&BLOB_VERSION) {
            return false;
        }
        let mut pos = 0usize;
        let body_start = 1;
        let body = &self.raw[body_start..];
        while body.len() - pos >= ENTRY_HEADER {
            let nlri_len = u16::from_be_bytes([body[pos + 1], body[pos + 2]])
                as usize;
            let pa_len = u32::from_be_bytes([
                body[pos + 3],
                body[pos + 4],
                body[pos + 5],
                body[pos + 6],
            ]) as usize;
            let entry_len = ENTRY_HEADER + nlri_len + pa_len;
            if body.len() - pos < entry_len {
                break; // malformed tail
            }
            let nlri_start = pos + ENTRY_HEADER;
            if &body[nlri_start..nlri_start + nlri_len] == nlri {
                let abs = body_start + pos;
                self.raw.drain(abs..abs + entry_len);
                if self.raw.len() == 1 {
                    self.raw.clear();
                }
                return true;
            }
            pos += entry_len;
        }
        false
    }

    pub fn rule_count(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.len() <= 1
    }

    /// Approximate heap size of the encoded blob, for memstat.
    pub fn byte_size(&self) -> usize {
        self.raw.len()
    }
}

pub struct FlowSpecRuleIter<'a> {
    body: &'a [u8],
    pos: usize,
}

impl Iterator for FlowSpecRuleIter<'_> {
    type Item = FlowSpecRule;

    fn next(&mut self) -> Option<FlowSpecRule> {
        let body = self.body;
        let pos = self.pos;
        if body.len().saturating_sub(pos) < ENTRY_HEADER {
            return None;
        }
        let flags = body[pos];
        let nlri_len =
            u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
        let pa_len = u32::from_be_bytes([
            body[pos + 3],
            body[pos + 4],
            body[pos + 5],
            body[pos + 6],
        ]) as usize;
        let entry_len = ENTRY_HEADER + nlri_len + pa_len;
        if body.len() - pos < entry_len {
            return None; // malformed tail: stop
        }
        let nlri_start = pos + ENTRY_HEADER;
        let pa_start = nlri_start + nlri_len;
        let rule = FlowSpecRule {
            validity: FlowSpecValidity::from_flags(flags),
            nlri: body[nlri_start..pa_start].to_vec(),
            pamap: RotondaPaMap::from_raw(
                body[pa_start..pa_start + pa_len].to_vec(),
            ),
        };
        self.pos = pos + entry_len;
        Some(rule)
    }
}

impl AsRef<[u8]> for FlowSpecRuleSet {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl From<Vec<u8>> for FlowSpecRuleSet {
    fn from(value: Vec<u8>) -> Self {
        Self { raw: value }
    }
}

impl fmt::Display for FlowSpecRuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlowSpecRuleSet({} rules)", self.rule_count())
    }
}

impl Meta for FlowSpecRuleSet {
    type Orderable<'a> = ();
    type TBI = ();

    fn as_orderable(&self, _tbi: Self::TBI) -> Self::Orderable<'_> {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pamap(fill: u8) -> RotondaPaMap {
        // rpki byte, ppi byte, then a fake attribute blob
        RotondaPaMap::from_raw(vec![0, 0, fill, fill, fill])
    }

    #[test]
    fn upsert_iter_remove_round_trip() {
        let mut rs = FlowSpecRuleSet::default();
        assert!(rs.is_empty());
        assert_eq!(rs.rule_count(), 0);

        let nlri_a = [0x01u8, 0x18, 10, 0, 1, 0x03, 0x81, 0x11];
        let nlri_b = [0x01u8, 0x18, 10, 0, 1, 0x05, 0x81, 0x35];

        assert!(!rs.upsert(&nlri_a, &pamap(0xaa), FlowSpecValidity::Valid));
        assert!(!rs.upsert(&nlri_b, &pamap(0xbb), FlowSpecValidity::Invalid));
        assert_eq!(rs.rule_count(), 2);

        let rules: Vec<_> = rs.iter().collect();
        assert_eq!(rules[0].nlri, nlri_a);
        assert_eq!(rules[0].validity, FlowSpecValidity::Valid);
        assert_eq!(rules[1].nlri, nlri_b);
        assert_eq!(rules[1].validity, FlowSpecValidity::Invalid);
        assert_eq!(rules[0].pamap.raw_arc()[2], 0xaa);

        // replace-by-NLRI
        assert!(rs.upsert(&nlri_a, &pamap(0xcc), FlowSpecValidity::Valid));
        assert_eq!(rs.rule_count(), 2);
        let rules: Vec<_> = rs.iter().collect();
        // replaced entry re-appends at the tail
        assert_eq!(rules[1].nlri, nlri_a);
        assert_eq!(rules[1].pamap.raw_arc()[2], 0xcc);

        assert!(rs.remove(&nlri_b));
        assert!(!rs.remove(&nlri_b));
        assert_eq!(rs.rule_count(), 1);
        assert!(rs.remove(&nlri_a));
        assert!(rs.is_empty());
        assert_eq!(rs.as_ref().len(), 0);
    }

    #[test]
    fn store_meta_round_trip() {
        let mut rs = FlowSpecRuleSet::default();
        let nlri = [0x03u8, 0x81, 0x11];
        rs.upsert(&nlri, &pamap(0x42), FlowSpecValidity::Unvalidatable);
        // Simulate the store's AsRef<[u8]> -> From<Vec<u8>> round trip.
        let restored = FlowSpecRuleSet::from(rs.as_ref().to_vec());
        assert_eq!(restored, rs);
        let rules: Vec<_> = restored.iter().collect();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].nlri, nlri);
        assert_eq!(rules[0].validity, FlowSpecValidity::Unvalidatable);
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        // wrong version byte
        let rs = FlowSpecRuleSet::from(vec![9, 1, 2, 3]);
        assert_eq!(rs.rule_count(), 0);
        // truncated entry header
        let rs = FlowSpecRuleSet::from(vec![1, 0, 0]);
        assert_eq!(rs.rule_count(), 0);
        // entry longer than blob
        let rs = FlowSpecRuleSet::from(vec![1, 0, 0, 5, 0, 0, 0, 5, 1, 2]);
        assert_eq!(rs.rule_count(), 0);
        // valid entry followed by garbage tail
        let mut rs = FlowSpecRuleSet::default();
        rs.upsert(&[0x03, 0x81, 0x11], &pamap(1), FlowSpecValidity::Valid);
        let mut bytes = rs.as_ref().to_vec();
        bytes.extend_from_slice(&[0xff, 0xff]);
        let rs = FlowSpecRuleSet::from(bytes);
        assert_eq!(rs.rule_count(), 1);
        // remove on hostile bytes
        let mut rs = FlowSpecRuleSet::from(vec![9, 1, 2, 3]);
        assert!(!rs.remove(&[1, 2]));
    }
}
