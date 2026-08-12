//! Command handlers.
//!
//! Each handler is deliberately split into a `fetch` step and a pure
//! `render(out, body)` step wherever rendering is non-trivial, so the
//! rendering can be tested against captured JSON with no daemon running.

pub mod bgp;
pub mod bmp;
pub mod system;
