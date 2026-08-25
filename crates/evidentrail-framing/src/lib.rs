//! Deterministic, conservative V1 framing over an already-sealed event ledger.
//!
//! The framer is byte-oriented and lane-local. It never decodes with a lossy
//! codec, never slices an event, and never grants omission or scoring
//! authority. Strong, frozen recognizers can join contiguous events in one
//! `(source member, stream)` lane; everything else remains an exact,
//! raw-addressable singleton.

mod classify;
mod framer;

pub use framer::{
    FRAMING_POLICY_NAME_V1, FRAMING_POLICY_VERSION_V1, MAX_CONTINUATION_GAP_NANOS_V1,
    MAX_RECONSTRUCTED_BLOCK_BYTES_V1, MAX_RECONSTRUCTED_BLOCK_LINES_V1,
    MAX_RECONSTRUCTED_STATE_DEPTH_V1, SourceLaneFramingError, frame_source_lanes_v1,
    source_lane_framing_policy_v1,
};
