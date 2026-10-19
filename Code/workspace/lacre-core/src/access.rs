//! Content access, enforced by types (Prime 7.3.1, axioms A1 and A7).
//!
//! The Core never interprets a payload. What a Profile may do with it is
//! decided here, at compile time: a Profile receives a `ContentView<A>`
//! whose type parameter is its declared access level, and the view only
//! offers the accessors that level allows.
//!
//! * `NoContent`      — header only (session, index, flags, length).
//! * `DerivedContent` — the bytes, named as derived: a proof, a metadata
//!   projection, anything that is by contract not the datum itself.
//! * `FullContent`    — the bytes of the datum.
//!
//! What the types guarantee: a Profile written against `NoContent` cannot
//! reach the bytes through the API it is given. What they do not guarantee:
//! the difference between `Derived` and `Full` is a declaration that an
//! auditor can check by reading which accessor is called (the source scan in
//! `lacre-profiles/tests/touches_payload.rs` does it); and a Profile that
//! holds its own channel to the data (a shared buffer, `unsafe`) is outside
//! what a type system can see.
//!
//! This module is pure data and does not depend on anything outside the
//! Core: the Core defines the levels, it does not interpret them.

use std::marker::PhantomData;

use crate::frame::LacreFrame;
use crate::session::SessionId;

mod sealed {
    pub trait Sealed {}
}

/// The three declared levels of content access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentAccess {
    None,
    Derived,
    Full,
}

impl ContentAccess {
    /// Stable name used on the wire (`GET /v1/profiles`) and in the spec.
    pub const fn name(self) -> &'static str {
        match self {
            ContentAccess::None => "none",
            ContentAccess::Derived => "derived",
            ContentAccess::Full => "full",
        }
    }

    /// `true` for every level that can read bytes. This is what the old
    /// boolean `touches_payload` meant.
    pub const fn reads_bytes(self) -> bool {
        !matches!(self, ContentAccess::None)
    }
}

/// Marker for a level of access. Sealed: new levels are a Core decision.
///
/// Outside this crate no type can implement it (the error code, not the
/// compiler's wording, is what the doctest pins, so it holds across versions):
///
/// ```compile_fail,E0277
/// use lacre_core::access::{AccessLevel, ContentAccess};
/// struct SneakyLevel;
/// impl AccessLevel for SneakyLevel {
///     const LEVEL: ContentAccess = ContentAccess::Full;
/// }
/// ```
pub trait AccessLevel: sealed::Sealed {
    const LEVEL: ContentAccess;
}

/// Header only.
#[derive(Debug, Clone, Copy)]
pub struct NoContent;
/// Bytes that are by contract not the datum itself.
#[derive(Debug, Clone, Copy)]
pub struct DerivedContent;
/// The bytes of the datum.
#[derive(Debug, Clone, Copy)]
pub struct FullContent;

impl sealed::Sealed for NoContent {}
impl sealed::Sealed for DerivedContent {}
impl sealed::Sealed for FullContent {}

impl AccessLevel for NoContent {
    const LEVEL: ContentAccess = ContentAccess::None;
}
impl AccessLevel for DerivedContent {
    const LEVEL: ContentAccess = ContentAccess::Derived;
}
impl AccessLevel for FullContent {
    const LEVEL: ContentAccess = ContentAccess::Full;
}

/// Where the bytes of a view come from. A view built from a frame the Core
/// verified says `CoreVerified`; a view built by an endpoint that evaluates
/// bytes the caller supplied, with no Core verification, says
/// `CallerSupplied`. The type does not hide the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    CoreVerified,
    /// Bytes a Profile rebuilt from frames the Core verified, handed to a
    /// later stage (a rule set) as one payload.
    Reassembled,
    CallerSupplied,
}

/// A view with full content access: what the Profiles that read the datum receive.
pub type FullView<'a> = ContentView<'a, FullContent>;

/// The identity of a frame. Readable at every level; it carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub session_id: SessionId,
    pub index: u64,
    pub total_fragments: Option<u64>,
    pub is_last: bool,
    pub payload_len: usize,
}

/// A frame the Core has verified. Only the Core can build one: the
/// constructor is private to this crate.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedFrame<'a> {
    frame: &'a LacreFrame,
}

impl<'a> VerifiedFrame<'a> {
    pub(crate) fn new(frame: &'a LacreFrame) -> Self {
        VerifiedFrame { frame }
    }

    pub fn header(&self) -> FrameHeader {
        header_of(self.frame)
    }

    /// The view a Profile with access level `A` is allowed to see.
    pub fn view<A: AccessLevel>(&self) -> ContentView<'a, A> {
        ContentView { frame: self.frame, provenance: Provenance::CoreVerified, _level: PhantomData }
    }
}

fn header_of(frame: &LacreFrame) -> FrameHeader {
    FrameHeader {
        session_id: frame.session_id,
        index: frame.index,
        total_fragments: frame.total_fragments,
        is_last: frame.is_last,
        payload_len: frame.payload.len(),
    }
}

/// What a Profile sees of a frame, shaped by its access level.
#[derive(Debug, Clone, Copy)]
pub struct ContentView<'a, A: AccessLevel> {
    frame: &'a LacreFrame,
    provenance: Provenance,
    _level: PhantomData<A>,
}

impl<'a, A: AccessLevel> ContentView<'a, A> {
    /// A view over bytes the caller supplied and the Core did not verify.
    /// The name is deliberate: it is the only way to get a view without
    /// `VerifiedFrame`, and the provenance travels with it.
    pub fn caller_supplied(frame: &'a LacreFrame) -> Self {
        ContentView { frame, provenance: Provenance::CallerSupplied, _level: PhantomData }
    }

    /// A view over a payload that a Profile reassembled from Core-verified
    /// frames. Same trust as the frames it came from, but no longer a frame.
    pub fn reassembled(frame: &'a LacreFrame) -> Self {
        ContentView { frame, provenance: Provenance::Reassembled, _level: PhantomData }
    }

    pub fn header(&self) -> FrameHeader {
        header_of(self.frame)
    }

    pub fn provenance(&self) -> Provenance {
        self.provenance
    }

    pub fn level(&self) -> ContentAccess {
        A::LEVEL
    }
}

impl ContentView<'_, DerivedContent> {
    /// The derived bytes (a proof, a projection). Not the datum.
    pub fn derived_bytes(&self) -> &[u8] {
        &self.frame.payload
    }
}

impl ContentView<'_, FullContent> {
    /// The bytes of the datum.
    pub fn content_bytes(&self) -> &[u8] {
        &self.frame.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> LacreFrame {
        LacreFrame {
            session_id: SessionId([7u8; 16]),
            index: 3,
            total_fragments: Some(5),
            is_last: false,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn levels_have_stable_names_and_the_old_boolean_meaning() {
        assert_eq!(ContentAccess::None.name(), "none");
        assert_eq!(ContentAccess::Derived.name(), "derived");
        assert_eq!(ContentAccess::Full.name(), "full");
        assert!(!ContentAccess::None.reads_bytes());
        assert!(ContentAccess::Derived.reads_bytes());
        assert!(ContentAccess::Full.reads_bytes());
        assert_eq!(<NoContent as AccessLevel>::LEVEL, ContentAccess::None);
        assert_eq!(<DerivedContent as AccessLevel>::LEVEL, ContentAccess::Derived);
        assert_eq!(<FullContent as AccessLevel>::LEVEL, ContentAccess::Full);
    }

    #[test]
    fn header_is_readable_at_every_level_and_carries_no_bytes() {
        let f = frame(b"secret");
        let none = ContentView::<NoContent>::caller_supplied(&f);
        let h = none.header();
        assert_eq!(h.index, 3);
        assert_eq!(h.total_fragments, Some(5));
        assert!(!h.is_last);
        assert_eq!(h.payload_len, 6);
        assert_eq!(h.session_id, SessionId([7u8; 16]));
    }

    #[test]
    fn derived_and_full_views_return_the_bytes() {
        let f = frame(b"abc");
        assert_eq!(ContentView::<DerivedContent>::caller_supplied(&f).derived_bytes(), b"abc");
        assert_eq!(ContentView::<FullContent>::caller_supplied(&f).content_bytes(), b"abc");
    }

    #[test]
    fn provenance_and_level_travel_with_the_view() {
        let f = frame(b"x");
        let v = ContentView::<FullContent>::caller_supplied(&f);
        assert_eq!(v.provenance(), Provenance::CallerSupplied);
        assert_eq!(v.level(), ContentAccess::Full);
        let verified = VerifiedFrame::new(&f);
        assert_eq!(verified.view::<NoContent>().provenance(), Provenance::CoreVerified);
        assert_eq!(verified.view::<DerivedContent>().level(), ContentAccess::Derived);
        assert_eq!(verified.header().payload_len, 1);
    }
}
