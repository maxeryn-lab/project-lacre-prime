//! Compile-time proof of the content-access rules (spec §13).
//! Each file under tests/ui must FAIL to compile, with the error recorded in
//! its .stderr. If one starts compiling, a Profile could reach bytes it did
//! not declare, or something other than the Core could fabricate a
//! `VerifiedFrame`. That levels are sealed is a `compile_fail,E0277` doctest on
//! `AccessLevel` (its error text varies between compiler versions).

#[test]
fn access_rules_are_enforced_by_the_compiler() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/none_cannot_read_bytes.rs");
    t.compile_fail("tests/ui/derived_cannot_read_full.rs");
    t.compile_fail("tests/ui/only_core_builds_verified_frame.rs");
    t.compile_fail("tests/ui/view_has_no_public_frame.rs");
}
