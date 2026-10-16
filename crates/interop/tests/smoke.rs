//! Placeholder suite: the differential tests arrive with `spark-crypto` in
//! stage S1. This target keeps the project building and the CI job green.

#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

#[test]
fn interop_project_is_wired() {}
