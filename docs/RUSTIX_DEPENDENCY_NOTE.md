# `rustix` dependency note

**Reviewed:** 2026-08-24  
**Decision:** pin `rustix = 1.1.4` with only `std`, `fs`, and `system`  
**Scope:** safe local-file descriptor preflight; no content reads

## Pin and provenance

- The exact crates.io release is
  [`rustix` 1.1.4](https://crates.io/crates/rustix/1.1.4), published
  2026-02-22. Cargo is constrained with `=1.1.4`, not a compatible range.
- The downloaded crate's `.cargo_vcs_info.json` identifies upstream commit
  [`c4caf5caaa7e93828a2e4a4cdba1dd0171e45717`](https://github.com/bytecodealliance/rustix/tree/c4caf5caaa7e93828a2e4a4cdba1dd0171e45717).
  The crates.io archive checksum recorded by Cargo is
  `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190`.
- Upstream is a Bytecode Alliance project and describes the library as safe,
  I/O-safe syscall bindings using owned and borrowed descriptor types in its
  [official README](https://github.com/bytecodealliance/rustix/blob/c4caf5caaa7e93828a2e4a4cdba1dd0171e45717/README.md).

## License

The published manifest declares
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`; the corresponding license
files ship in the crate and are visible in the
[official 1.1.4 source package](https://docs.rs/crate/rustix/1.1.4/source/).
This is compatible with the current dependency policy, subject to the normal
release-time attribution process.

## Capability and feature review

Only `std`, `fs`, and `system` are enabled. The reviewed safe APIs are:

- [`openat`](https://docs.rs/rustix/1.1.4/rustix/fs/fn.openat.html), with
  `O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC`, `O_NONBLOCK`, and read-only flags;
- [`fstat`](https://docs.rs/rustix/1.1.4/rustix/fs/fn.fstat.html) for descriptor
  identity and snapshot facts;
- [`fstatfs`](https://docs.rs/rustix/1.1.4/rustix/fs/fn.fstatfs.html) for the
  filesystem observation; and
- [`uname`](https://docs.rs/rustix/1.1.4/rustix/system/fn.uname.html) for a live
  OS observation.

The product crate uses no raw descriptor conversion and has workspace
`unsafe_code = "forbid"`. This constrains our code, not `rustix` internals; the
pin still requires dependency review on every upgrade.

## Advisory review

At review time, the RustSec
[advisory database](https://github.com/RustSec/advisory-db) at commit
[`cebc72be9ffc5707a5b0c70fc662198a1eb231a4`](https://github.com/RustSec/advisory-db/tree/cebc72be9ffc5707a5b0c70fc662198a1eb231a4)
contained no advisory whose package field was `rustix`. This is a dated database
check, not a claim that the dependency is vulnerability-free. Release CI must
scan the locked graph again and treat a database or provenance failure as a
blocker.

## Known boundary

`rustix` can observe the live OS, architecture-facing build target, filesystem
type, and file metadata. It cannot prove that a certification-profile digest is
an externally governed, tested matrix. Until such a matrix record is frozen and
admitted by product code, public preflight returns a typed certification blocker
rather than accepting a caller assertion.
