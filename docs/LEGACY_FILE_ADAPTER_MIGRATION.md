# Legacy file-adapter migration

The path-based `evidentrail-ingest::ApprovedRoot`, `SnapshotLimits`, and
`FileSnapshotAdapter` prototype has been removed from the compiled workspace.
It was never a release API and must not be restored or wrapped.

Local-file production work now belongs exclusively to `evidentrail-local-file`:
strict verified plan and binding documents, live registry authorization,
descriptor-relative zero-read preflight, retained-handle streaming, and a
checked `FetchCompletion`. Public execution remains fail-closed until the
external macOS/APFS certification profile is governed and admitted.

`evidentrail-ingest::InMemoryReplayAdapter` remains the deterministic synthetic-fixture
path for tests and benchmarks. It does not prove live local-file acquisition.
