# Source coverage and access gates (2026-09-24)

Evidentrail must not call a source complete merely because one search succeeds.
Connected queries may return cached records, so they need current authority for
**every** cached record before selection or expansion.

## Datadog

The connector already reads the authenticated user and roles, effective log
restriction queries, and global permissions. It can register storage tiers,
but sync and cached reads remain blocked. Datadog documents a preview
[restricted-dataset inventory API](https://docs.datadoghq.com/api/latest/datasets/get-all-datasets/)
and a [user team-membership API](https://docs.datadoghq.com/api/latest/teams/get-user-memberships/).
Those APIs could cover dataset filter and membership changes. They do **not**
document an inventory of the per-telemetry Strict/Standard mode or
Unrestricted User Groups. Both settings change log visibility independently
of a restricted dataset. The [Data Access Control guide](https://docs.datadoghq.com/account_management/rbac/data_access/)
describes these settings and confirms they also govern API query results.
Hashing only datasets, roles, and teams would therefore be an incomplete
cached-access check.

**Release condition:** obtain a documented, read-only API that returns the
effective Logs Data Access Control mode, unrestricted principals, full
restricted-dataset inventory, and effective user membership, or a provider
authorization decision for every cached native record. Then bind that scope
to a new corpus version, fail closed on any incomplete response or scope
change, and run a live narrowed-access and revocation test before enabling
Datadog sync or cached reads. Old blocked corpora must not be adopted.

## Sentry

The implemented connector covers paginated
[project error events](https://docs.sentry.io/api/events/list-a-projects-error-events/)
with exact event JSON. Sentry's documented [Explore table endpoint](https://docs.sentry.io/api/explore/query-explore-events-in-table-format/)
can query the `logs` dataset but explicitly says it is not for a full export.
Using it as a full-history structured-log connector would silently omit data.

**Release condition:** use a documented complete, paginated structured-log
export API if Sentry publishes one. Until then, connect the original logging
source (for example its CloudWatch log group) for full-history selection and
retain Sentry as an explicitly error-event-only connection. A live Sentry
project conformance run is still required for the existing connector.
