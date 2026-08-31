# Security policy

## Reporting a vulnerability

Please use GitHub's **Security → Report a vulnerability** flow for confidential
reports. Do not disclose a suspected vulnerability, credential, private key,
repository snapshot, or sensitive diagnostic artifact in a public issue.

Include the affected commit, component, reproduction conditions, and expected
impact where possible. Reports involving cryptographic authority, nonce reuse,
plaintext publication, exact-expansion authorization, repository rollback, or
content leakage are treated as security-sensitive.

## Supported surface

The default memory product and explicitly documented public interfaces are the
supported surface. Opt-in V3, durable storage, qualification harnesses, and
benchmark-only integrations retain the rollout and certification limitations
documented in the repository.
