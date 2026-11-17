# Security policy

## Report a vulnerability

Email [Caleb Walch](mailto:cawalch@pm.me) privately with suspected security
issues. Include the affected commit or version, Go version, reproduction steps,
and expected and actual behavior. Prefer a small synthetic reproducer; do not
send malware samples, credentials, or confidential files.

Do not disclose exploit details in public issues or pull requests before
coordinating a fix. GitHub private vulnerability reporting is not enabled as of
2026-11-17. There is no guaranteed response time.

## Supported versions and limits

The project is experimental; v0.1.0 is the first tagged release. Fixes target the
latest development revision and are published in subsequent releases. Older
versions have no maintained security branch.
Use a supported Go toolchain with current security patches, including for this
standard-library-only module.

Treat PE files as untrusted input. Bound file sizes and application resource use;
`Open` reads the entire file. Parser limits and tests do not guarantee that every
input is safe. See the [parsing guide](docs/parsing.md) for work and output limits.

Authenticode verification is offline. It does not perform revocation checks,
consult ambient operating-system trust stores, or reproduce Windows trust
policy. Supply explicit roots for certificate-chain checks and inspect each
verification result; successful parsing alone establishes no trust.
