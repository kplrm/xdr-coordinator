# Contributing to xdr-coordinator

This repository owns Agent enrollment, fleet lifecycle, policy groups, upgrades, and event intake. Start with the [README](README.md), [architecture](docs/architecture.md), and [API/data model](docs/api-data-model.md). The [Agent HTTP contract](https://github.com/kplrm/xdr-agent/blob/main/docs/api-endpoints.md) is authoritative for Agent-facing requests.

## Development and validation

Use the Node.js version and dependency tooling required by your target OpenSearch Dashboards checkout. Install plugin dependencies with the committed Yarn lockfile where needed. Point `OSD_ROOT` at a bootstrapped checkout matching your deployment:

```bash
export OSD_ROOT=/path/to/bootstrapped/OpenSearch-Dashboards
npm test
npm run build
```

The build targets the version of `OSD_ROOT` by default. An explicit `--opensearch-dashboards-version` must match that checkout. The build uses disposable staging; keep the upstream checkout untouched.

For ingestion or mapping changes, also run `npm run test:ingest:integration` against a disposable OpenSearch deployment. Set `XDR_OPENSEARCH_URL` and, when required, `XDR_OPENSEARCH_USER` and `XDR_OPENSEARCH_PASSWORD`. The integration check creates and deletes unique test indices.

## Engineering expectations

- Preserve enrollment authentication, identity handling, policy validation, health reporting, and upgrade compatibility.
- Coordinate Agent-facing route or field changes with the authoritative HTTP contract and tests in both repositories.
- Keep policy fields within the Agent contract; protection content ships with Agent releases.
- Cover malformed requests, authorization failures, retries, and partial ingest failures when relevant.
- Validate mappings, retention, and startup behavior for both new and existing installations.
- Match existing TypeScript conventions and keep new dependencies justified.

## Issues and pull requests

Use this repository's [issue tracker](https://github.com/kplrm/xdr-coordinator/issues) for general questions, reproducible bugs, and proposals. Discuss substantial changes before implementation.

1. Fork the repository and branch from `main`.
2. Keep the change focused and follow the existing code style.
3. Add regression coverage for changed behavior and update affected documentation.
4. In your PR, explain the problem, resulting behavior, validation performed, and compatibility impact. List any checks you could not run, including the reason.

Use sanitized logs and fixtures; remove secrets and identifying customer data before posting.

## License and attribution

By submitting a contribution, you agree to license your original changes under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0`). You retain copyright in your contributions. Submit only work you have the right to contribute, and preserve existing copyright and third-party license notices.

## Security reports

Report vulnerabilities through this repository's [private vulnerability reporting](https://github.com/kplrm/xdr-coordinator/security/advisories/new) when enabled. Include affected versions, reproduction steps, impact, and sanitized supporting details. Keep vulnerability, bypass, and credential details out of public issues.

If private reporting is unavailable, open an issue asking the maintainer for a private reporting channel without describing the vulnerability.

## Conduct

Be respectful, direct, and technically concrete in issues, reviews, and discussions.
