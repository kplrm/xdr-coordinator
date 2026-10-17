# XDR Coordinator

Coordinator manages Linux XDR Agent enrollment, health, upgrades and policy settings. Edit a policy to update supported telemetry settings across its enrolled agents; the fleet shows application status. It provisions event data streams and accepts event batches when direct OpenSearch ingestion is disabled. Protection content ships with agent releases.

Startup installs retention policies and three Discover patterns in Global and each Private tenant on first use: `xdr-agent-logs`, `xdr-agent-security` and `xdr-agent-telemetry` (initial default). Existing patterns and user-selected defaults are preserved. Hover an Agent's status to see reported health issues.

- [Architecture](docs/architecture.md)
- [API and data model](docs/api-data-model.md)
- [Agent HTTP contract](../xdr-agent/docs/api-endpoints.md)

```bash
npm test
npm run build -- --opensearch-dashboards-version 3.9.0
```

Builds use a disposable Dashboards copy and leave the upstream checkout untouched. Set `OSD_ROOT` to select another build checkout.
