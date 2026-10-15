# XDR Coordinator

Coordinator manages Linux XDR Agent enrollment, health, upgrades and grouping policies. It provisions event data streams and accepts event batches when direct OpenSearch ingestion is disabled. Policies are grouping labels; protection content ships with agent releases.

- [Architecture](docs/architecture.md)
- [API and data model](docs/api-data-model.md)
- [Agent HTTP contract](../xdr-agent/docs/api-endpoints.md)

```bash
npm test
npm run build -- --opensearch-dashboards-version 3.9.0
```

Builds use a disposable Dashboards copy and leave the upstream checkout untouched. Set `OSD_ROOT` to select another build checkout.
