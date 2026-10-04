# Coordinator API and data model

The authoritative agent-facing endpoint list is [the agent HTTP contract](../../xdr-agent/docs/api-endpoints.md); do not duplicate it here.

Operator routes use the normal Dashboards session:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/xdr_manager/agents` | List fleet and groups |
| DELETE | `/api/xdr_manager/agents/{id}` | Remove record and revoke its token |
| POST | `/api/xdr_manager/agents/{id}/action` | Queue an agent upgrade |
| GET, POST | `/api/xdr_manager/policies` | List/create grouping labels |
| PUT, DELETE | `/api/xdr_manager/policies/{id}` | Rename/delete a grouping label |
| GET, POST | `/api/xdr_manager/enrollment_tokens` | List/issue enrollment tokens |
| GET | `/api/xdr_manager/enrollment_tokens/{token}/status` | Check consumption |
| PUT | `/api/xdr_manager/enrollment_tokens/{token}/tag` | Set descriptive tag |
| DELETE | `/api/xdr_manager/enrollment_tokens/{token}` | Revoke token |
| GET | `/api/xdr_manager/protections` | Read last reported installed protections |
| GET | `/api/xdr_manager/version/latest` | Discover published agent version |

Policies contain `id`, `name`, and `description` and persist as `xdr-agent-policy`. The built-in `default-endpoint` group cannot be deleted. Groups referenced by agents or tokens cannot be deleted.

Agent records contain hostname, group, tags, version, last heartbeat, health, and optional pending upgrade version. Enrollment credentials stay internal to the stored record. Protection inventory has the shape specified by [the Agent heartbeat contract](../../xdr-agent/docs/api-endpoints.md).

Run `npm test` for real-schema handler tests, authentication/revocation tests, ingestion failure checks, and comparison against the agent route document. Deployment integration still requires a running Dashboards/OpenSearch stack.
