# Coordinator architecture

Coordinator owns fleet lifecycle and event intake for XDR Security. Agent detection/prevention stays local. Visualizer owns alert inspection and investigations.

Hidden saved objects store agents (`xdr-agent`), enrollment tokens (`xdr-enrollment-token`), and persistent grouping policies (`xdr-agent-policy`). Tokens bind to an enrolled agent. Agent removal revokes its consumed token; token revocation stops Coordinator traffic. Direct OpenSearch credentials have a separate lifecycle. Deleting a fleet record does not uninstall endpoint software.

Agents enroll, heartbeat and poll upgrade commands through `/api/v1/agents/*`. Event batches can use Coordinator or direct OpenSearch delivery, as defined in the [agent contract](../../xdr-agent/docs/api-endpoints.md). Heartbeats record installed-rule digest/version/count, mode, and actual component health. Stale agents become offline after five minutes. Upgrade commands remain pending until the reported version matches the target. Grouping is independent of protection content.

Coordinator provisions `xdr-agent-telemetry`, `xdr-agent-security` and `xdr-agent-logs` data streams before accepting event intake. Bulk creates append events with stable IDs. Coordinator intake authenticates agent identity, checks topic, normalizes ownership and returns errors for bulk failures. Large-volume events are not stored in saved objects.

The three XDR retention policies roll streams over at 10 GB or seven days, then delete backing indices at 90 days from index creation by default. Operator retention changes are preserved. Templates, permissions, searches and Dashboards data views target stream names only. Dashboards calls these views `index-pattern` saved objects even for streams. XDR does not create `homelab-30d` or configure Query Insights.

After provisioning the streams, Coordinator installs three Global-tenant Discover patterns: `xdr-agent-logs`, `xdr-agent-security` and `xdr-agent-telemetry`, using `@timestamp`. Browser startup also initializes the selected tenant, including each user's Private tenant, before Discover mounts. Existing patterns are reused by title; their settings and user-selected defaults are preserved. Telemetry is the initial default. The previously generated combined pattern is removed. Failed view setup is reported and retried on the next visit. Defense queries the telemetry stream directly.

Health is independent of release versions. Detection mode deliberately leaves execution blocking off; this is not degraded health. Coordinator shows reported component failures in the status tooltip. Enrollment downloads and upgrade targets use `xdr-agent/main/VERSION` on GitHub, cached for one minute; the Agent workflow publishes that version independently of plugin releases.

Process and parent-process command lines and arguments use `keyword` mappings with `ignore_above: 8191` to stay below Lucene's 32,766-byte term limit, including Unicode. Longer values remain complete in `_source` for inspection, but cannot be searched or aggregated as keywords. Startup updates both the telemetry template and those mapping parameters on existing hidden telemetry indices. Bulk failures log bounded samples of HTTP status, field name, and exception types without event values.

For a local deployment, rebuild the coordinator ZIP against the stack's Dashboards version, then rebuild and recreate the Dashboards container using the [local stack deployment steps](../../opensearch/README.md#build-xdr-plugin-artifacts). The startup mapping repair lets queued events retry successfully without restarting or re-enrolling the endpoint.

The UI manages agents, policy groups, and enrollment tokens. There are no Defense rollout commands, remote rule editing, or obsolete host-resource dashboards. Agent runtime defaults send health every 30 seconds and batches every 30 seconds. The complete agent endpoint list and regression rules are authoritative in `xdr-agent/docs/api-endpoints.md`.
