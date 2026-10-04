# Coordinator architecture

Coordinator owns fleet lifecycle and event intake for XDR Security. Agent detection/prevention stays local. Visualizer owns alert inspection and investigations.

Hidden saved objects store agents (`xdr-agent`), enrollment tokens (`xdr-enrollment-token`), and persistent grouping policies (`xdr-agent-policy`). Tokens bind to an enrolled agent. Agent removal revokes its consumed token; token revocation stops authenticated agent traffic. Deleting a fleet record does not uninstall endpoint software.

Agents enroll, heartbeat, poll upgrade commands, and send gzip JSON batches to `/api/v1/agents/*`. Heartbeats record installed-rule digest/version/count, mode, and actual component health. Stale agents become offline after five minutes. Upgrade commands remain pending until the reported version matches the target. Grouping is independent of protection content.

Events are indexed into daily `.xdr-agent-telemetry-*`, `.xdr-agent-security-*`, and `.xdr-agent-logs-*` indices with retention templates. Intake authenticates agent identity, checks topic, normalizes the indexed owner, preserves event identity on retry, and returns errors for bulk failures. Large-volume events are not stored in saved objects.

Process and parent-process command lines and arguments use `keyword` mappings with `ignore_above: 8191` to stay below Lucene's 32,766-byte term limit, including Unicode. Longer values remain complete in `_source` for inspection, but cannot be searched or aggregated as keywords. Startup updates both the telemetry template and those mapping parameters on existing hidden telemetry indices. Bulk failures log bounded samples of HTTP status, field name, and exception types without event values.

For a local deployment, rebuild the coordinator ZIP against the stack's Dashboards version, then rebuild and recreate the Dashboards container using the [local stack deployment steps](../../opensearch/README.md#build-xdr-plugin-artifacts). The startup mapping repair lets queued events retry successfully without restarting or re-enrolling the endpoint.

The UI manages agents, policy groups, and enrollment tokens. There are no Defense rollout commands, remote rule editing, or obsolete host-resource dashboards. Agent runtime defaults send health every 30 seconds and batches every 30 seconds. The complete agent endpoint list and regression rules are authoritative in `xdr-agent/docs/api-endpoints.md`.
