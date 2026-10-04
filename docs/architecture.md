# Coordinator architecture

Coordinator owns fleet lifecycle and event intake for XDR Security. Agent detection/prevention stays local. Visualizer owns alert inspection and investigations.

Hidden saved objects store agents (`xdr-agent`), enrollment tokens (`xdr-enrollment-token`), and persistent grouping policies (`xdr-agent-policy`). Tokens bind to an enrolled agent. Agent removal revokes its consumed token; token revocation stops authenticated agent traffic. Deleting a fleet record does not uninstall endpoint software.

Agents enroll, heartbeat, poll upgrade commands, and send gzip JSON batches to `/api/v1/agents/*`. Heartbeats record installed-rule digest/version/count, mode, and actual component health. Stale agents become offline after five minutes. Upgrade commands remain pending until the reported version matches the target. Grouping is independent of protection content.

Events are indexed into daily `.xdr-agent-telemetry-*`, `.xdr-agent-security-*`, and `.xdr-agent-logs-*` indices with retention templates. Intake authenticates agent identity, checks topic, normalizes the indexed owner, preserves event identity on retry, and returns errors for bulk failures. Large-volume events are not stored in saved objects.

The UI manages agents, policy groups, and enrollment tokens. There are no Defense rollout commands, remote rule editing, or obsolete host-resource dashboards. Agent runtime defaults send health every 30 seconds and batches every 30 seconds. The complete agent endpoint list and regression rules are authoritative in `xdr-agent/docs/api-endpoints.md`.
