export type AgentStatus = 'healthy' | 'degraded' | 'offline' | 'unseen';
export type XdrAction = 'upgrade';

export interface ManagedAgentConfig {
  internal_networks?: string[];
  process_scan_interval_seconds?: number;
  network_scan_interval_seconds?: number;
  telemetry_ship_interval_seconds?: number;
}

export interface ManagedConfigPolicy {
  schema_version: 1;
  revision: string;
  settings: ManagedAgentConfig;
}

export interface XdrPolicy {
  id: string;
  name: string;
  description: string;
  config?: ManagedAgentConfig;
  configRevision?: string;
}

export interface ProtectionInventory {
  rule_source: string;
  rule_version: string;
  rule_count: number;
  mode: string;
  platform: string;
  rules_sha256: string;
  health?: Record<string, string>;
}

export interface XdrAgent {
  id: string;
  name: string;
  policyId: string;
  status: AgentStatus;
  lastSeen: string;
  tags: string[];
  version: string;
  enrollmentToken?: string;
  pendingUpgradeVersion?: string;
  upgrade?: UpgradeState;
  protection?: ProtectionInventory;
  configRevision?: string;
  configError?: string;
}

export interface UpgradeState {
  id: string;
  version: string;
  attempts: number;
  status: 'queued' | 'upgrading' | 'retrying' | 'failed' | 'complete';
  error: string;
  nextAttemptAt: string;
}

export interface ListAgentsResponse {
  agents: XdrAgent[];
  policies: XdrPolicy[];
  latestVersion?: string;
}

export interface EnrollAgentRequest {
  hostname: string;
  policyId: string;
  tags?: string[];
}

export interface EnrollAgentResponse {
  agent: XdrAgent;
}

export interface GenerateEnrollmentTokenRequest {
  policyId: string;
  tag?: string;
}

export interface GenerateEnrollmentTokenResponse {
  token: string;
  policyId: string;
  createdAt: string;
  tag?: string;
}

export interface EnrollmentTokenStatusResponse {
  token: string;
  policyId: string;
  status: 'pending' | 'consumed';
  createdAt: string;
  tag?: string;
  consumedAt?: string;
  consumedAgentId?: string;
  consumedHostname?: string;
}

export interface UpdateEnrollmentTokenTagRequest {
  tag: string;
}

export interface ControlPlaneEnrollRequest {
  agent_id: string;
  machine_id: string;
  hostname: string;
  architecture: string;
  os_type: string;
  ip_addresses: string[];
  policy_id: string;
  tags: string[];
  agent_version: string;
}

export interface ControlPlaneEnrollResponse {
  enrollment_id: string;
  message: string;
}

export interface ControlPlaneHeartbeatRequest {
  agent_id: string;
  machine_id: string;
  hostname: string;
  policy_id: string;
  tags: string[];
  agent_version: string;
  protection?: ProtectionInventory;
  config_revision?: string;
  config_error?: string;
  upgrade_id?: string;
  upgrade_error?: string;
  upgrade_retryable?: boolean;
  upgrade_retry_at?: number;
}

export interface ControlPlaneHeartbeatResponse {
  message: string;
  pending_commands?: string[];
  upgrade_id?: string;
  managed_config?: ManagedConfigPolicy;
}

export interface RunActionRequest {
  action: XdrAction;
}

export interface RunActionResponse {
  agent: XdrAgent;
  message: string;
}

export interface RemoveAgentResponse {
  removedAgentId: string;
  message: string;
}

export interface XdrEnrollmentToken {
  token: string;
  policyId: string;
  policyName: string;
  status: 'pending' | 'consumed';
  createdAt: string;
  tag?: string;
  consumedAt?: string;
  consumedHostname?: string;
}

export interface ListEnrollmentTokensResponse {
  tokens: XdrEnrollmentToken[];
}

export interface LatestVersionResponse {
  version: string;
}

export interface ListPoliciesResponse {
  policies: XdrPolicy[];
}

export interface UpsertPolicyRequest {
  name: string;
  description: string;
  config?: ManagedAgentConfig;
}

export interface UpsertPolicyResponse {
  policy: XdrPolicy;
}

// ── Telemetry ingestion ────────────────────────────────────────────────────

export interface TelemetryEvent {
  _id: string;
  '@timestamp': string;
  'event.type': string;
  'event.category': string;
  'event.kind': string;
  'event.severity'?: number;
  'event.module': string;
  'agent.id': string;
  'host.hostname': string;
  [field: string]: unknown;
  'threat.tactic.name'?: string;
  'threat.technique.id'?: string;
  'threat.technique.subtechnique.id'?: string;
  tags?: string[];
}

export interface ControlPlaneTelemetryRequest {
  agent_id: string;
  events: TelemetryEvent[];
}

export interface ControlPlaneTelemetryResponse {
  indexed: number;
  telemetry_indexed?: number;
  security_indexed?: number;
  message: string;
}
