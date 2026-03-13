export type AgentStatus = 'healthy' | 'degraded' | 'offline' | 'unseen';
export type XdrAction = 'upgrade';
export type PolicyLogLevel = 'minimal' | 'standard' | 'verbose';

export interface XdrPolicy {
  id: string;
  name: string;
  description: string;
  malwareProtection: boolean;
  fileIntegrityMonitoring: boolean;
  autoUpgrade: boolean;
  osqueryEnabled: boolean;
  logLevel: PolicyLogLevel;
}

export interface XdrAgent {
  id: string;
  name: string;
  policyId: string;
  status: AgentStatus;
  lastSeen: string;
  tags: string[];
  version: string;
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
}

export interface GenerateEnrollmentTokenResponse {
  token: string;
  policyId: string;
  createdAt: string;
}

export interface EnrollmentTokenStatusResponse {
  token: string;
  policyId: string;
  status: 'pending' | 'consumed';
  createdAt: string;
  consumedAt?: string;
  consumedAgentId?: string;
  consumedHostname?: string;
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
}

export interface ControlPlaneHeartbeatResponse {
  message: string;
  pending_commands?: string[];
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
  malwareProtection: boolean;
  fileIntegrityMonitoring: boolean;
  autoUpgrade: boolean;
  osqueryEnabled: boolean;
  logLevel: PolicyLogLevel;
}

export interface UpsertPolicyResponse {
  policy: XdrPolicy;
}

// ── Telemetry ingestion ────────────────────────────────────────────────────

export interface TelemetryEvent {
  id: string;
  '@timestamp': string;
  'event.type': string;
  'event.category': string;
  'event.kind': string;
  'event.severity': number;
  'event.module': string;
  'agent.id': string;
  'host.hostname': string;
  payload?: Record<string, unknown>;
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
  message: string;
}

// ── Telemetry dashboard query responses ────────────────────────────────────

export interface TelemetryHostMetrics {
  cpu: {
    cores: number;
    total_pct: number;
    user_pct: number;
    system_pct: number;
    idle_pct: number;
    iowait_pct: number;
    steal_pct: number;
  };
  memory: {
    total: number;
    used_bytes: number;
    used_pct: number;
    free: number;
    actual_free: number;
    cached: number;
    buffer: number;
    swap_total: number;
    swap_free: number;
    swap_used_bytes: number;
  };
  timestamp: string;
}

export interface TelemetryHostTimelinePoint {
  timestamp: string;
  cpu_total_pct: number;
  cpu_user_pct: number;
  cpu_system_pct: number;
  cpu_iowait_pct: number;
  memory_used_pct: number;
}

export interface TelemetryHostResponse {
  latest: TelemetryHostMetrics | null;
  timeline: TelemetryHostTimelinePoint[];
}

export interface TelemetryProcessEntry {
  // Core identity
  name: string;
  pid: number;
  ppid: number;
  executable: string;
  command_line: string;
  args: string[];
  working_directory: string;
  state: string;
  entity_id: string;
  // CPU (from process.cpu metric events)
  cpu_pct: number;
  // User / group context
  user_id: number;
  user_name: string;
  group_id: number;
  group_name: string;
  // Security
  cap_eff: string;
  exe_sha256: string;
  // Resource metrics
  threads_count: number;
  fd_count: number;
  mem_rss_bytes: number;
  mem_vms_bytes: number;
  io_read_bytes: number;
  io_write_bytes: number;
  // Lineage
  parent_pid: number;
  parent_name: string;
  // Event metadata
  event_type: string;
  timestamp: string;
}

export interface TelemetryProcessResponse {
  processes: TelemetryProcessEntry[];
  total_events: number;
  process_starts: number;
  process_ends: number;
}

export interface TelemetryNetworkConnection {
  direction: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  protocol: string;
  state: string;
  transport: string;
  timestamp: string;
  event_type: string;
}

export interface TelemetryNetworkResponse {
  connections: TelemetryNetworkConnection[];
  summary: {
    total: number;
    inbound: number;
    outbound: number;
  };
  protocols: Record<string, number>;
  states: Record<string, number>;
}
