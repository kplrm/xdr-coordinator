import { schema } from '@osd/config-schema';
import { randomBytes } from 'crypto';
import * as https from 'https';
import { IRouter, ISavedObjectsRepository, Logger } from '../../../OpenSearch-Dashboards/src/core/server';
import {
  AgentStatus,
  ControlPlaneHeartbeatRequest,
  ControlPlaneHeartbeatResponse,
  ControlPlaneEnrollRequest,
  ControlPlaneEnrollResponse,
  ControlPlaneTelemetryRequest,
  ControlPlaneTelemetryResponse,
  EnrollmentTokenStatusResponse,
  GenerateEnrollmentTokenResponse,
  LatestVersionResponse,
  ListAgentsResponse,
  ListEnrollmentTokensResponse,
  RemoveAgentResponse,
  RunActionResponse,
  UpsertPolicyRequest,
  UpsertPolicyResponse,
  XdrAgent,
  XdrPolicy,
  XDR_AGENT_SAVED_OBJECT_TYPE,
  XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
} from '../../common';
import { defineTelemetryRoutes } from './telemetry';

const policies: XdrPolicy[] = [
  {
    id: 'default-endpoint',
    name: 'Default Endpoint Policy',
    description: 'Baseline telemetry and malware prevention.',
    malwareProtection: true,
    fileIntegrityMonitoring: true,
    autoUpgrade: false,
    osqueryEnabled: false,
    logLevel: 'standard',
  },
];

type XdrAgentAttributes = Omit<XdrAgent, 'id'>;

function toXdrAgent(so: { id: string; attributes: XdrAgentAttributes }): XdrAgent {
  return {
    id: so.id,
    name: so.attributes.name,
    policyId: so.attributes.policyId,
    status: so.attributes.status,
    lastSeen: so.attributes.lastSeen,
    tags: so.attributes.tags,
    version: so.attributes.version,
  };
}

type EnrollmentTokenAttributes = {
  token: string;
  policyId: string;
  createdAt: string;
  consumedAt?: string;
  consumedAgentId?: string;
  consumedHostname?: string;
};

// ── In-memory control-plane state ─────────────────────────────────────────
// Agents removed via the UI can no longer send heartbeats or telemetry.
const removedAgentIds = new Set<string>();

// Agents that have a pending upgrade command (cleared once the agent reports
// the expected version).
const pendingUpgradeAgentIds = new Set<string>();

// GitHub latest-release cache (refreshed at most once per minute).
interface VersionCache {
  version: string;
  fetchedAt: number;
}
let latestVersionCache: VersionCache | null = null;
const VERSION_CACHE_TTL_MS = 60_000;

function fetchLatestVersionFromGitHub(): Promise<string> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: '/repos/kplrm/xdr-agent/releases/latest',
      method: 'GET',
      headers: { 'User-Agent': 'xdr-coordinator' },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const tagName: string = parsed.tag_name ?? '';
          // Strip leading 'v' if present
          const version = tagName.startsWith('v') ? tagName.slice(1) : tagName;
          if (!version) {
            reject(new Error(`Could not parse tag_name from GitHub response`));
          } else {
            resolve(version);
          }
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function getCachedLatestVersion(): Promise<string> {
  const now = Date.now();
  if (latestVersionCache && now - latestVersionCache.fetchedAt < VERSION_CACHE_TTL_MS) {
    return latestVersionCache.version;
  }
  const version = await fetchLatestVersionFromGitHub();
  latestVersionCache = { version, fetchedAt: now };
  return version;
}

const STALE_AGENT_THRESHOLD_MS = 5 * 60 * 1000;

const isUnknownUnseenPlaceholder = (agent: XdrAgent): boolean => {
  return agent.status === 'unseen' && (agent.name === 'unknown' || agent.name === 'localhost');
};

const deriveAgentStatus = (agent: XdrAgent, nowMs: number): AgentStatus => {
  if (agent.status === 'unseen') {
    return 'unseen';
  }

  const lastSeenMs = Date.parse(agent.lastSeen);
  if (Number.isFinite(lastSeenMs) && nowMs - lastSeenMs >= STALE_AGENT_THRESHOLD_MS) {
    return 'offline';
  }

  return agent.status;
};

const toPolicyId = (value: string): string => {
  const normalized = value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

  return normalized || `policy-${Date.now()}`;
};

const issueEnrollmentToken = (): string => {
  return `xdr_enroll_${randomBytes(24).toString('base64url')}`;
};

const readBearerToken = (authorization: string | string[] | undefined): string | null => {
  if (!authorization) {
    return null;
  }

  const value = Array.isArray(authorization) ? authorization[0] : authorization;
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  if (!match) {
    return null;
  }

  return match[1].trim() || null;
};

const policyRequestSchema = schema.object({
  name: schema.string({ minLength: 1 }),
  description: schema.string({ minLength: 1 }),
  malwareProtection: schema.boolean(),
  fileIntegrityMonitoring: schema.boolean(),
  autoUpgrade: schema.boolean(),
  osqueryEnabled: schema.boolean(),
  logLevel: schema.oneOf([
    schema.literal('minimal'),
    schema.literal('standard'),
    schema.literal('verbose'),
  ]),
});

export function defineRoutes(
  router: IRouter,
  logger: Logger,
  agentRepoPromise: Promise<ISavedObjectsRepository>
) {
  router.post(
    {
      path: '/api/xdr_manager/enrollment_tokens',
      validate: {
        body: schema.object({
          policyId: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_context, request, response) => {
      const selectedPolicy = policies.find((policy) => policy.id === request.body.policyId);

      if (!selectedPolicy) {
        return response.badRequest({
          body: `Unknown policy [${request.body.policyId}]`,
        });
      }

      const token = issueEnrollmentToken();
      const createdAt = new Date().toISOString();
      const repo = await agentRepoPromise;
      await repo.create<EnrollmentTokenAttributes>(
        XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        { token, policyId: request.body.policyId, createdAt }
      );

      const body: GenerateEnrollmentTokenResponse = {
        token,
        policyId: request.body.policyId,
        createdAt,
      };

      return response.ok({ body });
    }
  );

  router.get(
    {
      path: '/api/xdr_manager/enrollment_tokens/{token}/status',
      validate: {
        params: schema.object({
          token: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_context, request, response) => {
      const repo = await agentRepoPromise;
      const result = await repo.find<EnrollmentTokenAttributes>({
        type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        search: request.params.token,
        searchFields: ['token'],
        perPage: 1,
      });
      const tokenSO = result.saved_objects[0] ?? null;
      if (!tokenSO) {
        return response.notFound({
          body: `Enrollment token [${request.params.token}] not found`,
        });
      }

      const t = tokenSO.attributes;
      const body: EnrollmentTokenStatusResponse = {
        token: t.token,
        policyId: t.policyId,
        status: t.consumedAt ? 'consumed' : 'pending',
        createdAt: t.createdAt,
        consumedAt: t.consumedAt,
        consumedAgentId: t.consumedAgentId,
        consumedHostname: t.consumedHostname,
      };

      return response.ok({ body });
    }
  );

  // ── DELETE /api/xdr_manager/enrollment_tokens/{token} ──────────────────
  // Revokes (deletes) an enrollment token so it can no longer be used.

  router.delete(
    {
      path: '/api/xdr_manager/enrollment_tokens/{token}',
      validate: {
        params: schema.object({
          token: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_context, request, response) => {
      const repo = await agentRepoPromise;
      const result = await repo.find<EnrollmentTokenAttributes>({
        type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        search: request.params.token,
        searchFields: ['token'],
        perPage: 1,
      });
      const tokenSO = result.saved_objects[0] ?? null;
      if (!tokenSO) {
        return response.notFound({
          body: `Enrollment token not found`,
        });
      }

      await repo.delete(XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, tokenSO.id);

      return response.ok({
        body: { message: 'Enrollment token revoked' },
      });
    }
  );

  router.post(
    {
      path: '/api/v1/agents/enroll',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          machine_id: schema.string({ minLength: 1 }),
          hostname: schema.string({ minLength: 1 }),
          architecture: schema.string({ minLength: 1 }),
          os_type: schema.string({ minLength: 1 }),
          ip_addresses: schema.arrayOf(schema.string()),
          policy_id: schema.string({ minLength: 1 }),
          tags: schema.arrayOf(schema.string()),
          agent_version: schema.string({ minLength: 1 }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (_context, request, response) => {
      const repo = await agentRepoPromise;
      const bearerToken = readBearerToken(request.headers.authorization);
      if (!bearerToken) {
        return response.unauthorized({
          body: {
            message: 'Missing or invalid Authorization header',
          },
        });
      }

      // Look up the token record from saved objects
      const tokenSearchResult = await repo.find<EnrollmentTokenAttributes>({
        type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        search: bearerToken,
        searchFields: ['token'],
        perPage: 1,
      });
      const tokenSO = tokenSearchResult.saved_objects[0] ?? null;
      if (!tokenSO) {
        return response.unauthorized({
          body: {
            message: 'Enrollment token is invalid',
          },
        });
      }

      if (tokenSO.attributes.consumedAt) {
        return response.unauthorized({
          body: {
            message: 'Enrollment token already used',
          },
        });
      }

      const payload = request.body as ControlPlaneEnrollRequest;
      if (tokenSO.attributes.policyId !== payload.policy_id) {
        return response.badRequest({
          body: {
            message: `Enrollment token policy mismatch: token=${tokenSO.attributes.policyId} request=${payload.policy_id}`,
          },
        });
      }

      const selectedPolicy = policies.find((policy) => policy.id === payload.policy_id);
      if (!selectedPolicy) {
        return response.badRequest({
          body: {
            message: `Unknown policy [${payload.policy_id}]`,
          },
        });
      }

      const now = new Date().toISOString();
      const agentAttrs: XdrAgentAttributes = {
        name: payload.hostname,
        policyId: payload.policy_id,
        status: 'healthy',
        lastSeen: now,
        tags: payload.tags,
        version: payload.agent_version,
      };

      let existingAgent: { id: string; attributes: XdrAgentAttributes } | null = null;
      try {
        existingAgent = await repo.get<XdrAgentAttributes>(
          XDR_AGENT_SAVED_OBJECT_TYPE,
          payload.agent_id
        );
      } catch (err: any) {
        if (err?.output?.statusCode !== 404) throw err;
      }

      if (existingAgent) {
        await repo.update(XDR_AGENT_SAVED_OBJECT_TYPE, payload.agent_id, agentAttrs);
      } else {
        // Check for an "unseen" placeholder agent for this policy
        const placeholders = await repo.find<XdrAgentAttributes>({
          type: XDR_AGENT_SAVED_OBJECT_TYPE,
          perPage: 10000,
        });
        const placeholder = placeholders.saved_objects.find(
          (so) =>
            isUnknownUnseenPlaceholder(toXdrAgent(so)) &&
            so.attributes.policyId === payload.policy_id
        );

        if (placeholder) {
          // Replace the placeholder with the real agent
          await repo.delete(XDR_AGENT_SAVED_OBJECT_TYPE, placeholder.id);
        }

        await repo.create<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, agentAttrs, {
          id: payload.agent_id,
        });
      }

      const body: ControlPlaneEnrollResponse = {
        enrollment_id: payload.agent_id,
        message: `enrolled agent ${payload.hostname}`,
      };

      // If this agent was previously removed via the UI, clear it from the
      // blocklist so that its heartbeats and telemetry are accepted again.
      removedAgentIds.delete(payload.agent_id);

      // Mark token as consumed in saved objects
      await repo.update<EnrollmentTokenAttributes>(XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, tokenSO.id, {
        consumedAt: now,
        consumedAgentId: payload.agent_id,
        consumedHostname: payload.hostname,
      });

      return response.ok({ body });
    }
  );

  router.post(
    {
      path: '/api/v1/agents/heartbeat',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          machine_id: schema.string({ minLength: 1 }),
          hostname: schema.string({ minLength: 1 }),
          policy_id: schema.string({ minLength: 1 }),
          tags: schema.arrayOf(schema.string()),
          agent_version: schema.string({ minLength: 1 }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (_context, request, response) => {
      const payload = request.body as ControlPlaneHeartbeatRequest;

      // Reject heartbeats from agents that were removed via the UI.
      if (removedAgentIds.has(payload.agent_id)) {
        return response.unauthorized({
          body: { message: `Agent [${payload.agent_id}] has been removed` },
        });
      }

      const repo = await agentRepoPromise;

      try {
        await repo.get<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, payload.agent_id);
      } catch (err: any) {
        if (err?.output?.statusCode === 404) {
          return response.notFound({
            body: {
              message: `Agent [${payload.agent_id}] not found`,
            },
          });
        }
        throw err;
      }

      await repo.update(XDR_AGENT_SAVED_OBJECT_TYPE, payload.agent_id, {
        name: payload.hostname,
        policyId: payload.policy_id,
        status: 'healthy' as AgentStatus,
        lastSeen: new Date().toISOString(),
        tags: payload.tags,
        version: payload.agent_version,
      });

      // Build pending commands list.
      const pendingCommands: string[] = [];
      if (pendingUpgradeAgentIds.has(payload.agent_id)) {
        // Fetch current latest version to tell the agent what to install
        let latestVersion: string | undefined;
        try {
          latestVersion = await getCachedLatestVersion();
        } catch {
          // If we can't reach GitHub, skip upgrade command this cycle
        }

        if (latestVersion && payload.agent_version !== latestVersion) {
          pendingCommands.push(`upgrade:${latestVersion}`);
        } else {
          // Agent already on latest version (or we couldn't determine it)
          pendingUpgradeAgentIds.delete(payload.agent_id);
        }
      }

      const body: ControlPlaneHeartbeatResponse = {
        message: `heartbeat accepted for ${payload.hostname}`,
        pending_commands: pendingCommands.length > 0 ? pendingCommands : undefined,
      };

      return response.ok({ body });
    }
  );

  // ── Fast command poll ────────────────────────────────────────────────────
  // Lightweight read-only endpoint polled by the agent every few seconds.
  // Returns any pending commands without updating lastSeen or the saved object,
  // so it is safe to call frequently without inflating heartbeat metrics.
  router.get(
    {
      path: '/api/v1/agents/commands',
      validate: {
        query: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          agent_version: schema.string({ minLength: 1 }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (_context, request, response) => {
      const { agent_id, agent_version } = request.query as {
        agent_id: string;
        agent_version: string;
      };

      if (removedAgentIds.has(agent_id)) {
        return response.unauthorized({
          body: { message: `Agent [${agent_id}] has been removed` },
        });
      }

      const pendingCommands: string[] = [];
      if (pendingUpgradeAgentIds.has(agent_id)) {
        let latestVersion: string | undefined;
        try {
          latestVersion = await getCachedLatestVersion();
        } catch {
          // GitHub unreachable — skip this poll cycle
        }

        if (latestVersion && agent_version !== latestVersion) {
          pendingCommands.push(`upgrade:${latestVersion}`);
        } else {
          // Agent is already on the latest version
          pendingUpgradeAgentIds.delete(agent_id);
        }
      }

      const body: ControlPlaneHeartbeatResponse = {
        message: 'commands polled',
        pending_commands: pendingCommands.length > 0 ? pendingCommands : undefined,
      };

      return response.ok({ body });
    }
  );

  router.get(
    {
      path: '/api/xdr_manager/agents',
      validate: false,
    },
    async (_context, _request, response) => {
      const repo = await agentRepoPromise;
      const result = await repo.find<XdrAgentAttributes>({
        type: XDR_AGENT_SAVED_OBJECT_TYPE,
        perPage: 10000,
        sortField: 'lastSeen',
        sortOrder: 'desc',
      });

      // Fetch latest version from GitHub (non-blocking — use cached value on error)
      let latestVersion: string | undefined;
      try {
        latestVersion = await getCachedLatestVersion();
      } catch {
        // Continue without version info if GitHub is unreachable
      }

      const nowMs = Date.now();
      const body: ListAgentsResponse = {
        agents: result.saved_objects.map((so) => {
          const agent = toXdrAgent(so);
          return {
            ...agent,
            name: agent.status === 'unseen' ? 'unknown' : agent.name,
            status: deriveAgentStatus(agent, nowMs),
          };
        }),
        policies,
        latestVersion,
      };

      return response.ok({ body });
    }
  );

  router.post(
    {
      path: '/api/xdr_manager/agents/enroll',
      validate: {
        body: schema.object({
          hostname: schema.string({ minLength: 1 }),
          policyId: schema.string({ minLength: 1 }),
          tags: schema.maybe(schema.arrayOf(schema.string())),
        }),
      },
    },
    async (_context, request, response) => {
      const selectedPolicy = policies.find((policy) => policy.id === request.body.policyId);

      if (!selectedPolicy) {
        return response.badRequest({
          body: `Unknown policy [${request.body.policyId}]`,
        });
      }

      const repo = await agentRepoPromise;
      const agentId = `agent-${Date.now()}`;
      const attrs: XdrAgentAttributes = {
        name: 'unknown',
        policyId: request.body.policyId,
        status: 'unseen',
        lastSeen: new Date().toISOString(),
        tags: request.body.tags ?? [],
        version: '1.0.0',
      };

      await repo.create<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, attrs, {
        id: agentId,
      });

      const newAgent: XdrAgent = { id: agentId, ...attrs };

      return response.ok({
        body: {
          agent: newAgent,
        },
      });
    }
  );

  router.get(
    {
      path: '/api/xdr_manager/policies',
      validate: false,
    },
    async (_context, _request, response) => {
      return response.ok({
        body: {
          policies,
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr_manager/policies',
      validate: {
        body: policyRequestSchema,
      },
    },
    async (_context, request, response) => {
      const payload = request.body as UpsertPolicyRequest;
      const baseId = toPolicyId(payload.name);
      let id = baseId;
      let count = 1;
      while (policies.some((policy) => policy.id === id)) {
        count += 1;
        id = `${baseId}-${count}`;
      }

      const newPolicy: XdrPolicy = {
        id,
        ...payload,
      };
      policies.unshift(newPolicy);

      const body: UpsertPolicyResponse = {
        policy: newPolicy,
      };

      return response.ok({ body });
    }
  );

  router.put(
    {
      path: '/api/xdr_manager/policies/{id}',
      validate: {
        params: schema.object({
          id: schema.string({ minLength: 1 }),
        }),
        body: policyRequestSchema,
      },
    },
    async (_context, request, response) => {
      const policy = policies.find((item) => item.id === request.params.id);

      if (!policy) {
        return response.notFound({
          body: `Policy [${request.params.id}] not found`,
        });
      }

      const payload = request.body as UpsertPolicyRequest;
      policy.name = payload.name;
      policy.description = payload.description;
      policy.malwareProtection = payload.malwareProtection;
      policy.fileIntegrityMonitoring = payload.fileIntegrityMonitoring;
      policy.autoUpgrade = payload.autoUpgrade;
      policy.osqueryEnabled = payload.osqueryEnabled;
      policy.logLevel = payload.logLevel;

      const body: UpsertPolicyResponse = {
        policy,
      };

      return response.ok({ body });
    }
  );

  router.delete(
    {
      path: '/api/xdr_manager/policies/{id}',
      validate: {
        params: schema.object({
          id: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_context, request, response) => {
      const policyIndex = policies.findIndex((item) => item.id === request.params.id);

      if (policyIndex === -1) {
        return response.notFound({
          body: `Policy [${request.params.id}] not found`,
        });
      }

      const agentRepo = await agentRepoPromise;
      const assignedResult = await agentRepo.find<XdrAgentAttributes>({
        type: XDR_AGENT_SAVED_OBJECT_TYPE,
        perPage: 10000,
      });
      if (
        assignedResult.saved_objects.some(
          (so) => so.attributes.policyId === request.params.id
        )
      ) {
        return response.badRequest({
          body: `Policy [${request.params.id}] is currently assigned to one or more agents.`,
        });
      }

      const [deletedPolicy] = policies.splice(policyIndex, 1);

      return response.ok({
        body: {
          deletedPolicyId: deletedPolicy.id,
        },
      });
    }
  );

  router.post(
    {
      path: '/api/xdr_manager/agents/{id}/action',
      validate: {
        params: schema.object({
          id: schema.string({ minLength: 1 }),
        }),
        body: schema.object({
          action: schema.oneOf([
            schema.literal('upgrade'),
          ]),
        }),
      },
    },
    async (_context, request, response) => {
      const repo = await agentRepoPromise;

      let existing;
      try {
        existing = await repo.get<XdrAgentAttributes>(
          XDR_AGENT_SAVED_OBJECT_TYPE,
          request.params.id
        );
      } catch (err: any) {
        if (err?.output?.statusCode === 404) {
          return response.notFound({
            body: `Agent [${request.params.id}] not found`,
          });
        }
        throw err;
      }

      // Mark the agent as having a pending upgrade. The upgrade:VERSION
      // command will be delivered on the next heartbeat.
      pendingUpgradeAgentIds.add(request.params.id);

      const agent: XdrAgent = toXdrAgent(existing);

      const body: RunActionResponse = {
        agent,
        message: `Upgrade queued for ${agent.name}. The agent will upgrade on its next heartbeat.`,
      };

      return response.ok({ body });
    }
  );

  // ── Topic ingestion (telemetry, security, logs) ──────────────────────────
  // Agent-facing endpoints. Each topic uses its own HTTP path and index.

  const XDR_TELEMETRY_INDEX_PREFIX = '.xdr-agent-telemetry';
  const XDR_SECURITY_INDEX_PREFIX = '.xdr-agent-security';
  const XDR_LOGS_INDEX_PREFIX = '.xdr-agent-logs';
  const SECURITY_MODULE_PREFIXES = ['detection.', 'prevention.', 'response.'];
  const MAX_EVENTS_PER_INGEST_REQUEST = 1000;
  const BULK_INDEX_CHUNK_SIZE = 250;

  const isSecurityEvent = (event: ControlPlaneTelemetryRequest['events'][number]): boolean => {
    const eventModule = event['event.module'] ?? '';
    return (
      event['event.kind'] === 'alert' ||
      event['event.category'] === 'intrusion_detection' ||
      SECURITY_MODULE_PREFIXES.some((prefix) => eventModule.startsWith(prefix))
    );
  };

  const isAgentLogEvent = (event: ControlPlaneTelemetryRequest['events'][number]): boolean => {
    return event['event.type'] === 'agent.log' || event['event.module'] === 'agent.logger';
  };

  const buildDailyIndexName = (prefix: string): string => {
    const today = new Date().toISOString().slice(0, 10);
    return `${prefix}-${today}`;
  };

  const telemetryEventSchema = schema.object({
    id: schema.string(),
    '@timestamp': schema.string(),
    'event.type': schema.string(),
    'event.category': schema.string(),
    'event.kind': schema.string(),
    'event.severity': schema.number(),
    'event.module': schema.string(),
    'agent.id': schema.string(),
    'host.hostname': schema.string(),
    payload: schema.maybe(schema.recordOf(schema.string(), schema.any())),
    'threat.tactic.name': schema.maybe(schema.string()),
    'threat.technique.id': schema.maybe(schema.string()),
    'threat.technique.subtechnique.id': schema.maybe(schema.string()),
    tags: schema.maybe(schema.arrayOf(schema.string())),
  });

  const indexBatch = async (
    context: any,
    payload: ControlPlaneTelemetryRequest,
    events: ControlPlaneTelemetryRequest['events'],
    indexName: string,
    kind: 'telemetry' | 'security' | 'logs'
  ) => {
    if (events.length === 0) {
      return;
    }

    const opensearchClient = context.core.opensearch.client.asInternalUser;
    const indexExists = await opensearchClient.indices.exists({ index: indexName });
    if (!indexExists.body) {
      await opensearchClient.indices.create({ index: indexName });
      logger.info(`Created ${kind} index [${indexName}]`);
    }

    // Send bulk requests in bounded chunks to avoid creating one very large payload.
    for (let start = 0; start < events.length; start += BULK_INDEX_CHUNK_SIZE) {
      const end = Math.min(start + BULK_INDEX_CHUNK_SIZE, events.length);
      const bulkBody: Array<Record<string, unknown>> = [];

      for (let i = start; i < end; i++) {
        const evt = events[i];
        bulkBody.push({ index: { _index: indexName, _id: evt.id } });
        bulkBody.push({
          ...evt,
          'agent.id': payload.agent_id,
          indexed_at: new Date().toISOString(),
        });
      }

      const bulkResponse = await opensearchClient.bulk({ body: bulkBody });
      if (bulkResponse.body.errors) {
        const failedItems = bulkResponse.body.items.filter((item: any) => {
          const action = item.index || item.create || item.update || item.delete;
          return action?.error;
        });
        logger.warn(
          `Bulk index to [${indexName}]: ${failedItems.length}/${end - start} ${kind} events failed`
        );
      }
    }
  };

  router.post(
    {
      path: '/api/v1/agents/telemetry',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          events: schema.arrayOf(telemetryEventSchema, { minSize: 1, maxSize: MAX_EVENTS_PER_INGEST_REQUEST }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (context, request, response) => {
      const payload = request.body as ControlPlaneTelemetryRequest;

      // Reject telemetry from agents that were removed via the UI.
      if (removedAgentIds.has(payload.agent_id)) {
        return response.unauthorized({
          body: { message: `Agent [${payload.agent_id}] has been removed` },
        });
      }

      const securityCount = payload.events.filter((evt) => isSecurityEvent(evt)).length;
      if (securityCount > 0) {
        return response.badRequest({
          body: {
            message: `${securityCount} security-classified events received on telemetry endpoint; send them to /api/v1/agents/security`,
          },
        });
      }

      try {
        const telemetryIndexName = buildDailyIndexName(XDR_TELEMETRY_INDEX_PREFIX);
        await indexBatch(context, payload, payload.events, telemetryIndexName, 'telemetry');

        const indexed = payload.events.length;
        const message = `${indexed} events indexed into ${telemetryIndexName}`;
        logger.debug(`Indexed ${indexed} telemetry events from agent [${payload.agent_id}]`);

        const body: ControlPlaneTelemetryResponse = {
          indexed,
          telemetry_indexed: indexed,
          message,
        };

        return response.ok({ body });
      } catch (err) {
        logger.error(`Failed to index telemetry events: ${err}`);
        return response.customError({
          statusCode: 502,
          body: {
            message: `Failed to index telemetry events: ${err}`,
          },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/v1/agents/security',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          events: schema.arrayOf(telemetryEventSchema, { minSize: 1, maxSize: MAX_EVENTS_PER_INGEST_REQUEST }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (context, request, response) => {
      const payload = request.body as ControlPlaneTelemetryRequest;

      if (removedAgentIds.has(payload.agent_id)) {
        return response.unauthorized({
          body: { message: `Agent [${payload.agent_id}] has been removed` },
        });
      }

      const nonSecurityCount = payload.events.filter((evt) => !isSecurityEvent(evt)).length;
      if (nonSecurityCount > 0) {
        return response.badRequest({
          body: {
            message: `${nonSecurityCount} non-security events received on security endpoint; send them to /api/v1/agents/telemetry`,
          },
        });
      }

      try {
        const securityIndexName = buildDailyIndexName(XDR_SECURITY_INDEX_PREFIX);
        await indexBatch(context, payload, payload.events, securityIndexName, 'security');

        const indexed = payload.events.length;
        const body: ControlPlaneTelemetryResponse = {
          indexed,
          security_indexed: indexed,
          message: `${indexed} events indexed into ${securityIndexName}`,
        };

        logger.debug(`Indexed ${indexed} security events from agent [${payload.agent_id}]`);
        return response.ok({ body });
      } catch (err) {
        logger.error(`Failed to index security events: ${err}`);
        return response.customError({
          statusCode: 502,
          body: {
            message: `Failed to index security events: ${err}`,
          },
        });
      }
    }
  );

  router.post(
    {
      path: '/api/v1/agents/logs',
      validate: {
        body: schema.object({
          agent_id: schema.string({ minLength: 1 }),
          events: schema.arrayOf(telemetryEventSchema, { minSize: 1, maxSize: MAX_EVENTS_PER_INGEST_REQUEST }),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (context, request, response) => {
      const payload = request.body as ControlPlaneTelemetryRequest;

      if (removedAgentIds.has(payload.agent_id)) {
        return response.unauthorized({
          body: { message: `Agent [${payload.agent_id}] has been removed` },
        });
      }

      const nonLogCount = payload.events.filter((evt) => !isAgentLogEvent(evt)).length;
      if (nonLogCount > 0) {
        return response.badRequest({
          body: {
            message: `${nonLogCount} non-log events received on logs endpoint; send telemetry to /api/v1/agents/telemetry and security alerts to /api/v1/agents/security`,
          },
        });
      }

      try {
        const logsIndexName = buildDailyIndexName(XDR_LOGS_INDEX_PREFIX);
        await indexBatch(context, payload, payload.events, logsIndexName, 'logs');

        const indexed = payload.events.length;
        const body: ControlPlaneTelemetryResponse = {
          indexed,
          message: `${indexed} events indexed into ${logsIndexName}`,
        };

        logger.debug(`Indexed ${indexed} agent logs from agent [${payload.agent_id}]`);
        return response.ok({ body });
      } catch (err) {
        logger.error(`Failed to index log events: ${err}`);
        return response.customError({
          statusCode: 502,
          body: {
            message: `Failed to index log events: ${err}`,
          },
        });
      }
    }
  );

  // ── DELETE /api/xdr_manager/agents/{id} ────────────────────────────────
  // Removes a known agent: deletes its saved object and adds its ID to the
  // in-memory blocklist so further heartbeats and telemetry are rejected.

  router.delete(
    {
      path: '/api/xdr_manager/agents/{id}',
      validate: {
        params: schema.object({
          id: schema.string({ minLength: 1 }),
        }),
      },
    },
    async (_context, request, response) => {
      const agentId = request.params.id;
      const repo = await agentRepoPromise;

      try {
        await repo.delete(XDR_AGENT_SAVED_OBJECT_TYPE, agentId);
      } catch (err: any) {
        if (err?.output?.statusCode !== 404) {
          throw err;
        }
        // Already gone — still add to blocklist below
      }

      // Add to blocklist so further heartbeats / telemetry are rejected even
      // if another process re-creates the object.
      removedAgentIds.add(agentId);
      pendingUpgradeAgentIds.delete(agentId);

      const body: RemoveAgentResponse = {
        removedAgentId: agentId,
        message: `Agent [${agentId}] removed. Further communications will be rejected.`,
      };

      return response.ok({ body });
    }
  );

  // ── GET /api/xdr_manager/enrollment_tokens ─────────────────────────────
  // Returns all enrollment tokens with their status and associated policy.

  router.get(
    {
      path: '/api/xdr_manager/enrollment_tokens',
      validate: false,
    },
    async (_context, _request, response) => {
      const policyNameById = Object.fromEntries(
        policies.map((policy) => [policy.id, policy.name])
      );

      const repo = await agentRepoPromise;
      const result = await repo.find<EnrollmentTokenAttributes>({
        type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        perPage: 10000,
        sortField: 'createdAt',
        sortOrder: 'desc',
      });

      const body: ListEnrollmentTokensResponse = {
        tokens: result.saved_objects.map((so) => {
          const t = so.attributes;
          return {
            token: t.token,
            policyId: t.policyId,
            policyName: policyNameById[t.policyId] ?? t.policyId,
            status: (t.consumedAt ? 'consumed' : 'pending') as 'consumed' | 'pending',
            createdAt: t.createdAt,
            consumedAt: t.consumedAt,
            consumedHostname: t.consumedHostname,
          };
        }),
      };

      return response.ok({ body });
    }
  );

  // ── GET /api/xdr_manager/version/latest ────────────────────────────────
  // Returns the latest xdr-agent version from GitHub releases (cached).

  router.get(
    {
      path: '/api/xdr_manager/version/latest',
      validate: false,
    },
    async (_context, _request, response) => {
      try {
        const version = await getCachedLatestVersion();
        const body: LatestVersionResponse = { version };
        return response.ok({ body });
      } catch (err) {
        logger.warn(`Failed to fetch latest version from GitHub: ${err}`);
        return response.customError({
          statusCode: 502,
          body: { message: `Failed to fetch latest version: ${err}` },
        });
      }
    }
  );

  // Register telemetry dashboard query routes (Host / Process / Network tabs)
  defineTelemetryRoutes(router, logger);
}
