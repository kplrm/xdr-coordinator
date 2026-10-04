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
  GenerateEnrollmentTokenRequest,
  GenerateEnrollmentTokenResponse,
  LatestVersionResponse,
  ListAgentsResponse,
  ListEnrollmentTokensResponse,
  RemoveAgentResponse,
  RunActionResponse,
  UpdateEnrollmentTokenTagRequest,
  UpsertPolicyRequest,
  UpsertPolicyResponse,
  XdrAgent,
  XdrPolicy,
  XDR_AGENT_SAVED_OBJECT_TYPE,
  XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
  XDR_POLICY_SAVED_OBJECT_TYPE,
} from '../../common';

const defaultPolicy: XdrPolicy = {
  id: 'default-endpoint',
  name: 'Default Endpoint Policy',
  description: 'Default agent group.',
};

// Group labels are persisted; they never change endpoint protections.
async function listPolicies(repo: ISavedObjectsRepository): Promise<XdrPolicy[]> {
  const result = await repo.find<Omit<XdrPolicy, 'id'>>({ type: XDR_POLICY_SAVED_OBJECT_TYPE, perPage: 10000 });
  return [defaultPolicy, ...result.saved_objects.map((item) => ({ id: item.id, ...item.attributes }))];
}

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
    protection: so.attributes.protection,
  };
}

type EnrollmentTokenAttributes = {
  token: string;
  policyId: string;
  tag?: string;
  createdAt: string;
  consumedAt?: string;
  consumedAgentId?: string;
  consumedHostname?: string;
};

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
    req.setTimeout(10000, () => req.destroy(new Error('GitHub release lookup timed out')));
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

const authorizeAgentRequest = async (
  repo: ISavedObjectsRepository,
  authorization: string | string[] | undefined,
  agentId: string
): Promise<
  | { ok: true; agent: { id: string; attributes: XdrAgentAttributes } }
  | { ok: false; status: 'unauthorized' | 'not-found'; message: string }
> => {
  const bearerToken = readBearerToken(authorization);
  if (!bearerToken) {
    return {
      ok: false,
      status: 'unauthorized',
      message: 'Missing or invalid Authorization header',
    };
  }

  const tokenSearchResult = await repo.find<EnrollmentTokenAttributes>({
    type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
    search: bearerToken,
    searchFields: ['token'],
    perPage: 1,
  });

  if (tokenSearchResult.saved_objects[0]?.attributes.token !== bearerToken) {
    return {
      ok: false,
      status: 'unauthorized',
      message: 'Enrollment token is invalid',
    };
  }

  let agent: { id: string; attributes: XdrAgentAttributes };
  try {
    agent = await repo.get<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, agentId);
  } catch (err: any) {
    if (err?.output?.statusCode === 404) {
      return {
        ok: false,
        status: 'not-found',
        message: `Agent [${agentId}] not found`,
      };
    }
    throw err;
  }

  if (!agent.attributes.enrollmentToken || agent.attributes.enrollmentToken !== bearerToken) {
    return {
      ok: false,
      status: 'unauthorized',
      message: `Bearer token does not match enrolled token for agent [${agentId}]`,
    };
  }

  return { ok: true, agent };
};

const policyRequestSchema = schema.object({
  name: schema.string({ minLength: 1 }),
  description: schema.string({ minLength: 1 }),

});

export function defineRoutes(
  router: IRouter,
  logger: Logger,
  agentRepoPromise: Promise<ISavedObjectsRepository>
) {
  const collectPendingCommands = async (agentId: string, agentVersion: string): Promise<string[]> => {
    const repo = await agentRepoPromise;
    const agent = await repo.get<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, agentId);
    const target = agent.attributes.pendingUpgradeVersion;
    if (!target) return [];
    if (target === agentVersion) {
      await repo.update(XDR_AGENT_SAVED_OBJECT_TYPE, agentId, { pendingUpgradeVersion: '' });
      return [];
    }
    return [`upgrade:${target}`];
  };

  router.post(
    {
      path: '/api/xdr_manager/enrollment_tokens',
      validate: {
        body: schema.object({
          policyId: schema.string({ minLength: 1 }),
          tag: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      const payload = request.body as GenerateEnrollmentTokenRequest;
      const policies = await listPolicies(await agentRepoPromise);
      const selectedPolicy = policies.find((policy) => policy.id === request.body.policyId);

      if (!selectedPolicy) {
        return response.badRequest({
          body: `Unknown policy [${request.body.policyId}]`,
        });
      }

      const token = issueEnrollmentToken();
      const createdAt = new Date().toISOString();
      const trimmedTag = payload.tag?.trim();
      const repo = await agentRepoPromise;
      await repo.create<EnrollmentTokenAttributes>(
        XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        {
          token,
          policyId: request.body.policyId,
          createdAt,
          tag: trimmedTag || undefined,
        }
      );

      const body: GenerateEnrollmentTokenResponse = {
        token,
        policyId: request.body.policyId,
        createdAt,
        tag: trimmedTag || undefined,
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
      if (!tokenSO || tokenSO.attributes.token !== request.params.token) {
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
        tag: t.tag,
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
      if (!tokenSO || tokenSO.attributes.token !== request.params.token) {
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

  router.put(
    {
      path: '/api/xdr_manager/enrollment_tokens/{token}/tag',
      validate: {
        params: schema.object({
          token: schema.string({ minLength: 1 }),
        }),
        body: schema.object({
          tag: schema.string(),
        }),
      },
    },
    async (_context, request, response) => {
      const payload = request.body as UpdateEnrollmentTokenTagRequest;
      const repo = await agentRepoPromise;
      const result = await repo.find<EnrollmentTokenAttributes>({
        type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
        search: request.params.token,
        searchFields: ['token'],
        perPage: 1,
      });

      const tokenSO = result.saved_objects[0] ?? null;
      if (!tokenSO || tokenSO.attributes.token !== request.params.token) {
        return response.notFound({
          body: `Enrollment token not found`,
        });
      }

      const trimmedTag = payload.tag.trim();
      await repo.update<EnrollmentTokenAttributes>(XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, tokenSO.id, {
        tag: trimmedTag || undefined,
      });

      return response.ok({
        body: {
          token: tokenSO.attributes.token,
          tag: trimmedTag || undefined,
        },
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
      if (!tokenSO || tokenSO.attributes.token !== bearerToken) {
        return response.unauthorized({
          body: {
            message: 'Enrollment token is invalid',
          },
        });
      }

      const payload = request.body as ControlPlaneEnrollRequest;
      if (tokenSO.attributes.consumedAgentId && tokenSO.attributes.consumedAgentId !== payload.agent_id) {
        return response.unauthorized({ body: { message: 'Enrollment token is already assigned to another agent' } });
      }
      if (tokenSO.attributes.policyId !== payload.policy_id) {
        return response.badRequest({
          body: {
            message: `Enrollment token policy mismatch: token=${tokenSO.attributes.policyId} request=${payload.policy_id}`,
          },
        });
      }

      const policies = await listPolicies(await agentRepoPromise);
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
        enrollmentToken: bearerToken,
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
        await repo.create<XdrAgentAttributes>(XDR_AGENT_SAVED_OBJECT_TYPE, agentAttrs, {
          id: payload.agent_id,
        });
      }

      const body: ControlPlaneEnrollResponse = {
        enrollment_id: payload.agent_id,
        message: `enrolled agent ${payload.hostname}`,
      };

      // Mark token as consumed in saved objects
      if (!tokenSO.attributes.consumedAt) {
        await repo.update<EnrollmentTokenAttributes>(XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, tokenSO.id, {
          consumedAt: now,
          consumedAgentId: payload.agent_id,
          consumedHostname: payload.hostname,
        });
      }

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
          protection: schema.maybe(schema.object({
            rule_source: schema.string(), rule_version: schema.string(),
            rule_count: schema.number({ min: 0 }), mode: schema.string(),
            platform: schema.string(), rules_sha256: schema.string(),
            health: schema.maybe(schema.recordOf(schema.string(), schema.string())),
          })),
        }),
      },
      options: {
        authRequired: false,
      },
    },
    async (context, request, response) => {
      const payload = request.body as ControlPlaneHeartbeatRequest;
      const repo = await agentRepoPromise;
      const auth = await authorizeAgentRequest(repo, request.headers.authorization, payload.agent_id);
      if (!auth.ok) {
        if (auth.status === 'not-found') {
          return response.notFound({
            body: {
              message: auth.message,
            },
          });
        }
        return response.unauthorized({
          body: {
            message: auth.message,
          },
        });
      }

      await repo.update(XDR_AGENT_SAVED_OBJECT_TYPE, payload.agent_id, {
        name: payload.hostname,
        status: Object.values(payload.protection?.health ?? {}).some((value) => /^(degraded|failed|stopped|unknown|disabled)/.test(value)) ? 'degraded' : 'healthy',
        lastSeen: new Date().toISOString(),
        tags: payload.tags,
        version: payload.agent_version,
        ...(payload.protection ? { protection: payload.protection } : {}),
      });

      let pendingCommands: string[] = [];
      try {
        pendingCommands = await collectPendingCommands(
          payload.agent_id,
          payload.agent_version
        );
      } catch (err: any) {
        // Keep heartbeat healthy even if command lookup fails.
        // The agent polls commands frequently and will pick them up on recovery.
        logger.warn(`heartbeat command lookup failed for agent ${payload.agent_id}: ${String(err?.message ?? err)}`);
        pendingCommands = [];
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
    async (context, request, response) => {
      const { agent_id, agent_version } = request.query as {
        agent_id: string;
        agent_version: string;
      };

      const repo = await agentRepoPromise;
      const auth = await authorizeAgentRequest(repo, request.headers.authorization, agent_id);
      if (!auth.ok) {
        if (auth.status === 'not-found') {
          return response.notFound({
            body: {
              message: auth.message,
            },
          });
        }
        return response.unauthorized({
          body: {
            message: auth.message,
          },
        });
      }

      const pendingCommands = await collectPendingCommands(agent_id, agent_version);

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
        policies: await listPolicies(repo),
        latestVersion,
      };

      return response.ok({ body });
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
          policies: await listPolicies(await agentRepoPromise),
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
      const repo = await agentRepoPromise;
      const policies = await listPolicies(repo);
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
      await repo.create(XDR_POLICY_SAVED_OBJECT_TYPE, payload, { id });

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
      const repo = await agentRepoPromise;
      const policies = await listPolicies(repo);
      const policy = policies.find((item) => item.id === request.params.id);

      if (!policy) {
        return response.notFound({
          body: `Policy [${request.params.id}] not found`,
        });
      }

      if (policy.id === defaultPolicy.id) {
        return response.badRequest({ body: 'The default group cannot be edited' });
      }
      const payload = request.body as UpsertPolicyRequest;
      await repo.update(XDR_POLICY_SAVED_OBJECT_TYPE, policy.id, payload);
      Object.assign(policy, payload);

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
      const policies = await listPolicies(await agentRepoPromise);
      if (request.params.id === defaultPolicy.id) return response.badRequest({ body: 'The default group cannot be deleted' });
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

      const tokens = await agentRepo.find<EnrollmentTokenAttributes>({ type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, perPage: 10000 });
      if (tokens.saved_objects.some((token) => token.attributes.policyId === request.params.id)) {
        return response.badRequest({ body: 'Revoke enrollment tokens assigned to this group first' });
      }
      const deletedPolicy = policies[policyIndex];
      await agentRepo.delete(XDR_POLICY_SAVED_OBJECT_TYPE, deletedPolicy.id);

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

      const targetVersion = await getCachedLatestVersion();
      await repo.update(XDR_AGENT_SAVED_OBJECT_TYPE, request.params.id, { pendingUpgradeVersion: targetVersion });

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
  const MAX_EVENTS_PER_INGEST_REQUEST = 1000;
  const BULK_INDEX_CHUNK_SIZE = 250;
  const isSecurityEvent = (event: ControlPlaneTelemetryRequest['events'][number]) =>
    event['event.kind'] === 'alert' || /^(detection|prevention|response)\./.test(event['event.module']);
  const isAgentLogEvent = (event: ControlPlaneTelemetryRequest['events'][number]) =>
    event['event.type'] === 'agent.log' || event['event.module'] === 'agent.logger';

  const buildDailyIndexName = (prefix: string): string => {
    const today = new Date().toISOString().slice(0, 10);
    return `${prefix}-${today}`;
  };

  const telemetryEventSchema = schema.object({
    id: schema.string({ minLength: 1 }),
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
    // Send bulk requests in bounded chunks to avoid creating one very large payload.
    for (let start = 0; start < events.length; start += BULK_INDEX_CHUNK_SIZE) {
      const end = Math.min(start + BULK_INDEX_CHUNK_SIZE, events.length);
      const bulkBody: Array<Record<string, unknown>> = [];

      for (let i = start; i < end; i++) {
        const evt = events[i];
        bulkBody.push({ index: { _index: indexName, _id: `${payload.agent_id}:${evt.id}` } });
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
        throw new Error(`Bulk index to [${indexName}]: ${failedItems.length}/${end - start} ${kind} events failed`);
      }
    }
  };

  const topics = [
    { path: '/api/v1/agents/telemetry', kind: 'telemetry' as const, prefix: XDR_TELEMETRY_INDEX_PREFIX,
      accepts: (event: ControlPlaneTelemetryRequest['events'][number]) => !isSecurityEvent(event) && !isAgentLogEvent(event) },
    { path: '/api/v1/agents/security', kind: 'security' as const, prefix: XDR_SECURITY_INDEX_PREFIX, accepts: isSecurityEvent },
    { path: '/api/v1/agents/logs', kind: 'logs' as const, prefix: XDR_LOGS_INDEX_PREFIX, accepts: isAgentLogEvent },
  ];
  for (const topic of topics) {
    router.post({
      path: topic.path,
      validate: { body: schema.object({
        agent_id: schema.string({ minLength: 1 }),
        events: schema.arrayOf(telemetryEventSchema, { minSize: 1, maxSize: MAX_EVENTS_PER_INGEST_REQUEST }),
      }) },
      options: { authRequired: false, body: { maxBytes: 10 * 1024 * 1024 } },
    }, async (context, request, response) => {
      const payload = request.body as ControlPlaneTelemetryRequest;
      const repo = await agentRepoPromise;
      const auth = await authorizeAgentRequest(repo, request.headers.authorization, payload.agent_id);
      if (!auth.ok) {
        return auth.status === 'not-found'
          ? response.notFound({ body: { message: auth.message } })
          : response.unauthorized({ body: { message: auth.message } });
      }
      if (!payload.events.every(topic.accepts)) {
        return response.badRequest({ body: { message: `Events do not belong to ${topic.kind} endpoint` } });
      }
      try {
        const indexName = buildDailyIndexName(topic.prefix);
        await indexBatch(context, payload, payload.events, indexName, topic.kind);
        const body: ControlPlaneTelemetryResponse = {
          indexed: payload.events.length,
          message: `${payload.events.length} events indexed into ${indexName}`,
        };
        return response.ok({ body });
      } catch (err) {
        logger.error(`Failed to index ${topic.kind} events: ${err}`);
        // Stable event IDs make retrying a partially accepted batch safe.
        return response.customError({ statusCode: 502, body: { message: `Failed to index ${topic.kind} events` } });
      }
    });
  }

  router.get({ path: '/api/xdr_manager/protections', validate: false }, async (_context, _request, response) => {
    const repo = await agentRepoPromise;
    const result = await repo.find<XdrAgentAttributes>({ type: XDR_AGENT_SAVED_OBJECT_TYPE, perPage: 10000 });
    const agents = result.saved_objects.map((item) => {
      const agent = toXdrAgent(item);
      return { agent_id: agent.id, name: agent.name, status: deriveAgentStatus(agent, Date.now()),
        version: agent.version, last_seen: agent.lastSeen, protection: agent.protection };
    });
    return response.ok({ body: { agents, total: agents.length } });
  });

  // ── DELETE /api/xdr_manager/agents/{id} ────────────────────────────────
  // Removes the agent and revokes its enrollment token.

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

      // Revoke its enrollment credential so an uninstalled agent cannot silently rejoin.
      const tokens = await repo.find<EnrollmentTokenAttributes>({ type: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, perPage: 10000 });
      for (const token of tokens.saved_objects) {
        if (token.attributes.consumedAgentId === request.params.id) {
          await repo.delete(XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, token.id);
        }
      }

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
      const policies = await listPolicies(await agentRepoPromise);
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
            tag: t.tag,
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


}
