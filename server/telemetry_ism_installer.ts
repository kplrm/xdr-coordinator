/**
 * Sets up an OpenSearch Index State Management (ISM) policy for XDR telemetry
 * indices and an index template that auto-attaches the policy to new daily
 * indices matching `.xdr-agent-telemetry-*`.
 *
 * The ISM policy retains data for 90 days, then deletes the index.
 *
 * Called once from plugin.start(). Idempotent — skips creation if the
 * policy / template already exist.
 */

import { Logger } from '../../OpenSearch-Dashboards/src/core/server';

const ISM_POLICY_ID = 'xdr-telemetry-retention';
const INDEX_TEMPLATE_NAME = 'xdr-telemetry-template';
const INDEX_PATTERN = '.xdr-agent-telemetry-*';

/**
 * The ISM policy definition:
 *   hot (current) → 90 days → delete
 */
function buildIsmPolicy() {
  return {
    policy: {
      description: 'Retain XDR telemetry indices for 90 days, then delete.',
      default_state: 'hot',
      states: [
        {
          name: 'hot',
          actions: [],
          transitions: [
            {
              state_name: 'delete',
              conditions: {
                min_index_age: '90d',
              },
            },
          ],
        },
        {
          name: 'delete',
          actions: [
            {
              delete: {},
            },
          ],
          transitions: [],
        },
      ],
      ism_template: [
        {
          index_patterns: [INDEX_PATTERN],
          priority: 100,
        },
      ],
    },
  };
}

/**
 * The index template ensures every new `.xdr-agent-telemetry-*` index gets:
 *   - number_of_shards: 1, number_of_replicas: 0
 *   - hidden: true
 *   - The correct field mappings
 *   - The ISM policy auto-attached via opendistro.index_state_management.policy_id
 */
function buildIndexTemplate() {
  return {
    index_patterns: [INDEX_PATTERN],
    priority: 100,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
        'opendistro.index_state_management.policy_id': ISM_POLICY_ID,
      },
      mappings: {
        dynamic: true,
        // ── Dynamic templates ─────────────────────────────────────────────
        // Applied in order when a new field arrives whose type is not yet
        // explicitly mapped. Goal: never auto-index strings as full-text
        // `text` — always use `keyword` instead (OpenSearch default is text).
        dynamic_templates: [
          {
            // Fields whose name ends in ".ip" should be indexed as IP
            ip_fields: {
              path_match: '*.ip',
              match_mapping_type: 'string',
              mapping: { type: 'ip', ignore_malformed: true },
            },
          },
          {
            // Catch-all: any unrecognised string → keyword (storage-friendly,
            // filterable, aggregatable; no tokenisation overhead)
            strings_as_keyword: {
              match_mapping_type: 'string',
              mapping: { type: 'keyword', ignore_above: 1024 },
            },
          },
        ],
        properties: {
          '@timestamp': { type: 'date' },
          'event.type': { type: 'keyword' },
          'event.category': { type: 'keyword' },
          'event.kind': { type: 'keyword' },
          'event.severity': { type: 'integer' },
          'event.module': { type: 'keyword' },
          'agent.id': { type: 'keyword' },
          'host.hostname': { type: 'keyword' },
          tags: { type: 'keyword' },
          indexed_at: { type: 'date' },
          'threat.tactic.name': { type: 'keyword' },
          'threat.technique.id': { type: 'keyword' },
          'threat.technique.subtechnique.id': { type: 'keyword' },
          payload: {
            type: 'object',
            dynamic: true,
            properties: {
              system: {
                properties: {
                  memory: {
                    properties: {
                      total: { type: 'long' },
                      free: { type: 'long' },
                      cached: { type: 'long' },
                      buffer: { type: 'long' },
                      used: {
                        properties: {
                          bytes: { type: 'long' },
                          pct: { type: 'float' },
                        },
                      },
                      actual: {
                        properties: {
                          free: { type: 'long' },
                        },
                      },
                      swap: {
                        properties: {
                          total: { type: 'long' },
                          free: { type: 'long' },
                          used: {
                            properties: {
                              bytes: { type: 'long' },
                              pct:   { type: 'float' },
                            },
                          },
                        },
                      },
                    },
                  },
                  cpu: {
                    properties: {
                      total: { properties: { pct: { type: 'float' } } },
                      user: { properties: { pct: { type: 'float' } } },
                      system: { properties: { pct: { type: 'float' } } },
                      idle: { properties: { pct: { type: 'float' } } },
                      iowait: { properties: { pct: { type: 'float' } } },
                      steal: { properties: { pct: { type: 'float' } } },
                      cores: { type: 'integer' },
                    },
                  },
                  diskio: {
                    properties: {
                      read:  { properties: { bytes: { type: 'long' }, ops: { type: 'long' } } },
                      write: { properties: { bytes: { type: 'long' }, ops: { type: 'long' } } },
                    },
                  },
                  netio: {
                    properties: {
                      in: {
                        properties: {
                          bytes:     { type: 'long' },
                          errors:    { type: 'long' },
                          packets:   { type: 'long' },
                          dropped:   { type: 'long' },
                          multicast: { type: 'long' },
                        },
                      },
                      out: {
                        properties: {
                          bytes:   { type: 'long' },
                          errors:  { type: 'long' },
                          packets: { type: 'long' },
                          dropped: { type: 'long' },
                        },
                      },
                      // per-interface breakdown — interface names are dynamic,
                      // sub-fields inherit from the dynamic_templates above.
                      interfaces: { type: 'object', dynamic: true },
                    },
                  },
                  disk: {
                    properties: {
                      root: {
                        properties: {
                          total: { type: 'long' },
                          free:  { type: 'long' },
                          used:  { properties: { bytes: { type: 'long' }, pct: { type: 'float' } } },
                        },
                      },
                      home: {
                        properties: {
                          total: { type: 'long' },
                          free:  { type: 'long' },
                          used:  { properties: { bytes: { type: 'long' }, pct: { type: 'float' } } },
                        },
                      },
                      var: {
                        properties: {
                          total: { type: 'long' },
                          free:  { type: 'long' },
                          used:  { properties: { bytes: { type: 'long' }, pct: { type: 'float' } } },
                        },
                      },
                      boot: {
                        properties: {
                          total: { type: 'long' },
                          free:  { type: 'long' },
                          used:  { properties: { bytes: { type: 'long' }, pct: { type: 'float' } } },
                        },
                      },
                    },
                  },
                },
              },
              process: {
                properties: {
                  // ── Core identity ─────────────────────────────────────
                  pid:               { type: 'integer' },
                  ppid:              { type: 'integer' },
                  name:              { type: 'keyword' },
                  executable:        { type: 'keyword' },
                  command_line:      { type: 'keyword' },
                  args:              { type: 'keyword' },
                  working_directory: { type: 'keyword' },
                  entity_id:         { type: 'keyword' },
                  state:             { type: 'keyword' },
                  start_time:        { type: 'long' },
                  // ── Session / terminal ────────────────────────────────
                  session_id: { type: 'integer' },
                  // tty is an ECS object: { nr: int, name: keyword }
                  tty: {
                    properties: {
                      nr:   { type: 'integer' },
                      name: { type: 'keyword' },
                    },
                  },
                  // ── CPU % ─────────────────────────────────────────────
                  cpu: {
                    properties: {
                      pct: { type: 'float' },
                    },
                  },
                  // ── User / group context ──────────────────────────────
                  user: {
                    properties: {
                      id:   { type: 'integer' },
                      name: { type: 'keyword' },
                    },
                  },
                  group: {
                    properties: {
                      id:   { type: 'integer' },
                      name: { type: 'keyword' },
                    },
                  },
                  effective_user:  { properties: { id: { type: 'integer' } } },
                  effective_group: { properties: { id: { type: 'integer' } } },
                  // ── Security ──────────────────────────────────────────
                  cap_eff: { type: 'keyword' },
                  hash: {
                    properties: {
                      sha256: { type: 'keyword' },
                    },
                  },
                  // ── Resource metrics ──────────────────────────────────
                  threads: {
                    properties: {
                      count: { type: 'integer' },
                    },
                  },
                  fd_count: { type: 'integer' },
                  memory: {
                    properties: {
                      rss: { type: 'long' },
                      vms: { type: 'long' },
                    },
                  },
                  io: {
                    properties: {
                      read_bytes:  { type: 'long' },
                      write_bytes: { type: 'long' },
                      pipe_name:   { type: 'keyword' },   // IPC named-pipe path
                    },
                  },
                  // ── Lineage ───────────────────────────────────────────
                  parent: {
                    properties: {
                      pid:          { type: 'integer' },
                      ppid:         { type: 'integer' },
                      name:         { type: 'keyword' },
                      executable:   { type: 'keyword' },
                      command_line: { type: 'keyword' },
                      args:         { type: 'keyword' },
                      entity_id:    { type: 'keyword' },
                    },
                  },
                  // ── Extended process fields ────────────────────────────
                  ancestors: { type: 'object', dynamic: true },
                  group_leader: {
                    properties: {
                      pid:       { type: 'integer' },
                      name:      { type: 'keyword' },
                      entity_id: { type: 'keyword' },
                    },
                  },
                  env:    { type: 'object', dynamic: true },
                  script: {
                    properties: {
                      path:    { type: 'keyword' },
                      content: { type: 'keyword', index: false },
                      length:  { type: 'long' },
                    },
                  },
                },
              },
              // ── Container context ──────────────────────────────────────
              container: {
                properties: {
                  id: { type: 'keyword' },
                },
              },
              // ── ECS network fields (connection events) ─────────────────
              network: {
                properties: {
                  // ECS standard
                  type:         { type: 'keyword' },   // ipv4 | ipv6
                  transport:    { type: 'keyword' },   // tcp | udp
                  direction:    { type: 'keyword' },   // inbound | outbound | internal | listening
                  protocol:     { type: 'keyword' },   // tcp4 | tcp6 | udp4 | udp6
                  community_id: { type: 'keyword' },   // Community ID v1 hash "1:<base64>"
                  // Legacy fields retained for pre-ECS docs already in the index
                  state:       { type: 'keyword' },
                  local_addr:  { type: 'ip' },
                  local_port:  { type: 'integer' },
                  remote_addr: { type: 'ip' },
                  remote_port: { type: 'integer' },
                  inode:       { type: 'long' },
                  uid:         { type: 'integer' },
                  // IPC — Unix domain socket path
                  unix_socket: {
                    properties: {
                      path: { type: 'keyword' },
                    },
                  },
                },
              },
              // ── ECS source / destination (replaces local/remote_addr) ──
              source: {
                properties: {
                  ip:   { type: 'ip' },
                  port: { type: 'integer' },
                  user: {
                    properties: {
                      id:   { type: 'keyword' },   // ECS: source.user.id is keyword/string
                      name: { type: 'keyword' },
                    },
                  },
                },
              },
              destination: {
                properties: {
                  ip:   { type: 'ip' },
                  port: { type: 'integer' },
                },
              },
              // ── ECS file fields (FIM events) ────────────────────────────
              file: {
                properties: {
                  path:      { type: 'keyword' },
                  name:      { type: 'keyword' },
                  directory: { type: 'keyword' },
                  type:      { type: 'keyword' },   // file | dir | symlink | ...
                  size:      { type: 'long' },
                  mode:      { type: 'keyword' },   // octal string e.g. "0644"
                  uid:       { type: 'integer' },
                  gid:       { type: 'integer' },
                  owner:     { type: 'keyword' },
                  group:     { type: 'keyword' },
                  mtime:     { type: 'date' },
                  ctime:     { type: 'date' },
                  hash: {
                    properties: {
                      sha256: { type: 'keyword' },
                    },
                  },
                  entropy:      { type: 'float' },
                  header_bytes: { type: 'keyword', index: false },
                },
              },
              // ── FIM-specific context (action + previous state delta) ────
              fim: {
                properties: {
                  // created | modified | attributes_modified | deleted
                  action: { type: 'keyword' },
                  previous: {
                    properties: {
                      size: { type: 'long' },
                      mode: { type: 'keyword' },
                      uid:  { type: 'integer' },
                      gid:  { type: 'integer' },
                      hash: {
                        properties: {
                          sha256: { type: 'keyword' },
                        },
                      },
                    },
                  },
                },
              },
              // ── ECS dns fields (DNS telemetry events) ──────────────────────
              // Emitted by DNSCollector (internal/telemetry/network/dns.go).
              // Both query (dns.type="query") and response (dns.type="answer")
              // events share this mapping; response-only fields are sparse-indexed.
              dns: {
                properties: {
                  id:                  { type: 'integer' },
                  type:                { type: 'keyword' },   // query | answer
                  op_code:             { type: 'keyword' },
                  response_code:       { type: 'keyword' },   // NOERROR | NXDOMAIN | SERVFAIL | …
                  authoritative:       { type: 'boolean' },
                  recursion_desired:   { type: 'boolean' },
                  recursion_available: { type: 'boolean' },
                  header_flags:        { type: 'keyword' },   // array: e.g. ["rd","ra"]
                  answers_count:       { type: 'integer' },
                  resolved_ips:        { type: 'ip', ignore_malformed: true },
                  question: {
                    properties: {
                      name:              { type: 'keyword' },
                      type:              { type: 'keyword' },
                      class:             { type: 'keyword' },
                      registered_domain: { type: 'keyword' },
                    },
                  },
                  // answers[] is a nested array of RRs; use nested type so
                  // individual RR fields remain correctly correlated.
                  answers: {
                    type: 'nested',
                    properties: {
                      name: { type: 'keyword' },
                      type: { type: 'keyword' },
                      ttl:  { type: 'integer' },
                      data: { type: 'keyword' },
                    },
                  },
                },
              },
              // ── ECS user / session fields (session & authentication events) ──
              // Emitted by SessionCollector (internal/telemetry/session/monitor.go).
              // Note: this `payload.user` sub-object is distinct from the
              //       `payload.process.user` field already mapped above.
              user: {
                properties: {
                  name: { type: 'keyword' },
                  effective: {
                    properties: {
                      name: { type: 'keyword' },
                    },
                  },
                },
              },
              session: {
                properties: {
                  // tty | pts | ssh | remote
                  type: { type: 'keyword' },
                },
              },
              related: {
                properties: {
                  user: { type: 'keyword' },
                  ip:   { type: 'ip', ignore_malformed: true },
                },
              },
              // ── Nested event sub-object inside payload (session events) ────
              // Carries event.action and event.outcome values specific to the
              // session/authentication domain. Separate from top-level ECS
              // event.* dotted fields (e.g. event.category, event.type).
              event: {
                properties: {
                  action:  { type: 'keyword' },
                  outcome: { type: 'keyword' },
                },
              },
              // ── ECS dll fields (library load events) ──────────────────────
              // Emitted by SoLoadCollector (internal/telemetry/library/soload.go).
              dll: {
                properties: {
                  name: { type: 'keyword' },
                  path: { type: 'keyword' },
                  hash: {
                    properties: {
                      sha256: { type: 'keyword' },
                    },
                  },
                  size: { type: 'long' },
                },
              },
              // ── ECS driver fields (kernel module events) ───────────────────
              // Emitted by KernelModuleCollector (internal/telemetry/kernel/modules.go).
              driver: {
                properties: {
                  name: { type: 'keyword' },
                },
              },
              // ── XDR agent-extended sub-objects ────────────────────────────
              // Fields that have no ECS home live under payload.xdr.*
              xdr: {
                properties: {
                  // Kernel module detail (internal/telemetry/kernel/modules.go)
                  kernel_module: {
                    properties: {
                      name:      { type: 'keyword' },
                      size:      { type: 'long' },
                      ref_count: { type: 'integer' },
                      deps:      { type: 'keyword' },
                      state:     { type: 'keyword' },   // Live | Loading | Unloading
                      address:   { type: 'keyword' },
                    },
                  },
                  // Scheduled task / cron change events (internal/telemetry/scheduled/tasks.go)
                  scheduled_task: {
                    properties: {
                      path:             { type: 'keyword' },
                      type:             { type: 'keyword' },   // cron | anacron | at | systemd-timer | …
                      raw_content:      { type: 'keyword', index: false },
                      previous_content: { type: 'keyword', index: false },
                      entries:          { type: 'object',  dynamic: true },
                    },
                  },
                  // Process injection indicators (internal/telemetry/injection/monitor.go)
                  injection: {
                    properties: {
                      indicator: { type: 'keyword' },
                      detail:    { type: 'keyword' },
                      target: {
                        properties: {
                          pid:  { type: 'integer' },
                          name: { type: 'keyword' },
                          exe:  { type: 'keyword' },
                        },
                      },
                      tracer: {
                        properties: {
                          pid:  { type: 'integer' },
                          name: { type: 'keyword' },
                          exe:  { type: 'keyword' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  };
}

export async function installTelemetryIsmPolicy(
  opensearchClient: any,
  logger: Logger
): Promise<void> {
  const isPolicyAlreadyExistsError = (err: any): boolean => {
    const statusCode = err?.statusCode ?? err?.meta?.statusCode;
    const message = String(err?.message ?? err?.meta?.body?.error?.reason ?? '').toLowerCase();
    return statusCode === 409 || message.includes('version conflict') || message.includes('already exists');
  };

  // ── 1. Create or update ISM policy ────────────────────────────────────
  try {
    await opensearchClient.transport.request({
      method: 'PUT',
      path: `/_plugins/_ism/policies/${ISM_POLICY_ID}`,
      body: buildIsmPolicy(),
    });
    logger.info(`xdr_manager: upserted ISM policy [${ISM_POLICY_ID}] (90-day retention)`);
  } catch (err: any) {
    if (isPolicyAlreadyExistsError(err)) {
      logger.debug(`xdr_manager: ISM policy [${ISM_POLICY_ID}] already exists/conflicted during startup`);
    } else {
      logger.warn(`xdr_manager: failed to upsert ISM policy: ${err}`);
    }
  }

  // ── 2. Create or update composable index template ─────────────────────
  try {
    await opensearchClient.indices.putIndexTemplate({
      name: INDEX_TEMPLATE_NAME,
      body: buildIndexTemplate(),
    });
    logger.info(`xdr_manager: installed index template [${INDEX_TEMPLATE_NAME}]`);
  } catch (err) {
    logger.warn(`xdr_manager: failed to install index template: ${err}`);
  }
}
