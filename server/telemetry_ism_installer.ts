/** Mappings, data stream and retention for XDR telemetry. */

import type { Logger } from '../../OpenSearch-Dashboards/src/core/server';
import { installEventDataStream } from './event_data_stream';

// Lucene terms are limited to 32,766 UTF-8 bytes. This character limit remains
// safe even for four-byte Unicode characters. Full values remain in _source.
const PROCESS_TEXT_FIELDS = {
  command_line: { type: 'keyword', ignore_above: 8191 },
  args: { type: 'keyword', ignore_above: 8191 },
};

const ENDPOINT_MAPPINGS = {
  local: {
    properties: {
      ip: { type: 'ip' },
      port: { type: 'integer' },
      user: { properties: { id: { type: 'keyword' }, name: { type: 'keyword' } } },
    },
  },
  remote: { properties: { ip: { type: 'ip' }, port: { type: 'integer' } } },
};

const DNS_ENDPOINT_MAPPINGS = { client: ENDPOINT_MAPPINGS.remote, server: ENDPOINT_MAPPINGS.remote };

function buildIndexTemplate() {
  return {
    index_patterns: ['xdr-agent-telemetry'],
    priority: 100,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
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
          'event.severity': { type: 'integer' }, // File telemetry only.
          'event.module': { type: 'keyword' },
          'agent.id': { type: 'keyword' },
          'host.hostname': { type: 'keyword' },
          tags: { type: 'keyword' },
          indexed_at: { type: 'date' },
          'threat.tactic.name': { type: 'keyword' },
          'threat.technique.id': { type: 'keyword' },
          'threat.technique.subtechnique.id': { type: 'keyword' },
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
              ...PROCESS_TEXT_FIELDS,
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
                  ...PROCESS_TEXT_FIELDS,
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
              direction:    { type: 'keyword' },   // inbound | outbound | internal | external | unknown
              protocol:     { type: 'keyword' },   // tcp4 | tcp6 | udp4 | udp6
              community_id: { type: 'keyword' },   // Community ID v1 hash "1:<base64>"
              state:       { type: 'keyword' },
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
          ...ENDPOINT_MAPPINGS,
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
              ...DNS_ENDPOINT_MAPPINGS,
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
          // Note: this `user` sub-object is distinct from the
          //       `process.user` field already mapped above.
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
          'event.action': { type: 'keyword' },
          'event.outcome': { type: 'keyword' },
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
          // Fields that have no ECS home live under xdr.*
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
  };
}

export async function installTelemetryIsmPolicy(
  opensearchClient: any,
  logger: Logger
): Promise<void> {
  await installEventDataStream(opensearchClient, logger, 'telemetry', buildIndexTemplate());
}
