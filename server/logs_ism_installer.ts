/** Mappings, data stream and retention for XDR logs. */

import type { Logger } from '../../OpenSearch-Dashboards/src/core/server';
import { installEventDataStream } from './event_data_stream';

function buildIndexTemplate() {
  return {
    index_patterns: ['xdr-agent-logs'],
    priority: 120,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
      },
      mappings: {
        dynamic: true,
        dynamic_templates: [
          {
            strings_as_keyword: {
              match_mapping_type: 'string',
              mapping: { type: 'keyword', ignore_above: 1024 },
            },
          },
        ],
        properties: {
          id: { type: 'keyword' },
          '@timestamp': { type: 'date' },
          'event.type': { type: 'keyword' },
          'event.category': { type: 'keyword' },
          'event.kind': { type: 'keyword' },
          'event.severity': { type: 'integer' },
          'event.module': { type: 'keyword' },
          'agent.id': { type: 'keyword' },
          'host.hostname': { type: 'keyword' },
          'log.level': { type: 'keyword' },
          message: { type: 'text' },
          tags: { type: 'keyword' },
          indexed_at: { type: 'date' },
        },
      },
    },
  };
}

export async function installAgentLogsIsmPolicy(
  opensearchClient: any,
  logger: Logger
): Promise<void> {
  await installEventDataStream(opensearchClient, logger, 'logs', buildIndexTemplate());
}
