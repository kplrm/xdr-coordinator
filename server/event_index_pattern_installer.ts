import { ISavedObjectsRepository, Logger } from '../../OpenSearch-Dashboards/src/core/server';
import { EVENT_STREAMS } from './event_data_stream';

type IndexPatternObject = {
  type: 'index-pattern';
  id: string;
  attributes: {
    title: string;
    timeFieldName: '@timestamp';
    fields: string;
  };
  references: [];
};

function buildIndexPatterns(): IndexPatternObject[] {
  return [
    { id: 'xdr-agent-events', title: 'xdr-agent-*' },
    { id: 'xdr-agent-telemetry', title: EVENT_STREAMS.telemetry },
    { id: 'xdr-agent-logs-hidden', title: EVENT_STREAMS.logs },
    { id: 'xdr-agent-security-hidden', title: EVENT_STREAMS.security },
  ].map<IndexPatternObject>(({ id, title }) => ({
    type: 'index-pattern', id,
    attributes: { title, timeFieldName: '@timestamp', fields: '[]' },
    references: [],
  }));
}

export async function installEventIndexPatterns(
  repo: ISavedObjectsRepository,
  logger: Logger,
  getFields: (pattern: string) => Promise<unknown[]>
): Promise<void> {
  try {
    // Dashboards calls these objects index-patterns even for data streams.
    const patterns = buildIndexPatterns();
    // Discover loads the saved field list; an empty list breaks its time field
    // and field picker even when the stream's mappings already exist.
    await Promise.all(patterns.map(async (pattern) => {
      pattern.attributes.fields = JSON.stringify(await getFields(pattern.attributes.title));
    }));
    const result = await repo.bulkCreate(patterns as any[], { overwrite: true });
    const errors = result.saved_objects.filter(
      (obj: any) => obj.error && obj.error.statusCode !== 409
    );

    if (errors.length > 0) {
      logger.warn(
        `xdr_manager: event index-pattern install error: ` +
          errors.map((e: any) => `${e.type}/${e.id}: ${e.error.message}`).join('; ')
      );
      return;
    }

    logger.info('xdr_manager: ensured Discover index patterns for all Agent events and each data stream');
  } catch (err) {
    logger.error(`xdr_manager: failed to install event index-patterns: ${err}`);
  }
}
