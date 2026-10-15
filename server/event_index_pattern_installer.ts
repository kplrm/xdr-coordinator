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
): Promise<Record<string, string>> {
  try {
    // Saved objects are tenant-scoped. Reuse manually created views by title
    // instead of creating duplicates or replacing the operator's formatting.
    const existing = await repo.find<{ title: string; fields?: string; timeFieldName?: string }>({
      type: 'index-pattern', perPage: 10000,
    });
    // Remove only the combined default previously provisioned by this plugin.
    if (existing.saved_objects.some((item) => item.id === 'xdr-agent-events' && item.attributes.title === 'xdr-agent-*')) {
      try {
        await repo.delete('index-pattern', 'xdr-agent-events');
      } catch (error: any) {
        if ((error.statusCode ?? error.output?.statusCode ?? error.meta?.statusCode) !== 404) throw error;
      }
    }
    const ids: Record<string, string> = {};
    const patterns = buildIndexPatterns().filter((pattern) => {
      const found = existing.saved_objects.find((item) => item.attributes.title === pattern.attributes.title);
      ids[pattern.attributes.title] = found?.id ?? pattern.id;
      return !found || (found.id === pattern.id && (!found.attributes.fields || found.attributes.fields === '[]'));
    });
    // Discover loads the saved field list; an empty list breaks its time field
    // and field picker even when the stream's mappings already exist.
    await Promise.all(patterns.map(async (pattern) => {
      pattern.attributes.fields = JSON.stringify(await getFields(pattern.attributes.title));
    }));
    const result = patterns.length
      ? await repo.bulkCreate(patterns as any[], { overwrite: true })
      : { saved_objects: [] };
    const errors = result.saved_objects.filter(
      (obj: any) => obj.error && obj.error.statusCode !== 409
    );

    if (errors.length > 0) {
      throw new Error(errors.map((e: any) => `${e.type}/${e.id}: ${e.error.message}`).join('; '));
    }

    logger.info('xdr_manager: ensured Discover index patterns for telemetry, security and logs');
    return ids;
  } catch (err) {
    logger.error(`xdr_manager: failed to install event index-patterns: ${err}`);
    throw err;
  }
}
