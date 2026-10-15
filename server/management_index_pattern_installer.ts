import { ISavedObjectsRepository, Logger } from '../../OpenSearch-Dashboards/src/core/server';

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
    {
      type: 'index-pattern',
      id: 'xdr-agent-logs-hidden',
      attributes: {
        title: 'xdr-agent-logs,.xdr-agent-logs-*',
        timeFieldName: '@timestamp',
        fields: '[]',
      },
      references: [],
    },
    {
      type: 'index-pattern',
      id: 'xdr-agent-security-hidden',
      attributes: {
        title: 'xdr-agent-security,.xdr-agent-security-*',
        timeFieldName: '@timestamp',
        fields: '[]',
      },
      references: [],
    },
  ];
}

export async function installManagementIndexPatterns(
  repo: ISavedObjectsRepository,
  logger: Logger
): Promise<void> {
  try {
    for (const pattern of buildIndexPatterns()) {
      try {
        const existing = await repo.get<{ title: string }>(pattern.type, pattern.id);
        const legacy = pattern.attributes.title.split(',')[1];
        if (existing.attributes.title === legacy) {
          await repo.update(pattern.type, pattern.id, { title: pattern.attributes.title });
        }
      } catch (error: any) {
        if (error?.output?.statusCode !== 404) throw error;
      }
    }
    const result = await repo.bulkCreate(buildIndexPatterns() as any[], { overwrite: false });
    const errors = result.saved_objects.filter(
      (obj: any) => obj.error && obj.error.statusCode !== 409
    );

    if (errors.length > 0) {
      logger.warn(
        `xdr_manager: management index-pattern install error: ` +
          errors.map((e: any) => `${e.type}/${e.id}: ${e.error.message}`).join('; ')
      );
      return;
    }

    logger.info('xdr_manager: ensured management index-patterns for logs/security');
  } catch (err) {
    logger.error(`xdr_manager: failed to install management index-patterns: ${err}`);
  }
}
