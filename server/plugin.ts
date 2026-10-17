import {
  CoreSetup,
  CoreStart,
  Logger,
  Plugin,
  PluginInitializerContext,
  ISavedObjectsRepository,
} from '../../OpenSearch-Dashboards/src/core/server';
// Runtime imports resolve from plugins/<id>/server in the Dashboards installation.
import { SavedObjectsClient } from '../../../src/core/server';
import { IndexPatternsFetcher } from '../../../src/plugins/data/server';
import { defineRoutes } from './routes';
import { installTelemetryIsmPolicy } from './telemetry_ism_installer';
import { installSecurityIsmPolicy } from './security_ism_installer';
import { installAgentLogsIsmPolicy } from './logs_ism_installer';
import { installEventIndexPatterns } from './event_index_pattern_installer';
import { EVENT_STREAMS } from './event_data_stream';
import { XdrManagerPluginSetup, XdrManagerPluginStart } from './types';
import { XDR_AGENT_SAVED_OBJECT_TYPE, XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE, XDR_POLICY_SAVED_OBJECT_TYPE } from '../common';

export class XdrManagerPlugin implements Plugin<XdrManagerPluginSetup, XdrManagerPluginStart> {
  private readonly logger: Logger;
  private agentRepoResolve!: (repo: ISavedObjectsRepository) => void;
  private readonly agentRepoPromise: Promise<ISavedObjectsRepository>;
  private readonly ingestionReady: Promise<void>;
  private ingestionResolve!: () => void;
  private ingestionReject!: (error: unknown) => void;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
    this.agentRepoPromise = new Promise<ISavedObjectsRepository>((resolve) => {
      this.agentRepoResolve = resolve;
    });
    this.ingestionReady = new Promise<void>((resolve, reject) => {
      this.ingestionResolve = resolve;
      this.ingestionReject = reject;
    });
    // Startup reports the error; ingestion requests receive 502 until repaired.
    void this.ingestionReady.catch(() => {});
  }

  public setup(core: CoreSetup): XdrManagerPluginSetup {
    this.logger.debug('xdr_manager: setup');

    // Register the xdr-agent saved object type
    core.savedObjects.registerType({
      name: XDR_AGENT_SAVED_OBJECT_TYPE,
      hidden: true,
      namespaceType: 'agnostic',
      mappings: {
        properties: {
          name: { type: 'keyword' },
          policyId: { type: 'keyword' },
          status: { type: 'keyword' },
          lastSeen: { type: 'date' },
          tags: { type: 'keyword' },
          version: { type: 'keyword' },
          enrollmentToken: { type: 'keyword' },
          pendingUpgradeVersion: { type: 'keyword' },
          protection: { type: 'object', enabled: false },
          configRevision: { type: 'keyword' },
          configError: { type: 'text', index: false },
        },
      },
    });

    // Register the enrollment token saved object type
    core.savedObjects.registerType({
      name: XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
      hidden: true,
      namespaceType: 'agnostic',
      mappings: {
        properties: {
          token: { type: 'keyword' },
          policyId: { type: 'keyword' },
          tag: { type: 'keyword' },
          createdAt: { type: 'date' },
          consumedAt: { type: 'date' },
          consumedAgentId: { type: 'keyword' },
          consumedHostname: { type: 'keyword' },
        },
      },
    });

    core.savedObjects.registerType({
      name: XDR_POLICY_SAVED_OBJECT_TYPE, hidden: true, namespaceType: 'agnostic',
      mappings: { properties: {
        name: { type: 'keyword' }, description: { type: 'text' },
        config: { type: 'object', enabled: false }, configRevision: { type: 'keyword' },
      } },
    });

    const router = core.http.createRouter();
    defineRoutes(router, this.logger, this.agentRepoPromise, this.ingestionReady);

    // Browser startup calls this once for its selected tenant, including Private.
    // Security's XDR role guard and the scoped client enforce caller permissions.
    router.post({ path: '/api/xdr_manager/setup', validate: false }, async (context, _request, response) => {
      try {
        await this.ingestionReady;
        const fields = new IndexPatternsFetcher(context.core.opensearch.legacy.client.callAsCurrentUser);
        const ids = await installEventIndexPatterns(context.core.savedObjects.client, this.logger,
          (pattern) => fields.getFieldsForWildcard({ pattern, metaFields: ['_id', '_index', '_source', '_score'] }));
        const currentDefault = await context.core.uiSettings.client.get('defaultIndex');
        if (!currentDefault || currentDefault === 'xdr-agent-events') {
          await context.core.uiSettings.client.set('defaultIndex', ids[EVENT_STREAMS.telemetry]);
        }
        return response.ok({ body: { telemetryId: ids[EVENT_STREAMS.telemetry] } });
      } catch (error: any) {
        const status = error.statusCode ?? error.meta?.statusCode;
        return response.customError({ statusCode: status === 403 ? 403 : 500,
          body: { message: 'Unable to initialize XDR Discover patterns. Check tenant permissions and Dashboards logs.' } });
      }
    });

    return {};
  }

  public start(core: CoreStart): XdrManagerPluginStart {
    this.logger.debug('xdr_manager: start');

    // Create the internal repository that can access hidden saved object types
    const repo = core.savedObjects.createInternalRepository([
      XDR_AGENT_SAVED_OBJECT_TYPE,
      XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
      XDR_POLICY_SAVED_OBJECT_TYPE,
    ]);

    // Resolve the promise so route handlers can use it
    this.agentRepoResolve(repo);

    // Routes await provisioning, so a startup race cannot create plain indices
    // where data streams should be. Health/enrollment do not wait on ingestion.
    const client = core.opensearch.client.asInternalUser;
    // The first policy may initialize ISM's system index; serialize that work.
    void (async () => {
      await installTelemetryIsmPolicy(client, this.logger);
      await installSecurityIsmPolicy(client, this.logger);
      await installAgentLogsIsmPolicy(client, this.logger);
      this.ingestionResolve();
      // Default Discover views live in the Global tenant, alongside these
      // provisioned streams. Do not replace the user's default Discover view.
      const fields = new IndexPatternsFetcher(core.opensearch.legacy.client.callAsInternalUser);
      const ids = await installEventIndexPatterns(repo, this.logger, (pattern) => fields.getFieldsForWildcard({
        pattern, metaFields: ['_id', '_index', '_source', '_score'],
      }));
      const settings = core.uiSettings.asScopedToClient(new SavedObjectsClient(repo));
      const currentDefault = await settings.get('defaultIndex');
      if (!currentDefault || currentDefault === 'xdr-agent-events') await settings.set('defaultIndex', ids[EVENT_STREAMS.telemetry]);
    })().catch((error) => {
      this.ingestionReject(error);
      this.logger.error(`xdr_manager: stream/Discover startup setup failed: ${error}`);
    });

    return {};
  }

  public stop() {}
}
