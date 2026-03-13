import {
  CoreSetup,
  CoreStart,
  Logger,
  Plugin,
  PluginInitializerContext,
  ISavedObjectsRepository,
} from '../../../src/core/server';
import { defineRoutes } from './routes';
import { installTelemetryDashboard } from './telemetry_dashboard_installer';
import { installTelemetryIsmPolicy } from './telemetry_ism_installer';
import { XdrManagerPluginSetup, XdrManagerPluginStart } from './types';
import { XDR_AGENT_SAVED_OBJECT_TYPE, XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE } from '../common';

export class XdrManagerPlugin implements Plugin<XdrManagerPluginSetup, XdrManagerPluginStart> {
  private readonly logger: Logger;
  private agentRepoResolve!: (repo: ISavedObjectsRepository) => void;
  private readonly agentRepoPromise: Promise<ISavedObjectsRepository>;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
    this.agentRepoPromise = new Promise<ISavedObjectsRepository>((resolve) => {
      this.agentRepoResolve = resolve;
    });
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
          createdAt: { type: 'date' },
          consumedAt: { type: 'date' },
          consumedAgentId: { type: 'keyword' },
          consumedHostname: { type: 'keyword' },
        },
      },
    });

    const router = core.http.createRouter();
    defineRoutes(router, this.logger, this.agentRepoPromise);

    return {};
  }

  public start(core: CoreStart): XdrManagerPluginStart {
    this.logger.debug('xdr_manager: start');

    // Create the internal repository that can access hidden saved object types
    const repo = core.savedObjects.createInternalRepository([
      XDR_AGENT_SAVED_OBJECT_TYPE,
      XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE,
    ]);

    // Resolve the promise so route handlers can use it
    this.agentRepoResolve(repo);

    // Install the out-of-the-box telemetry dashboard (index-pattern + visualizations + dashboard)
    installTelemetryDashboard(repo, this.logger).catch((err) =>
      this.logger.error(`xdr_manager: telemetry dashboard install failed: ${err}`)
    );

    // Install ISM policy (90-day retention) and index template for telemetry indices
    const opensearchClient = core.opensearch.client.asInternalUser;
    installTelemetryIsmPolicy(opensearchClient, this.logger).catch((err) =>
      this.logger.error(`xdr_manager: ISM policy install failed: ${err}`)
    );

    return {};
  }

  public stop() {}
}
