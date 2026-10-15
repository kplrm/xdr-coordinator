import {
  CoreSetup,
  CoreStart,
  Logger,
  Plugin,
  PluginInitializerContext,
  ISavedObjectsRepository,
} from '../../OpenSearch-Dashboards/src/core/server';
import { defineRoutes } from './routes';
import { installTelemetryIsmPolicy } from './telemetry_ism_installer';
import { installSecurityIsmPolicy } from './security_ism_installer';
import { installAgentLogsIsmPolicy } from './logs_ism_installer';
import { installManagementIndexPatterns } from './management_index_pattern_installer';
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
      mappings: { properties: { name: { type: 'keyword' }, description: { type: 'text' } } },
    });

    const router = core.http.createRouter();
    defineRoutes(router, this.logger, this.agentRepoPromise, this.ingestionReady);

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

    // Install out-of-the-box hidden index patterns for logs and security views.
    installManagementIndexPatterns(repo, this.logger).catch((err) =>
      this.logger.error(`xdr_manager: management index-pattern install failed: ${err}`)
    );

    // Routes await provisioning, so a startup race cannot create plain indices
    // where data streams should be. Health/enrollment do not wait on ingestion.
    const client = core.opensearch.client.asInternalUser;
    // The first policy may initialize ISM's system index; serialize that work.
    void (async () => {
      await installTelemetryIsmPolicy(client, this.logger);
      await installSecurityIsmPolicy(client, this.logger);
      await installAgentLogsIsmPolicy(client, this.logger);
    })().then(this.ingestionResolve, (error) => {
      this.ingestionReject(error);
      this.logger.error(`xdr_manager: event data stream provisioning failed: ${error}`);
    });

    return {};
  }

  public stop() {}
}
