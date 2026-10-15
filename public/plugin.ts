import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../OpenSearch-Dashboards/src/core/public';
import { PLUGIN_ID, PLUGIN_NAME } from '../common';
import { XdrManagerPluginSetup, XdrManagerPluginStart } from './types';

export class XdrManagerPlugin implements Plugin<XdrManagerPluginSetup, XdrManagerPluginStart> {
  public setup(core: CoreSetup): XdrManagerPluginSetup {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      order: 1,
      category: {
        id: 'xdrSecurity',
        label: 'XDR Security',
        order: 2200,
      },
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });

    return {};
  }

  public async start(core: CoreStart): Promise<XdrManagerPluginStart> {
    // Await setup before Discover mounts. Startup defaults exist in Global;
    // this also prepares the logged-in user's selected tenant.
    if (core.application.capabilities.indexPatterns?.save) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const { telemetryId } = await core.http.post<{ telemetryId: string }>('/api/xdr_manager/setup', { signal: controller.signal });
        const currentDefault = core.uiSettings.get('defaultIndex');
        if (!currentDefault || currentDefault === 'xdr-agent-events') await core.uiSettings.set('defaultIndex', telemetryId);
      } catch (error: any) {
        if (![401, 403].includes(error.response?.status ?? error.body?.statusCode)) {
          core.notifications.toasts.addWarning('XDR Discover patterns could not be initialized. Check Dashboards logs and tenant write access.');
        }
      } finally {
        clearTimeout(timeout);
      }
    }
    return {};
  }

  public stop() {}
}
