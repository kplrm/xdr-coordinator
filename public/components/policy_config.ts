import { ManagedAgentConfig } from '../../common';

export const intervalSettings = [
  { key: 'process_scan_interval_seconds', label: 'Process scan interval (seconds)', placeholder: '1' },
  { key: 'network_scan_interval_seconds', label: 'Network scan interval (seconds)', placeholder: '1' },
  { key: 'telemetry_ship_interval_seconds', label: 'Telemetry send interval (seconds)', placeholder: '30' },
] as const;

type IntervalSetting = typeof intervalSettings[number]['key'];

export interface PolicyConfigDraft {
  manageInternalNetworks: boolean;
  internalNetworks: string;
  intervals: Record<IntervalSetting, string>;
}

export function createPolicyConfigDraft(settings: ManagedAgentConfig = {}): PolicyConfigDraft {
  return {
    manageInternalNetworks: settings.internal_networks !== undefined,
    internalNetworks: (settings.internal_networks ?? [
      '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7',
    ]).join('\n'),
    intervals: {
      process_scan_interval_seconds: settings.process_scan_interval_seconds?.toString() ?? '',
      network_scan_interval_seconds: settings.network_scan_interval_seconds?.toString() ?? '',
      telemetry_ship_interval_seconds: settings.telemetry_ship_interval_seconds?.toString() ?? '',
    },
  };
}

export function parsePolicyConfigDraft(draft: PolicyConfigDraft): ManagedAgentConfig {
  const settings: ManagedAgentConfig = {};
  if (draft.manageInternalNetworks) {
    settings.internal_networks = draft.internalNetworks.split(/[\s,]+/).filter(Boolean);
  }
  for (const { key, label } of intervalSettings) {
    const value = draft.intervals[key].trim();
    if (!value) continue;
    const seconds = Number(value);
    if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86400) {
      throw new Error(`${label} must be a whole number from 1 to 86400.`);
    }
    settings[key] = seconds;
  }
  return settings;
}

export function policyConfigUpdate(draft: PolicyConfigDraft, previouslyManaged: boolean) {
  const settings = parsePolicyConfigDraft(draft);
  return previouslyManaged || Object.keys(settings).length > 0 ? settings : undefined;
}
