import type { ProtectionInventory } from './types';

export function agentHealthIssues(protection?: ProtectionInventory): string[] {
  return Object.entries(protection?.health ?? {})
    // Older Agents report this as disabled in detection mode, where execution
    // blocking is deliberately off. Actual protection failures still count.
    .filter(([name, status]) => !(name === 'execution_blocking' && protection?.mode === 'detect' && status === 'disabled'))
    .filter(([, status]) => /^(degraded|failed|stopped|unknown|disabled)/.test(status))
    .map(([name, status]) => `${name}: ${status}`);
}
