// Stable release versions only; unknown or newer installed versions never downgrade.
export function isNewerVersion(candidate: string | undefined, installed: string): boolean {
  const next = candidate?.match(/^(\d+)\.(\d+)\.(\d+)$/);
  const current = installed.match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  if (!next || !current) return false;
  for (let part = 1; part <= 3; part++) {
    if (Number(next[part]) !== Number(current[part])) return Number(next[part]) > Number(current[part]);
  }
  return installed.includes('-');
}
