import os from 'node:os';

export function redactHome(input: string, home: string = os.homedir()): string {
  if (!home) return input;
  // Normalize Windows backslashes in home for prefix comparison.
  const candidates = new Set<string>([home]);
  if (home.includes('\\')) {
    candidates.add(home.replace(/\\/g, '/'));
  }
  for (const h of candidates) {
    if (input === h) return '~';
    if (input.startsWith(h)) {
      const rest = input.slice(h.length);
      if (!rest.startsWith('/') && !rest.startsWith('\\')) continue;
      // rest starts with separator (\ or /) - keep it as-is so output is ~/x or ~\x.
      return '~' + rest;
    }
  }
  return input;
}

export function redactFinding<T extends { message: string; recommendation?: string; path?: string }>(
  f: T,
  home: string = os.homedir()
): T {
  const result = {
    ...f,
    message: redactHome(f.message, home),
  };

  if (Object.hasOwn(f, 'recommendation') || f.recommendation !== undefined) {
    (result as Record<string, unknown>).recommendation = f.recommendation
      ? redactHome(f.recommendation, home)
      : f.recommendation;
  }
  if (Object.hasOwn(f, 'path') || f.path !== undefined) {
    (result as Record<string, unknown>).path = f.path ? redactHome(f.path, home) : f.path;
  }

  return result;
}
