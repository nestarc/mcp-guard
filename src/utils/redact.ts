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
  return {
    ...f,
    message: redactHome(f.message, home),
    recommendation: f.recommendation ? redactHome(f.recommendation, home) : f.recommendation,
    path: f.path ? redactHome(f.path, home) : f.path,
  };
}
