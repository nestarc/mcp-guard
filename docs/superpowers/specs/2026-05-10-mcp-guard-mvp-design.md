---
title: mcp-guard MVP — Design Spec
status: Draft
date: 2026-05-10
related:
  - docs/handover.md
---

# mcp-guard MVP — Design Spec

본 문서는 [docs/handover.md](../../handover.md)를 기준점으로 채택하고, 구현 시 모호하거나 빠져 있던 영역을 명시화한 design spec이다. handover와 충돌하는 부분이 있으면 본 문서가 우선한다.

---

## 1. 목표

`mcp-guard scan` CLI로 MCP 서버 설정 파일을 정적 분석해 위험 패턴(시크릿 노출, 셸 실행, 동적 패키지 실행, 광범위 파일시스템 접근, 평문 HTTP, Docker 권한, 의심스러운 셸 파이프라인 등)을 식별하고, 사람이 읽을 수 있는 텍스트 또는 머신 읽기용 JSON 리포트를 출력한다. v0.1.0의 기능 범위는 단일 명령 `scan`으로 한정한다.

## 2. 비목표 (Non-goals)

- MCP 서버를 **실행**하거나 **연결**하지 않는다 (정적 스캔만).
- 네트워크 호출을 하지 않는다.
- 안전성을 **보장/인증**하지 않는다 ("certifies", "guarantees safe" 등 표현 금지).
- 본 사이클에 포함하지 않는 항목 (handover §13 future):
  - `mcp-guard detect` (자동 발견)
  - 디렉토리 / glob / stdin 입력
  - policy file / 룰 on-off
  - GitHub Action wrapper
  - VS Code 확장
  - SBOM / 패키지 출처 검사
  - **npm publish** (본 사이클은 코드 + CI까지)

## 3. 아키텍처

```
   ┌─────────┐      ┌────────────┐      ┌────────────┐
   │ cli.ts  │─────►│ loadConfig │─────►│ normalize  │
   └─────────┘      └────────────┘      └────────────┘
        │                                      │
        ▼                                      ▼
   ┌─────────┐      ┌────────────┐      ┌────────────┐
   │ exit    │◄─────│  reporter  │◄─────│ scanServer │
   │  code   │      │ (text/json)│      │  + rules   │
   └─────────┘      └────────────┘      └────────────┘
```

책임 분리:

- `loadConfig(path)`: 파일 읽기 + JSONC 파싱 → `unknown` raw
- `normalizeServers(raw)`: `mcpServers`/`servers` 추출 → `McpServerConfig[]`
- `scanServer(server, rules)`: 모든 룰을 적용해 `Finding[]` 산출
- `rules/*`: 각 룰은 순수 함수 `(server: McpServerConfig) => Finding[]`. 서로 독립.
- `reporter/text|json`: `ScanResult` → 문자열
- `cli.ts`: 옵션 파싱 + 출력 채널 선택 + exit code 결정

## 4. 모듈 분할

handover §7의 트리를 그대로 채택. 보강:

- `scanner/severity.ts` — severity 비교 / `summary.risk` 계산 / `--fail-on` 임계 비교
- `utils/redact.ts` — 홈 디렉토리 redaction (출력 단계에서만 적용)
- `utils/paths.ts` — broad-path 감지 helper (MCPG005에서 재사용)
- `utils/command.ts` — command basename + 확장자 제거 helper (MCPG002, MCPG003, MCPG006에서 재사용)

## 5. 입력 처리

### 5.1 `loadConfig(path)`

- `fs.promises.readFile`로 UTF-8 읽기.
- 파일 없음 / 권한 부족 → throw `LoadError` (CLI에서 catch 후 exit 2 + stderr).
- `jsonc-parser.parse`로 파싱. 파싱 에러 발생 시 라인/컬럼을 포함한 `LoadError` throw.
- 결과: `unknown`.

### 5.2 `normalizeServers(raw)`

- raw가 객체가 아니면 `LoadError` throw.
- `raw.mcpServers`(우선) 또는 `raw.servers`를 사용. 둘 다 없으면 빈 배열 + stderr 경고("no `mcpServers` or `servers` key found").
- entry 단위 zod 스키마:

  ```ts
  z.object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.unknown()).optional(),
    url: z.string().optional(),
    transport: z.string().optional(),
  }).passthrough()
  ```

- 검증 실패한 entry는 스킵하지 않고 `McpServerConfig`로 best-effort 매핑한다(누락 필드는 undefined). MCPG009가 그 결과를 잡아낸다.
- 출력 객체 형태:

  ```ts
  {
    name: string;          // map key
    command?: string;
    args?: string[];
    env?: Record<string, unknown>;
    url?: string;
    transport?: string;
    raw: unknown;          // 원본 entry 보존
  }
  ```

## 6. 룰 명세

각 룰은 `rules/*.ts` 한 파일이며 다음 인터페이스를 구현한다.

```ts
export interface Rule {
  id: string;                                  // 'MCPG001' 등
  run(server: McpServerConfig): Finding[];
}
```

룰 간 순서 무관. 동일 서버에서 여러 룰이 동시에 finding을 만들 수 있다.

| ID | 제목 | 기본 severity | 매칭 정의 |
|---|---|---|---|
| MCPG001 | Secret-like env vars | high | `env` key가 case-insensitive로 다음 중 하나에 매칭: substring `TOKEN` / `SECRET` / `PASSWORD` / `PASSWD` / `API_KEY` / `APIKEY` / `PRIVATE_KEY` / `CREDENTIAL` / `ACCESS_KEY`, 또는 prefix `AWS_` / `GCP_` / `GOOGLE_` / `AZURE_` / `OPENAI_` / `ANTHROPIC_` / `GITHUB_TOKEN` / `GITLAB_TOKEN`. 값이 빈 문자열, `${...}`, `<...>`, `your-*-here`, 또는 길이 < 8이면 severity를 medium으로 낮춘다. **값은 출력 어디에도 포함하지 않는다.** |
| MCPG002 | Shell execution command | high | `command` basename(확장자 제거, case-insensitive) ∈ `{bash, sh, zsh, fish, dash, ksh, cmd, powershell, pwsh}`. args에 `-c` / `/c` / `-e` / `--eval` / `--command`가 있으면 메시지에 그 사실을 명시. |
| MCPG003 | Dynamic package runner | medium | `command` basename ∈ `{npx, pnpx, bunx, uvx}`, 또는 `command` basename ∈ `{yarn, pnpm}` && `args`에 `dlx` 토큰 포함. |
| MCPG004 | Plain HTTP transport | medium | `url`이 string이고 `http://`로 시작. localhost / 127.0.0.1 / ::1 도 동일 severity (medium). |
| MCPG005 | Broad filesystem access | high | args 중 하나가 다음 중 하나에 매칭(좁은 하위 경로는 finding 만들지 않음): (a) 정확 매칭 `/`, `~`, `$HOME`, `%USERPROFILE%`; (b) 정확 매칭 `/Users`, `/home`; (c) 정확 매칭 `/Users/<segment>` 또는 `/home/<segment>` (즉 사용자 홈 자체); (d) 정규식 `^[a-zA-Z]:[\\/]?$` 매칭 (드라이브 루트, 예: `C:`, `C:\`, `D:/`); (e) 정규식 `^[a-zA-Z]:[\\/](Users[\\/][^\\/]+|Users)[\\/]?$` 매칭 (Windows 사용자 홈 자체); (f) args 토큰이 `..` 또는 그 chain (`../..` 등)과 정확 매칭. command/args에 `@modelcontextprotocol/server-filesystem`이 등장하면 메시지를 강화한다. |
| MCPG006 | Docker privileged / socket | high | `command` basename ∈ `{docker, podman}`이고 args 중에 다음 중 하나: `--privileged`; `-v` 다음 토큰이 `docker.sock` substring 포함; `-v` 다음 토큰이 `/:` prefix 또는 `/:/` substring 포함; `--mount` 다음 토큰에 `source=/var/run/docker.sock` 또는 `source=/` (root) 포함. |
| MCPG007 | Suspicious shell pipeline / download | critical | `[command, ...(args ?? [])].join(" ")` 합쳐 다음 정규식 중 하나라도 매칭: `(curl\|wget)\s+[^\|]+\|\s*(sh\|bash\|zsh\|fish)`, `\brm\s+-(rf\|fr)\b`, `\bchmod\s+\+x\b`. 매칭별로 별도 finding. |
| MCPG008 | Public remote endpoint | low | `url`이 `https://`로 시작하고 host가 localhost / loopback / RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) 가 아님. **HTTP는 MCPG004로만 보고**한다 (중복 방지). |
| MCPG009 | Missing explicit command/url | info | server entry에 `command`도 `url`도 없거나, `command`가 string이 아님. |

명령 basename 추출 규칙:

- POSIX 경로 → 마지막 `/` 이후
- Windows 경로 → 마지막 `\` 또는 `/` 이후
- 확장자 제거: `.exe`, `.cmd`, `.bat`, `.ps1`을 끝에서 제거
- 비교는 case-insensitive

## 7. severity & summary

```ts
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
const ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
```

- `summary.risk`: findings 중 ORDER 최댓값. findings가 없으면 `'info'`.
- `--fail-on <level>`: findings 중 `ORDER[finding.severity] >= ORDER[level]`인 것이 하나라도 있으면 exit 1. 옵션 미지정이면 항상 0 (parse/usage 에러 제외).

## 8. Reporter

### 8.1 Text reporter

- severity 색상: critical = red bold / high = red / medium = yellow / low = blue / info = dim.
- `--no-color`, `NO_COLOR` 환경변수, non-TTY (`process.stdout.isTTY === false`) 셋 중 하나라도 해당되면 색상 비활성.
- 헤더 라인:
  - `Risk: <UPPER>` (color 적용 가능)
  - `Servers scanned: N`
  - `Findings: M`
- 서버별 그룹. finding이 없는 서버는 출력 생략.
- finding 라인:

  ```
    [HIGH] MCPG005 Broad filesystem access
      Argument appears to grant broad file access: ~/
      Recommendation: restrict access to a project-specific directory.
  ```

- `--quiet`: 헤더만 출력, finding 라인 생략.

### 8.2 JSON reporter

- 항상 색상 없음, `--quiet` 무관하게 전체 출력.
- 형태:

  ```json
  {
    "schemaVersion": "1",
    "target": "<absolute path, redacted>",
    "summary": {
      "risk": "high",
      "serversScanned": 2,
      "findings": 4
    },
    "findings": [
      {
        "ruleId": "MCPG005",
        "severity": "high",
        "server": "filesystem",
        "title": "Broad filesystem access",
        "message": "Argument appears to grant broad file access: ~/",
        "recommendation": "Restrict access to a project-specific directory.",
        "path": "mcpServers.filesystem.args[2]"
      }
    ]
  }
  ```

- `path`는 best-effort. jsonc-parser가 위치를 줄 수 있는 경우에만 채운다. 누락은 허용.

## 9. Redaction

- 홈 디렉토리:
  - POSIX: `os.homedir()` (`/Users/<user>` 또는 `/home/<user>`)
  - Windows: `os.homedir()` (`C:\Users\<user>`)
- 매칭 시 `~`로 치환. 다른 사용자 경로(`/Users/other`)는 변경하지 않음.
- 적용 위치: 모든 reporter 출력의 `message`, `recommendation`, `path`, `target`. text와 JSON 동일하게 적용.
- 시크릿 값: 룰이 message에 절대 포함시키지 않는다 (값을 인용하는 finding 메시지 자체를 작성하지 않는 것이 원칙). 테스트로 회귀 방지.

## 10. CLI

### 10.1 명령

```
mcp-guard scan <path> [options]
```

`<path>`는 단일 파일 경로. 디렉토리/glob/stdin은 본 사이클 미지원.

### 10.2 옵션

| 옵션 | 설명 |
|---|---|
| `--json` | JSON 출력 |
| `--fail-on <level>` | `info` / `low` / `medium` / `high` / `critical`. 잘못된 값이면 exit 2. |
| `--no-color` | 색상 비활성 |
| `--quiet` | 텍스트 reporter에서 헤더만 출력 (JSON에는 영향 없음) |
| `--version`, `--help` | commander 기본 |

### 10.3 exit code

- `0` — 성공. fail-on 미충족 또는 옵션 미지정.
- `1` — fail-on 임계 도달.
- `2` — usage error / 파일 없음 / parse error / 잘못된 옵션 값.

### 10.4 채널

- stdout — 리포트 본체 (text 또는 JSON)
- stderr — 경고 / 에러 / parse 에러 메시지

## 11. CI

`.github/workflows/ci.yml`:

- 트리거: `pull_request`, `push` to `main`
- matrix: Node 20, 22 on Ubuntu latest
- 단계:
  1. `actions/checkout@v4`
  2. `pnpm/action-setup@v3` (pnpm 9)
  3. `actions/setup-node@v4` (cache: `pnpm`)
  4. `pnpm install --frozen-lockfile`
  5. `pnpm typecheck`
  6. `pnpm test`
  7. `pnpm build`

캐시는 setup-node의 pnpm cache로 충분. publish/release 단계 없음.

## 12. 테스트

vitest. `test/` 아래 `*.test.ts`.

### 12.1 fixture

| 파일 | 목적 |
|---|---|
| `fixtures/safe.json` | handover §12 그대로. high 이상 finding 없음. |
| `fixtures/risky.json` | handover §12 그대로. MCPG001/002/003/004/005/007 동시 트리거. |
| `fixtures/jsonc.jsonc` | JSONC 주석 포함. parse 정상화 검증. |
| `fixtures/empty.json` | `{}`. 빈 결과 + stderr 경고. |
| `fixtures/malformed.json` | invalid JSON. exit 2 + stderr. |
| `fixtures/missing-cmd.json` | command/url 없음. MCPG009 트리거. |
| `fixtures/placeholder-secret.json` | env에 `TOKEN: "${TOKEN}"`. MCPG001 medium. |
| `fixtures/docker-socket.json` | MCPG006 트리거. |
| `fixtures/pipeline-curl.json` | MCPG007 트리거. |
| `fixtures/public-https.json` | MCPG008 low (HTTPS + 외부 호스트). |

### 12.2 테스트 카테고리

- 룰 단위 — 각 룰 모듈별 finding 산출/비산출 케이스
- normalize 단위 — `mcpServers` vs `servers`, 잘못된 entry 처리
- reporter 단위 — text ANSI on/off, JSON shape, redaction 적용 여부
- redact 단위 — Windows / POSIX 경로 mock으로 양쪽 검증
- CLI 통합 — 자식 프로세스로 spawn하여 exit code / stdout / stderr 검증
- **secret leak guard** — risky.json 스캔 출력(text + JSON 양쪽) 어디에도 토큰 값 substring(`ghp_should_not_be_printed`)이 등장하지 않음을 단언

## 13. Future (out of scope)

handover §13 그대로. 본 사이클에서 손대지 않음.

## 14. Open risks / 가정

- **Windows 경로 처리** — MCPG005의 드라이브 letter 매칭은 case-insensitive(`c:\`, `D:/`도). 백슬래시/포워드슬래시 모두 허용.
- **MCPG001 false positive** — 짧은/플레이스홀더 값을 medium으로 낮추는 정책으로 일부 완화. entropy 기반 검사는 future.
- **MCPG007 정규식 우회** — 셸 메타문자 분리, base64 디코드, eval 등은 탐지 불가. 한계 명시.
- **command basename 추출** — 경로 (`/usr/bin/bash`) 또는 확장자 (`bash.exe`) 처리는 §6 말미 규칙으로 통일.
- **JSON path tracking** — jsonc-parser의 location API로 best-effort. 누락 시 finding은 여전히 유효해야 한다 (`path`는 optional).
- **`pnpm` 부재 환경** — README에 `corepack enable` 안내 추가. CI에는 pnpm action으로 명시 설치.

## 15. v0.1.0 완료 정의 (Done)

다음이 모두 통과해야 v0.1.0 PR 머지 가능:

1. `pnpm install --frozen-lockfile && pnpm typecheck && pnpm test && pnpm build` 모두 성공.
2. `pnpm dev scan test/fixtures/risky.json`이 §6의 트리거 룰 모두를 보고 (최소 MCPG001/002/003/004/005/007).
3. `pnpm dev scan test/fixtures/risky.json --json`이 valid JSON이고 `schemaVersion: "1"` 포함.
4. `pnpm dev scan test/fixtures/safe.json --fail-on high` → exit 0.
5. `pnpm dev scan test/fixtures/risky.json --fail-on high` → exit 1.
6. 시크릿 값(`ghp_should_not_be_printed`)이 출력 어디에도 등장하지 않음 (자동 테스트로 검증).
7. README가 실제 명령/예시를 반영 (handover §10 outline 기반).
8. CI가 `main` push와 PR에서 모두 green.
