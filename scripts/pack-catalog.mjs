#!/usr/bin/env node
/**
 * 카탈로그 생성·검사기 (S463).
 *
 * `catalog/<id>/` 를 훑어 `index.json` 을 만든다. 앱은 그 파일 **하나만** 받아 목록을 그리므로
 * (비로그인 raw fetch 1회), 여기서 만들지 않으면 앱이 레포 트리를 걸어 다녀야 한다.
 *
 * 하는 일 셋:
 *   1. **구조 검사** — `pack.json` 의 필수 칸 · 파일 실재 · 묶음이 스스로 완결하는가(부르는
 *      에이전트·자식 워크플로우가 묶음 안에 있는가).
 *   2. **위험 스캔과 신고 대조** — 정의를 읽어 `shell` 수와 밖으로 나가는 스텝을 **직접 센 뒤**
 *      `pack.json` 의 `risk` 와 맞춰 본다. 어긋나면 실패한다. POLICY.md §3 의 「신고와 실제가
 *      다르면 거절」이 집행되는 자리다.
 *   3. **`index.json` 생성** — 파일 목록 · sha256 · 위험 요약 · 비파일 의존 선언.
 *
 * 정의 자체의 문법·액션 입력 검사는 **여기서 하지 않는다.** 그건 앱이 가져오기 직전에
 * `validateWorkflowBundle` 로 한다 — 규칙을 두 곳에 두면 한쪽이 「통과」라고 한 것을 다른 쪽이
 * 거절한다. 이 레포는 앱의 비공개 소스를 가져올 수 없기도 하다.
 *
 * 쓰는 법:
 *   node scripts/pack-catalog.mjs            # index.json 을 다시 쓴다
 *   node scripts/pack-catalog.mjs --check    # 쓰지 않고, 지금 index.json 이 최신인지만 본다(CI)
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { parse as parseYaml } from 'yaml';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const CATALOG = join(ROOT, 'catalog');
const INDEX = join(ROOT, 'index.json');
const CHECK = process.argv.includes('--check');

/** 스텝 객체에서 액션 이름이 아닌 칸. 나머지 키 하나가 액션이다. */
const STEP_META = new Set(['as', 'label', 'when', 'loop', 'output', 'retry', 'timeoutSec', 'optional']);

/**
 * 밖으로 나가는 액션. POLICY.md §3 의 신고 대상과 같은 목록이어야 한다 —
 * 늘리면 정책 문서도 같이 고친다.
 */
const OUTBOUND_PREFIX = ['gh.', 'slack.', 'jira.'];

/**
 * `shell` 명령 안에서 **밖으로 나가는** 것과 **민감한 자리를 읽는** 것.
 * 완전하지 않다(변수로 감추면 못 잡는다) — 그래서 이것은 리뷰어를 돕는 장치이지
 * 리뷰를 대신하는 장치가 아니다. POLICY.md §6 이 사람의 검토를 필수로 두는 이유다.
 */
const NET_RE = /\b(curl|wget|nc|ncat|ssh|scp|rsync|git\s+push|npm\s+publish|gh\s+api)\b/;
const SECRET_RE = /(secrets\.json|\.ssh\b|security\s+find-generic-password|Keychain|~\/\.aws|\.netrc)/;
const OBFUSCATED_RE = /(base64\s+-{1,2}d|\|\s*(sh|bash)\b|eval\s)/;

const errors = [];
const warns = [];
const fail = (pack, msg) => errors.push(`${pack}: ${msg}`);
const warn = (pack, msg) => warns.push(`${pack}: ${msg}`);

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** 묶음 폴더 안의 모든 파일을 묶음 기준 상대 경로로 (정렬해서) 낸다. */
function listFiles(dir, base = dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p, base));
    else out.push(relative(base, p));
  }
  return out;
}

/** 스텝 하나에서 액션 이름을 집는다. 없으면 null. */
function actionOf(step) {
  if (step === null || typeof step !== 'object') return null;
  for (const k of Object.keys(step)) if (!STEP_META.has(k)) return k;
  return null;
}

/**
 * 정의를 읽어 **실제** 위험을 센다. 반환: `{ shell, outbound: [{step, action, why}], flags }`.
 * `step` 은 1부터 센 스텝 번호다 — 사람이 리뷰에서 가리키는 번호와 같아야 한다.
 */
function scanRisk(def) {
  const steps = Array.isArray(def?.steps) ? def.steps : [];
  const out = { shell: 0, outbound: [], flags: [] };
  steps.forEach((step, i) => {
    const action = actionOf(step);
    if (!action) return;
    const n = i + 1;
    if (action === 'shell') {
      out.shell += 1;
      const cmd = String(step.shell?.cmd ?? '');
      if (NET_RE.test(cmd)) {
        out.outbound.push({ step: n, action: 'shell', why: (cmd.match(NET_RE) ?? [''])[0].trim() });
      }
      if (SECRET_RE.test(cmd)) out.flags.push(`${n}번 스텝의 shell 이 민감한 자리를 읽습니다`);
      if (OBFUSCATED_RE.test(cmd)) out.flags.push(`${n}번 스텝의 shell 에 읽을 수 없는 명령이 있습니다`);
      if (step.shell?.env && typeof step.shell.env === 'object') {
        for (const v of Object.values(step.shell.env)) {
          if (typeof v === 'string' && v.startsWith('secret:')) {
            out.flags.push(`${n}번 스텝이 secrets.json 의 값을 환경변수로 넣습니다 (${v})`);
          }
        }
      }
    }
    if (OUTBOUND_PREFIX.some((p) => action.startsWith(p))) {
      out.outbound.push({ step: n, action, why: action });
    }
  });
  return out;
}

/** 정의가 부르는 것 — 에이전트 · 자식 워크플로우 · 팀. */
function scanRefs(def) {
  const steps = Array.isArray(def?.steps) ? def.steps : [];
  const refs = { agents: new Set(), workflows: new Set(), teams: new Set() };
  for (const step of steps) {
    const action = actionOf(step);
    if (!action) continue;
    const p = step[action];
    if (action === 'agent.prompt' && typeof p?.agent === 'string') refs.agents.add(p.agent);
    if (action === 'workflow.spawn' && typeof p?.workflow === 'string') refs.workflows.add(p.workflow);
    if (action === 'team.run' && typeof p?.team === 'string') refs.teams.add(p.team);
  }
  return refs;
}

function readPack(id) {
  const dir = join(CATALOG, id);
  const packPath = join(dir, 'pack.json');
  if (!existsSync(packPath)) {
    fail(id, 'pack.json 이 없습니다');
    return null;
  }
  let pack;
  try {
    pack = JSON.parse(readFileSync(packPath, 'utf8'));
  } catch (e) {
    fail(id, `pack.json 을 읽지 못했습니다 — ${e.message}`);
    return null;
  }
  for (const k of ['id', 'title', 'description', 'version']) {
    if (typeof pack[k] !== 'string' || pack[k] === '') fail(id, `pack.json 의 \`${k}\` 가 비어 있습니다`);
  }
  if (pack.id !== id) fail(id, `pack.json 의 id(${pack.id})가 폴더 이름(${id})과 다릅니다`);
  if (!/^\d+\.\d+\.\d+$/.test(pack.version ?? '')) fail(id, `version 은 semver 여야 합니다 — ${pack.version}`);

  const files = listFiles(dir).filter((f) => f !== 'pack.json');
  if (files.length === 0) fail(id, '정의 파일이 하나도 없습니다');

  // 워크플로우 정의(있으면 하나)
  const wfFile = files.find((f) => f === 'workflow.yaml' || f === 'workflow.yml');
  let def = null;
  if (wfFile) {
    try {
      def = parseYaml(readFileSync(join(dir, wfFile), 'utf8'));
    } catch (e) {
      fail(id, `${wfFile} 를 읽지 못했습니다 — ${e.message}`);
    }
  }

  // ── 스스로 완결하는가 ────────────────────────────────────────────────
  // 묶음 안에 없는 것을 부르면 받는 쪽에서 「이 파일이 빠졌습니다」가 뜬다. 앱 기본 제공 정의를
  // 부르는 것은 괜찮지만, **그 사실을 적게** 한다(`usesBundled`) — 적지 않으면 빠뜨린 것과
  // 구별되지 않는다.
  const bundled = new Set(Array.isArray(pack.usesBundled) ? pack.usesBundled : []);
  if (def) {
    const refs = scanRefs(def);
    const have = new Set(files.filter((f) => f.startsWith('agents/')).map((f) => f.slice('agents/'.length).replace(/\.md$/, '')));
    for (const a of refs.agents) {
      if (!have.has(a) && !bundled.has(a)) {
        fail(id, `에이전트 \`${a}\` 를 부르는데 묶음에 없습니다 — agents/${a}.md 를 담거나 usesBundled 에 적으세요`);
      }
    }
    const haveWf = new Set(files.filter((f) => f.endsWith('.yaml') && f !== wfFile).map((f) => f.replace(/\.ya?ml$/, '')));
    for (const w of refs.workflows) {
      if (!haveWf.has(w) && !bundled.has(w)) {
        fail(id, `워크플로우 \`${w}\` 를 spawn 하는데 묶음에 없습니다 — 담거나 usesBundled 에 적으세요`);
      }
    }
    for (const t of refs.teams) {
      if (!files.includes(`teams/${t}.yaml`) && !bundled.has(t)) {
        fail(id, `팀 \`${t}\` 을 부르는데 묶음에 없습니다 — 담거나 usesBundled 에 적으세요`);
      }
    }
  }

  // ── 위험: 신고와 실제를 맞춘다 (POLICY.md §3) ─────────────────────────
  const actual = def ? scanRisk(def) : { shell: 0, outbound: [], flags: [] };
  const declared = pack.risk ?? {};
  const declaredShell = Number(declared.shell ?? 0);
  if (declaredShell !== actual.shell) {
    fail(id, `risk.shell 신고가 ${declaredShell} 인데 실제는 ${actual.shell} 입니다`);
  }
  const declaredOut = new Set((Array.isArray(declared.outbound) ? declared.outbound : []).map((o) => Number(o.step)));
  for (const o of actual.outbound) {
    if (!declaredOut.has(o.step)) {
      fail(id, `${o.step}번 스텝이 밖으로 나가는데(${o.why}) risk.outbound 에 없습니다`);
    }
  }
  for (const s of declaredOut) {
    if (!actual.outbound.some((o) => o.step === s)) {
      warn(id, `risk.outbound 에 ${s}번이 적혀 있는데 스캐너는 못 찾았습니다 — 변수로 감춘 자리라면 그대로 두세요`);
    }
  }
  for (const f of actual.flags) warn(id, f);

  return {
    id,
    title: pack.title,
    description: pack.description,
    version: pack.version,
    ...(pack.author ? { author: pack.author } : {}),
    ...(pack.pr ? { pr: pack.pr } : {}),
    requires: {
      setup: pack.requires?.setup ?? [],
      mcp: pack.requires?.mcp ?? [],
      skill: pack.requires?.skill ?? [],
    },
    usesBundled: [...bundled].sort(),
    risk: { shell: actual.shell, outbound: actual.outbound },
    files: files.map((f) => ({ path: f, sha256: sha256(join(dir, f)) })),
  };
}

const ids = existsSync(CATALOG)
  ? readdirSync(CATALOG)
      .filter((n) => !n.startsWith('.') && statSync(join(CATALOG, n)).isDirectory())
      .sort()
  : [];

const packs = ids.map(readPack).filter(Boolean);

for (const w of warns) console.warn(`경고 — ${w}`);
if (errors.length > 0) {
  for (const e of errors) console.error(`오류 — ${e}`);
  console.error(`\n${errors.length}건이 막습니다. POLICY.md 를 보세요.`);
  process.exit(1);
}

// `generatedAt` 은 넣지 않는다 — 돌릴 때마다 바뀌면 `--check` 가 늘 「오래됐다」고 한다.
const next = JSON.stringify({ schema: 1, packs }, null, 2) + '\n';

if (CHECK) {
  const cur = existsSync(INDEX) ? readFileSync(INDEX, 'utf8') : '';
  if (cur !== next) {
    console.error('오류 — index.json 이 catalog/ 와 다릅니다. `npm run index` 를 돌리고 그 결과를 커밋하세요.');
    process.exit(1);
  }
  console.log(`index.json 최신 · 묶음 ${packs.length}`);
} else {
  writeFileSync(INDEX, next);
  console.log(`index.json 썼습니다 · 묶음 ${packs.length}`);
}
