import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Adapted from qualified Contracts PR7; Kernel has one quality job.
export const requiredParents = Object.freeze(['quality']);
export const requiredJobs = Object.freeze(['quality']);
const repository = 'neverhuman/jankurai-tools-analyzers';
const workflowPath = '.github/workflows/ci.yml';
// Matches the GitHub Actions producer required by protected main.
const producer = Object.freeze({ id: 15368, slug: 'github-actions' });

export function parseUniqueJson(raw) {
  const value = JSON.parse(raw);
  // JSON.parse silently replaces duplicate keys. Inspect the already valid
  // string/punctuation tokens, including escaped spellings of the same key.
  const scopes = [];
  for (const token of raw.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]/g) ?? []) {
    if (token === '{' || token === '[') {
      scopes.push({ object: token === '{', key: token === '{', seen: new Set() });
    } else if (token === '}' || token === ']') {
      scopes.pop();
    } else {
      const scope = scopes.at(-1);
      if (token === ',' && scope?.object) scope.key = true;
      if (token.startsWith('"') && scope?.object && scope.key) {
        const key = JSON.parse(token);
        if (scope.seen.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        scope.seen.add(key);
        scope.key = false;
      }
    }
  }
  return value;
}

export function validateParents(jobs) {
  if (requiredParents.length === 0 || !jobs || Array.isArray(jobs) || typeof jobs !== 'object' ||
      JSON.stringify(Object.keys(jobs).sort()) !== JSON.stringify(requiredParents)) {
    throw new Error('required parent inventory must be exactly quality');
  }
  for (const name of requiredParents) {
    const job = jobs[name];
    if (!job || Array.isArray(job) || typeof job !== 'object' || job.result !== 'success') {
      throw new Error(`required parent did not succeed: ${name}`);
    }
  }
}

export function validateExpandedJobs(payload, runId, head, attempt) {
  if (!/^[1-9][0-9]*$/.test(runId) || !Number.isSafeInteger(Number(runId))
      || !/^[1-9][0-9]*$/.test(attempt ?? '') || !Number.isSafeInteger(Number(attempt))
      || !/^[a-f0-9]{40}$/.test(head)) {
    throw new Error('missing valid workflow run/attempt/source identity');
  }
  if (requiredJobs.length === 0 || !payload || !Array.isArray(payload.jobs) || !Number.isSafeInteger(payload.total_count) ||
      payload.total_count !== payload.jobs.length || payload.total_count === 0) {
    throw new Error('incomplete or malformed hosted job inventory');
  }
  const names = new Set(), ids = new Set();
  for (const job of payload.jobs) {
    if (!job || typeof job !== 'object' || !Number.isSafeInteger(job.id) || job.id <= 0 ||
        String(job.run_id) !== runId || job.run_attempt !== Number(attempt) || job.head_sha !== head ||
        typeof job.name !== 'string' || ids.has(job.id) || names.has(job.name)) {
      throw new Error('duplicate, malformed, or foreign hosted job');
    }
    ids.add(job.id);
    names.add(job.name);
    if (requiredJobs.includes(job.name)) {
      if (job.status !== 'completed' || job.conclusion !== 'success') {
        throw new Error(`required hosted job did not succeed: ${job.name}`);
      }
    } else if (!['jankurai-tools-analyzers/required', 'publish-ci-tag'].includes(job.name)) {
      throw new Error(`unexpected hosted job: ${job.name}`);
    }
  }
  for (const name of requiredJobs) {
    if (!names.has(name)) throw new Error(`missing required hosted job: ${name}`);
  }
}

export function validateRun(run, workflow, runId, head, attempt) {
  if (!run || !workflow || String(run.id) !== runId || run.head_sha !== head ||
      run.run_attempt !== Number(attempt) || run.repository?.full_name !== repository ||
      run.path !== workflowPath || workflow.path !== workflowPath ||
      !Number.isSafeInteger(workflow.id) || workflow.id <= 0 || run.workflow_id !== workflow.id ||
      !Number.isSafeInteger(run.check_suite_id) || run.check_suite_id <= 0) {
    throw new Error('foreign workflow, repository, source or run attempt');
  }
}

export function checkEndpoint(job) {
  const prefix = `https://api.github.com/repos/${repository}/check-runs/`;
  if (typeof job.check_run_url !== 'string' || !job.check_run_url.startsWith(prefix) ||
      !/^[1-9][0-9]*$/.test(job.check_run_url.slice(prefix.length))) {
    throw new Error('missing or foreign check producer endpoint');
  }
  return job.check_run_url.slice('https://api.github.com/'.length);
}

export function validateProducer(check, job, run) {
  const endpoint = checkEndpoint(job);
  if (!check || !Number.isSafeInteger(check.id) || check.id <= 0 ||
      endpoint !== `repos/${repository}/check-runs/${check.id}` ||
      check.app?.id !== producer.id || check.app?.slug !== producer.slug ||
      check.check_suite?.id !== run.check_suite_id || check.head_sha !== run.head_sha ||
      check.name !== job.name || check.status !== 'completed' || check.conclusion !== 'success') {
    throw new Error(`required check has an invalid producer or result: ${job.name}`);
  }
}

function api(endpoint) {
  const result = spawnSync('gh', ['api', '--hostname', 'github.com', endpoint], {
    encoding: 'utf8', timeout: 20000, maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error('cannot read hosted qualification evidence');
  return parseUniqueJson(result.stdout);
}

function main(args) {
  if (args.length > 1 || (args.length === 1 && args[0] !== '--hosted')) {
    throw new Error('usage: aggregate.sh [--hosted]');
  }
  validateParents(parseUniqueJson(process.env.NEEDS_JSON ?? ''));
  if (args[0] === '--hosted') {
    const { GITHUB_REPOSITORY: repo, GITHUB_RUN_ID: runId, GITHUB_RUN_ATTEMPT: attempt,
      EXPECTED_HEAD_SHA: head, GH_TOKEN: token } = process.env;
    if (repo !== repository || !/^[1-9][0-9]*$/.test(runId ?? '') ||
        !Number.isSafeInteger(Number(runId)) || !/^[1-9][0-9]*$/.test(attempt ?? '') ||
        !Number.isSafeInteger(Number(attempt)) ||
        !/^[a-f0-9]{40}$/.test(head ?? '') || !token) {
      throw new Error('hosted aggregate requires the authenticated run/source identity');
    }
    const run = api(`repos/${repo}/actions/runs/${runId}/attempts/${attempt}`);
    const workflow = api(`repos/${repo}/actions/workflows/ci.yml`);
    validateRun(run, workflow, runId, head, attempt);
    // The expected inventory is smaller than one page. Reject truncation or
    // unexpected expansion, rather than trusting an incomplete page of jobs.
    const jobs = api(`repos/${repo}/actions/runs/${runId}/attempts/${attempt}/jobs?per_page=100`);
    validateExpandedJobs(jobs, runId, head, attempt);
    for (const job of jobs.jobs.filter(job => requiredJobs.includes(job.name))) {
      validateProducer(api(checkEndpoint(job)), job, run);
    }
  }
  console.log('complete required lane inventory passed');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
