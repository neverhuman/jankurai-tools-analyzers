import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { checkEndpoint, parseUniqueJson, requiredJobs, validateExpandedJobs, validateProducer, validateRun } from './ci-aggregate.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const lanes = ['quality'];

function aggregate(value) {
  const result = spawnSync('bash', [path.join(root, 'ops/ci/aggregate.sh')], {
    encoding: 'utf8',
    env: { ...process.env, NEEDS_JSON: value },
  });
  assert.ifError(result.error);
  return result.status === 0;
}

const success = { result: 'success', outputs: {} };
const successfulJobs = Object.fromEntries(lanes.map((lane) => [lane, success]));

test('successful quality lane passes', () => {
  assert.equal(aggregate(JSON.stringify(successfulJobs)), true);
});

for (const [name, value] of [
  ['empty object', '{}'],
  ['empty array', '[]'],
  ['null', 'null'],
  ['string', '"success"'],
  ['boolean', 'true'],
  ['number', '0'],
  ['missing input', ''],
  ['malformed JSON', '{'],
  ['multiple JSON values', '{}\n{}'],
  ['renamed job', JSON.stringify({ audit: success })],
  ['wrong name complete-quality-gates', JSON.stringify({ 'complete-quality-gates': success })],
  ['extra job', JSON.stringify({ ...successfulJobs, extra: success })],
  ['successful array', JSON.stringify([success])],
  ['duplicate job', '{"quality":{"result":"failure"},"quality":{"result":"success"}}'],
  ['duplicate result', '{"quality":{"result":"failure","result":"success"}}'],
  ['escaped duplicate job', '{"quality":{"result":"failure"},"qu\\u0061lity":{"result":"success"}}'],
  ['escaped duplicate result', '{"quality":{"result":"failure","r\\u0065sult":"success"}}'],
]) {
  test(`required aggregate rejects ${name}`, () => assert.equal(aggregate(value), false));
}

test('quoted punctuation and independent nested keys are valid payload data', () => {
  assert.equal(aggregate(JSON.stringify({quality: {result: 'success', outputs: {
    quoted: '\"result\":\"failure\",{[}', records: '[{"same":1},{"same":2}]',
    nested: [{same: 1}, {same: 2}],
  }}})), true);
});

for (const lane of lanes) {
  test(`required aggregate rejects missing ${lane}`, () => {
    assert.equal(aggregate('{}'), false);
  });
  for (const value of [
    null,
    [],
    'success',
    {},
    { result: true },
    { result: 0 },
    ...['failure', 'cancelled', 'skipped', 'pending', 'neutral', 'timed_out'].map(
      (result) => ({ result }),
    ),
  ]) {
    test(`required aggregate rejects ${lane} outcome ${JSON.stringify(value)}`, () => {
      const jobs = { ...successfulJobs, [lane]: value };
      assert.equal(aggregate(JSON.stringify(jobs)), false);
    });
  }
}

function assertWorkflowLanes(source) {
  // Keep this deliberately narrow: a workflow layout change requires review.
  const jobs = [...source.matchAll(/^  ([\w-]+):$/gm)].map((match) => match[1]);
  assert.deepEqual(jobs, ['push', 'pull_request', 'workflow_dispatch', 'quality', 'required', 'publish-ci-tag']);
  assert.match(source, /^    name: quality$/m);
  assert.match(source, /^    needs: quality$/m);
  assert.doesNotMatch(source, /^    strategy:/m);
  assert.match(source, /^          EXPECTED_HEAD_SHA: \$\{\{ github.event.pull_request.head.sha \|\| github.sha \}\}$/m);
  assert.match(source, /^      actions: read$/m);
  assert.match(source, /^      checks: read$/m);
  assert.match(source, /^      - run: bash ops\/ci\/github-check\.sh$/m);
  assert.match(source, /^    if: always\(\)$/m);
  assert.match(source, /^      - run: node --test scripts\/ci-aggregate\.test\.mjs$/m);
  assert.match(source, /^      - run: bash ops\/ci\/aggregate\.sh --hosted$/m);
}

test('workflow retains the quality lane and always-run aggregate', () => {
  assertWorkflowLanes(workflow);
});

test('workflow mutations removing quality or always() are rejected', () => {
  for (const changed of [
    workflow.replace('needs: quality', 'needs: []'),
    workflow.replace('  quality:', '  renamed-quality:'),
    workflow.replace('    needs: quality', '    strategy: {}\n    needs: quality'),
    workflow.replace('bash ops/ci/aggregate.sh --hosted', 'bash ops/ci/aggregate.sh'),
    workflow.replace('bash ops/ci/github-check.sh', 'true'),
    workflow.replace('needs: quality', 'needs: audit'),
    workflow.replace(/\n  quality:\n[\s\S]*?(?=\n  required:)/, '\n'),
    workflow.replace(/^    if: always\(\)\n/m, ''),
    workflow.replace('name: quality', 'name: renamed-quality'),
    workflow.replace('checks: read', 'checks: none'),
    workflow.replace('node --test scripts/ci-aggregate.test.mjs', 'true'),
    workflow.replace('bash ops/ci/aggregate.sh', 'bash ops/ci/required.sh'),
  ]) {
    assert.notEqual(changed, workflow);
    assert.throws(() => assertWorkflowLanes(changed));
  }
});

const runId = '123', head = 'a'.repeat(40), attempt = '2';
function hosted() {
  const jobs = requiredJobs.map((name, i) => ({id:i + 1, name, run_id:123, run_attempt:2, head_sha:head, status:'completed', conclusion:'success',
    check_run_url:`https://api.github.com/repos/neverhuman/jankurai-tools-analyzers/check-runs/${i + 1}`}));
  return { total_count:jobs.length, jobs };
}

test('expanded inventory permits every successful lane and conditional publication', () => {
  validateExpandedJobs(hosted(), runId, head, attempt);
  const payload = hosted();
  payload.jobs.push({id:5, name:'publish-ci-tag', run_id:123, run_attempt:2, head_sha:head, status:'completed', conclusion:'skipped'});
  payload.total_count++;
  validateExpandedJobs(payload, runId, head, attempt);
  assert.deepEqual(parseUniqueJson('{"nested":[{"same":1},{"same":2}],"quoted":"\\\"{,}"}').nested, [{same:1},{same:2}]);
});

for (const name of requiredJobs) for (const mutation of ['missing', 'renamed', 'failure', 'cancelled', 'skipped', 'in_progress']) {
  test(`expanded inventory rejects ${name}: ${mutation}`, () => {
    const payload = hosted(), job = payload.jobs.find(job => job.name === name);
    if (mutation === 'missing') payload.jobs = payload.jobs.filter(candidate => candidate !== job);
    else if (mutation === 'renamed') job.name += '-renamed';
    else if (mutation === 'in_progress') job.status = mutation;
    else job.conclusion = mutation;
    payload.total_count = payload.jobs.length;
    assert.throws(() => validateExpandedJobs(payload, runId, head, attempt));
  });
}

for (const mutation of ['duplicate-id', 'duplicate-name', 'wrong-head', 'wrong-run', 'wrong-attempt', 'missing-attempt', 'string-attempt', 'truncated', 'empty']) {
  test(`expanded inventory rejects ${mutation}`, () => {
    const payload = hosted();
    if (mutation === 'duplicate-id') { payload.jobs.push({...payload.jobs[0], name:'publish-ci-tag'}); payload.total_count++; }
    if (mutation === 'duplicate-name') { payload.jobs.push({...payload.jobs[0], id:2}); payload.total_count++; }
    if (mutation === 'wrong-head') payload.jobs[0].head_sha = 'b'.repeat(40);
    if (mutation === 'wrong-run') payload.jobs[0].run_id++;
    if (mutation === 'wrong-attempt') payload.jobs[0].run_attempt--;
    if (mutation === 'missing-attempt') delete payload.jobs[0].run_attempt;
    if (mutation === 'string-attempt') payload.jobs[0].run_attempt = '2';
    if (mutation === 'truncated') payload.total_count++;
    if (mutation === 'empty') { payload.jobs = []; payload.total_count = 0; }
    assert.throws(() => validateExpandedJobs(payload, runId, head, attempt));
  });
}

test('expanded inventory requires an explicit safe run attempt', () => {
  for (const invalid of [undefined, '', '0', '-1', '1.5', '9007199254740992']) {
    assert.throws(() => validateExpandedJobs(hosted(), runId, head, invalid));
  }
  assert.throws(() => validateExpandedJobs(hosted(), '9007199254740992', head, attempt));
});

const workflowIdentity = { id: 456, path: '.github/workflows/ci.yml' };
function runIdentity() {
  return { id:123, head_sha:head, run_attempt:2, repository:{full_name:'neverhuman/jankurai-tools-analyzers'},
    workflow_id:456, path:workflowIdentity.path, check_suite_id:789 };
}
function checkIdentity() {
  return { id:1, name:'quality', head_sha:head, status:'completed', conclusion:'success',
    app:{id:15368, slug:'github-actions'}, check_suite:{id:789} };
}

test('run and check evidence must belong to the configured workflow and producer', () => {
  const run = runIdentity(), job = hosted().jobs[0];
  validateRun(run, workflowIdentity, runId, head, attempt);
  validateProducer(checkIdentity(), job, run);
  for (const change of [
    {id:124}, {head_sha:'b'.repeat(40)}, {run_attempt:1}, {repository:{full_name:'other/repo'}},
    {workflow_id:457}, {path:'.github/workflows/other.yml'}, {check_suite_id:0},
  ]) assert.throws(() => validateRun({...run, ...change}, workflowIdentity, runId, head, attempt));
  for (const change of [{id:457}, {id:'456'}, {path:'.github/workflows/other.yml'}]) {
    assert.throws(() => validateRun(run, {...workflowIdentity, ...change}, runId, head, attempt));
  }
  for (const change of [
    {id:2}, {app:{id:1, slug:'github-actions'}}, {app:{id:15368, slug:'other-app'}},
    {app:null}, {check_suite:{id:790}}, {head_sha:'b'.repeat(40)}, {name:'other'},
    {status:'in_progress'}, ...['failure','cancelled','skipped',null].map(conclusion => ({conclusion})),
  ]) assert.throws(() => validateProducer({...checkIdentity(), ...change}, job, run));
});

test('producer endpoints cannot redirect credentials to another repository or server', () => {
  const job = hosted().jobs[0];
  for (const url of [undefined, '', job.check_run_url + '?query=1', job.check_run_url + '/..',
    job.check_run_url.replace('api.github.com', 'example.invalid'),
    job.check_run_url.replace('jankurai-tools-analyzers', 'other-repo')]) {
    assert.throws(() => checkEndpoint({...job, check_run_url:url}));
  }
});

test('hosted command requests the current attempt and rejects incomplete admission', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-aggregate-api-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const requested = path.join(directory, 'requested.json');
  fs.writeFileSync(path.join(directory, 'gh'), `#!${process.execPath}\n` +
    'const args = process.argv.slice(2);\n' +
    'require("fs").appendFileSync(process.env.REQUESTED_API, JSON.stringify(args) + "\\n");\n' +
    'const key = args.at(-1).split("/").slice(3).join("/");\n' +
    'const response = JSON.parse(process.env.FIXTURE_RESPONSES)[key];\n' +
    'if (!response) process.exit(22);\n' +
    'process.stdout.write(JSON.stringify(response));\n', { mode: 0o700 });
  const responses = {
    'actions/runs/123/attempts/2':runIdentity(), 'actions/workflows/ci.yml':workflowIdentity,
    'actions/runs/123/attempts/2/jobs?per_page=100':hosted(), 'check-runs/1':checkIdentity(),
  };
  const env = { ...process.env, PATH: `${directory}${path.delimiter}${process.env.PATH}`,
    GITHUB_REPOSITORY: 'neverhuman/jankurai-tools-analyzers', GITHUB_RUN_ID: runId,
    GITHUB_RUN_ATTEMPT: attempt, EXPECTED_HEAD_SHA: head, GH_TOKEN: 'fixture-only',
    NEEDS_JSON: JSON.stringify(successfulJobs), REQUESTED_API: requested, FIXTURE_RESPONSES: JSON.stringify(responses) };
  const execute = changes => spawnSync(process.execPath, [path.join(root, 'scripts/ci-aggregate.mjs'), '--hosted'], {
    env: { ...env, ...changes }, encoding: 'utf8',
  });
  const passed = execute({}); assert.ifError(passed.error); assert.equal(passed.status, 0, passed.stderr);
  assert.deepEqual(fs.readFileSync(requested, 'utf8').trim().split('\n').map(line => JSON.parse(line)),
    Object.keys(responses).map(endpoint => ['api', '--hostname', 'github.com', `repos/neverhuman/jankurai-tools-analyzers/${endpoint}`]));
  fs.unlinkSync(requested);
  for (const changes of [{ GITHUB_REPOSITORY: 'other/repository' }, { GITHUB_RUN_ID: '' },
    { GITHUB_RUN_ATTEMPT: '' }, { GITHUB_RUN_ATTEMPT: '9007199254740992' },
    { EXPECTED_HEAD_SHA: '' }, { GH_TOKEN: '' }]) {
    const rejected = execute(changes); assert.ifError(rejected.error); assert.notEqual(rejected.status, 0);
    assert.equal(fs.existsSync(requested), false, 'invalid admission must not query another run');
  }
  const stale = hosted(); stale.jobs[0].run_attempt = 1;
  assert.notEqual(execute({ FIXTURE_RESPONSES: JSON.stringify({...responses, 'actions/runs/123/attempts/2/jobs?per_page=100':stale}) }).status, 0);
  const forged = {...checkIdentity(), app:{id:1, slug:'github-actions'}};
  assert.notEqual(execute({ FIXTURE_RESPONSES: JSON.stringify({...responses, 'check-runs/1':forged}) }).status, 0);
});
