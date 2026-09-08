#!/usr/bin/env bash
# Invoked only after the aggregate required check succeeds on a default-branch push.
set -euo pipefail
[[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]]
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
python3 - <<'PY_TAG'
import json, os, subprocess
repo, sha = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA']
ref = 'tags/ci-' + sha
existing = subprocess.run(['gh', 'api', f'repos/{repo}/git/ref/{ref}'], capture_output=True, text=True)
if existing.returncode == 0:
    obj = json.loads(existing.stdout)['object']
    if obj != {'type': 'commit', 'sha': sha, 'url': obj['url']}:
        raise SystemExit('immutable CI tag mismatch')
else:
    payload = json.dumps({'ref': 'refs/' + ref, 'sha': sha})
    subprocess.run(['gh', 'api', '--method', 'POST', f'repos/{repo}/git/refs', '--input', '-'],
                   input=payload, text=True, check=True, stdout=subprocess.DEVNULL)
print('Published immutable ci-' + sha)
PY_TAG
