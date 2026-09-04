#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/docker/web/ssrf-metadata');
const composeFile = resolve(root, 'ctf/docker-compose.yml');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const compose = readFileSync(composeFile, 'utf8');
const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'web_ssrf_metadata');

if (!challenge) throw new Error('web_ssrf_metadata is missing from the manifest');
if (challenge.docker.dockerfile !== '../docker/web/ssrf-metadata/Dockerfile') throw new Error('manifest Dockerfile does not match the challenge');
if (challenge.docker.ports?.[0] !== '127.0.0.1:8083:8080') throw new Error('manifest must publish loopback-only via the gateway');
if (challenge.docker.healthcheck !== 'http://localhost:8080/health') throw new Error('manifest health check is stale');
if (challenge.docker.teardown !== 'docker compose down --remove-orphans') throw new Error('manifest teardown is stale');
if (challenge.target.endpoint !== '/fetch') throw new Error('challenge target endpoint must be /fetch');
if (challenge.flag.location !== 'mock_metadata_service' || challenge.flag.requires_ssrf !== true) throw new Error('flag must require SSRF to the mock metadata service');
if (!dockerfile.match(/^FROM [^\n]+@sha256:[a-f0-9]{64}$/m)) throw new Error('base image is not pinned by digest');
for (const required of [
  'ssrf-metadata-gateway:', 'metadata-mock:', '127.0.0.1:8083:8080',
  'ssrf-metadata-internal', 'read_only: true', 'cap_drop:', 'pids_limit: 64',
  'mem_limit: 128m', 'internal: true', 'restart: "no"',
]) {
  if (!compose.includes(required)) throw new Error(`compose safety contract missing: ${required}`);
}
for (const required of [
  'Origin:', 'License:', 'Flag handling:', 'Reproduction:', 'Rollback:',
  'Sensitive-data review:', 'Container trust:', 'Intended vulnerability:',
  'Network-negative test:',
]) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}

const expectedFlag = 'T3MP3ST{ssrf_t0_m0ck_m3t4d4t4}';
const flag = execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim();
if (flag !== expectedFlag) throw new Error(`deterministic solution failed: ${flag}`);

const localSmoke = `
import os, subprocess, sys, time
sys.path.insert(0, ${JSON.stringify(challengeDir)})
def up(port):
    from urllib.error import URLError
    from urllib.request import urlopen
    try:
        return urlopen('http://127.0.0.1:%d/health' % port, timeout=1).status == 200
    except (URLError, OSError, ValueError):
        return False
metadata = subprocess.Popen(['python3', 'metadata.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'METADATA_PORT': '18092'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
server = subprocess.Popen(['python3', 'server.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18091'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
gateway = subprocess.Popen(['python3', 'proxy.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18090', 'UPSTREAM': 'http://127.0.0.1:18091'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    deadline = time.time() + 15
    while time.time() < deadline:
        if up(18092) and up(18091) and up(18090):
            break
        time.sleep(0.2)
    else:
        raise SystemExit('metadata, challenge, or gateway not healthy in time')
    import solve
    solve.MOCK_URL = 'http://127.0.0.1:18092' + solve.ROLE_PATH
    print(solve.run_live('http://127.0.0.1:18090'))
finally:
    for proc in (gateway, server, metadata):
        proc.terminate()
`;
const extracted = execFileSync('python3', ['-c', localSmoke], { encoding: 'utf8' }).trim();
if (extracted !== expectedFlag) throw new Error(`gateway smoke extraction failed: ${extracted}`);

function dockerCompose(...args) {
  return execFileSync('docker', ['compose', '-f', composeFile, ...args], {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function runDockerNetworkTest() {
  try {
    dockerCompose('config', '--quiet');
    dockerCompose('up', '-d', '--build', 'ssrf-metadata-gateway');
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      try {
        const response = await fetch('http://127.0.0.1:8083/health');
        if (response.ok) break;
      } catch {}
      await new Promise((resolveWait) => setTimeout(resolveWait, 500));
    }
    const live = execFileSync('python3', [resolve(challengeDir, 'solve.py'), '--url', 'http://127.0.0.1:8083'], { encoding: 'utf8' }).trim();
    if (live !== expectedFlag) throw new Error(`container smoke extraction failed: ${live}`);

    for (const target of ['http://169.254.169.254/latest/meta-data/', 'https://example.com/']) {
      const response = await fetch('http://127.0.0.1:8083/fetch', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url: target }),
      });
      const payload = await response.json();
      if (payload.upstream_status !== 502 || !String(payload.body).startsWith('unreachable:')) {
        throw new Error(`default-deny egress failed for ${target}: ${JSON.stringify(payload)}`);
      }
    }

    const published = JSON.parse(dockerCompose('ps', '--format', 'json'));
    const services = Array.isArray(published) ? published : [published];
    for (const service of services.filter(Boolean)) {
      if (service.Service !== 'ssrf-metadata-gateway' && service.Publishers?.length) {
        throw new Error(`${service.Service} must not publish a host port`);
      }
    }
  } finally {
    dockerCompose('down', '--remove-orphans');
  }
}

if (process.argv.includes('--docker')) {
  await runDockerNetworkTest();
  console.log('SSRF CTF container smoke and network-negative checks: PASS');
} else {
  console.log('SSRF CTF contract and deterministic solution: PASS (use --docker for network isolation)');
}
