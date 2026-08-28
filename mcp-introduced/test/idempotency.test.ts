import { test } from 'node:test';
import assert from 'node:assert/strict';
import { branchNameFor, openOrFindPullRequest, type Http } from '../src/github.ts';

/**
 * Tool execution is at-least-once across a crash inside the write window.
 *
 * Measured on TrueForge e9bf976: one human approval produced two `tools/call`, the
 * second firing before the model was consulted again. The guard that prevents this
 * for ungated tools is disabled for gated ones — annotating a tool destructive, which
 * is what switches the approval gate on, is what removes the double-execution guard.
 *
 * If the harness is killed inside the write window and the session is resumed, a second
 * pull request is opened against a real public repository, with nobody in the loop.
 *
 * So the branch name has to be a pure function of the advisory: the second call must
 * be able to find the first call's work.
 */

test('the branch name is derived from the advisory alone', () => {
  const a = branchNameFor('GHSA-x7jh-595q-wq82');
  const b = branchNameFor('GHSA-x7jh-595q-wq82');
  assert.equal(a, b);
  assert.match(a, /^introduced\/ghsa-/);
});

test('different advisories never collide', () => {
  assert.notEqual(branchNameFor('GHSA-x7jh-595q-wq82'), branchNameFor('GHSA-4qqq-9vqf-3h3f'));
});

test('a malformed advisory id is refused rather than guessed at', () => {
  assert.throws(() => branchNameFor('CVE-2020-1234'));
  assert.throws(() => branchNameFor('GHSA-short'));
});

const TARGET = { owner: 'BigAchiever', repo: 'advisory-database', base: 'main' };
const CORRECTION = {
  advisoryId: 'GHSA-x7jh-595q-wq82',
  path: 'advisories/GHSA-x7jh-595q-wq82.json',
  content: '{"affected": []}',
  title: 'Correct the affected range for GHSA-x7jh-595q-wq82',
  body: 'evidence follows',
};

/** A GitHub that remembers what it was asked, so a second call meets the first one's work. */
function fakeGitHub(seed: { pulls?: any[]; contents?: any } = {}) {
  const calls: string[] = [];
  const pulls: any[] = seed.pulls ? [...seed.pulls] : [];
  let contents: any = seed.contents ?? null;
  const http: Http = async (method: string, path: string, body: any) => {
    calls.push(`${method} ${path.split('?')[0]}`);
    if (method === 'GET' && path.includes('/pulls?')) return { status: 200, json: pulls };
    if (method === 'GET' && path.includes('/git/ref/')) {
      return { status: 200, json: { object: { sha: 'b'.repeat(40) } } };
    }
    if (method === 'POST' && path.endsWith('/git/refs')) return { status: 201, json: {} };
    if (method === 'GET' && path.includes('/contents/')) {
      return contents
        ? { status: 200, json: { sha: 'c'.repeat(40), content: contents } }
        : { status: 404, json: null };
    }
    if (method === 'PUT' && path.includes('/contents/')) {
      contents = body.content;
      return { status: 200, json: {} };
    }
    if (method === 'POST' && path.endsWith('/pulls')) {
      const pr = { html_url: 'https://github.com/x/y/pull/7', number: 7 };
      pulls.push(pr);
      return { status: 201, json: pr };
    }
    return { status: 500, json: null };
  };
  return { http, calls, pulls };
}

test('a first correction opens a pull request', async () => {
  const gh = fakeGitHub();
  const result = await openOrFindPullRequest(gh.http, TARGET, CORRECTION);
  assert.equal(result.preexisting, false);
  assert.equal(result.number, 7);
});

test('a repeated correction returns the existing pull request instead of opening a second one', async () => {
  // The case this exists for: the harness is killed inside the write window and the
  // session is resumed. The tool runs again with no model in the loop and no second
  // approval.
  const gh = fakeGitHub();
  const first = await openOrFindPullRequest(gh.http, TARGET, CORRECTION);
  const second = await openOrFindPullRequest(gh.http, TARGET, CORRECTION);

  assert.equal(first.number, second.number);
  assert.equal(second.preexisting, true);
  assert.equal(gh.pulls.length, 1, 'a second pull request was opened against a real repository');
});

test('the repeat stops at the first check without creating anything', async () => {
  const gh = fakeGitHub();
  await openOrFindPullRequest(gh.http, TARGET, CORRECTION);
  const before = gh.calls.length;
  await openOrFindPullRequest(gh.http, TARGET, CORRECTION);
  const onRepeat = gh.calls.slice(before);
  assert.deepEqual(onRepeat, ['GET /repos/BigAchiever/advisory-database/pulls'],
    'a resumed call must not create a branch or write a file before it checks');
});

test('a branch left behind by a crashed attempt is carried on from, not failed on', async () => {
  const gh = fakeGitHub();
  const http: Http = async (method: string, path: string, body?: unknown) =>
    method === 'POST' && path.endsWith('/git/refs')
      ? { status: 422, json: { message: 'Reference already exists' } }
      : gh.http(method, path, body);
  const result = await openOrFindPullRequest(http, TARGET, CORRECTION);
  assert.equal(result.number, 7);
});

test('identical content is not committed twice', async () => {
  const encoded = Buffer.from(CORRECTION.content, 'utf8').toString('base64');
  const gh = fakeGitHub({ contents: encoded });
  await openOrFindPullRequest(gh.http, TARGET, CORRECTION);
  assert.equal(gh.calls.filter((c) => c.startsWith('PUT')).length, 0,
    'a retry must not add an empty commit to a branch someone is reading');
});

test('a pull request opened concurrently is found rather than duplicated', async () => {
  // Between the first check and the create, a concurrent resume opened one.
  const gh = fakeGitHub();
  let raced = false;
  const http: Http = async (method: string, path: string, body?: unknown) => {
    if (method === 'POST' && path.endsWith('/pulls') && !raced) {
      raced = true;
      gh.pulls.push({ html_url: 'https://github.com/x/y/pull/9', number: 9 });
      return { status: 422, json: { message: 'A pull request already exists' } };
    }
    return gh.http(method, path, body);
  };
  const result = await openOrFindPullRequest(http, TARGET, CORRECTION);
  assert.equal(result.number, 9);
  assert.equal(result.preexisting, true);
});

test('every casing of one advisory names the same branch', () => {
  // Two spellings of one advisory must not become two branches: the branch name is
  // what lets a repeated write find the first write's work.
  //
  // The prefix is varied as well as the suffix. The first version of this test only
  // varied the suffix, so it passed while `ghsa-...` was still being rejected.
  const canonical = branchNameFor('GHSA-x7jh-595q-wq82');
  for (const spelling of ['GHSA-X7JH-595Q-WQ82', 'ghsa-x7jh-595q-wq82', 'Ghsa-X7jh-595Q-wq82']) {
    assert.equal(branchNameFor(spelling), canonical, spelling);
  }
});
