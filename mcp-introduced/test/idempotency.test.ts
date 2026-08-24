import { test } from 'node:test';
import assert from 'node:assert/strict';
import { branchNameFor } from '../src/github.ts';

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

test(
  'a repeated correction returns the existing pull request instead of opening a second one',
  { todo: 'openOrFindPullRequest — the write path is not yet idempotent' },
  () => {},
);
