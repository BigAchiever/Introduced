import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Boundary, narrowingIsSufficientlyEvidenced } from '../src/evidence.ts';

const SHA = 'a'.repeat(40);

function boundary(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'fixed',
    version: '1.4.2',
    commit_sha: SHA,
    hunk: { path: 'loader.py', patch: '@@ -1 +1 @@\n-bad\n+good\n' },
    tier: 'exact_patch',
    nomination_source: 'advisory_record',
    verified_at_refs: ['v1.4.2'],
    reasoning: 'hunk present from v1.4.2 onward',
    ...overrides,
  };
}

test('a well-formed boundary is accepted', () => {
  assert.ok(Boundary.safeParse(boundary()).success);
});

test('a boundary without a commit is refused', () => {
  const { commit_sha, ...rest } = boundary();
  void commit_sha;
  assert.equal(Boundary.safeParse(rest).success, false);
});

test('a boundary without a hunk is refused', () => {
  const { hunk, ...rest } = boundary();
  void hunk;
  assert.equal(Boundary.safeParse(rest).success, false);
});

test('an abbreviated sha is refused', () => {
  assert.equal(Boundary.safeParse(boundary({ commit_sha: '3f2a1c9' })).success, false);
});

test('a boundary verified at no refs is refused', () => {
  assert.equal(Boundary.safeParse(boundary({ verified_at_refs: [] })).success, false);
});

test('tier unknown is an abstention and cannot be filed', () => {
  assert.equal(Boundary.safeParse(boundary({ tier: 'unknown' })).success, false);
});

test('low-trust text may nominate but never justify', () => {
  // The commit is real and the hunk is genuinely present. Every other check here
  // passes. Provenance is the only thing standing between an issue comment and a
  // public correction.
  const result = Boundary.safeParse(boundary({ nomination_source: 'low_trust_text' }));
  assert.equal(result.success, false);
});

test('narrowing on one evidence tier is insufficient', () => {
  const one = [Boundary.parse(boundary())];
  assert.equal(narrowingIsSufficientlyEvidenced(one), false);
});

test('narrowing on two independent tiers is sufficient', () => {
  const two = [
    Boundary.parse(boundary()),
    Boundary.parse(boundary({ kind: 'introduced', version: '1.1.0', tier: 'release_reference' })),
  ];
  assert.equal(narrowingIsSufficientlyEvidenced(two), true);
});
