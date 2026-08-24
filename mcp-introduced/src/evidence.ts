import { z } from 'zod';

/**
 * A boundary is a claim that some version of a package does, or does not, contain a
 * fix. It ends up in a public register that Dependabot and every SCA scanner reads,
 * so the schema is the last place a claim can be stopped before it becomes a fact
 * about someone else's software.
 *
 * Two rules are enforced here rather than in prose:
 *
 *   1. A boundary needs a commit and the hunk that commit changed. Without both there
 *      is nothing for a reviewer to check, and the correction is an assertion.
 *
 *   2. Text anyone can write may nominate a candidate. It may never justify a
 *      boundary. An issue comment saying "the real fix was in 3f2a1c9" is a lead, and
 *      a lead pointing at a genuine old commit will survive every other check here —
 *      the commit is real, the hunk is really present, the tier comes back
 *      `exact_patch`. This schema stops fabrication; it does not stop misdirection.
 *      The provenance rule is what stops misdirection.
 */

export const EvidenceTier = z.enum([
  'exact_patch',
  'backport',
  'release_reference',
  'test_added',
  'behavioral_probe',
  'unknown',
]);

export const NominationSource = z.enum([
  'advisory_record',
  'default_branch_history',
  'maintainer_authored',
  /** Arbitrary issue or PR comments, non-maintainer commit messages, fork READMEs. */
  'low_trust_text',
]);

const CommitSha = z
  .string()
  .regex(/^[0-9a-f]{40}$/, 'commit_sha must be a full 40-character hex SHA');

/** The smallest unit a reviewer can independently verify. */
export const Hunk = z.object({
  path: z.string().min(1),
  /** Unified-diff body. Kept verbatim so a reviewer sees what the agent saw. */
  patch: z.string().min(1),
});

export const Boundary = z
  .object({
    kind: z.enum(['introduced', 'fixed', 'last_affected']),
    version: z.string().min(1),
    commit_sha: CommitSha,
    hunk: Hunk,
    tier: EvidenceTier,
    nomination_source: NominationSource,
    /** Refs at which the hunk's presence was checked. Empty is not evidence. */
    verified_at_refs: z.array(z.string().min(1)).min(1),
    reasoning: z.string().min(1),
  })
  .refine((b) => b.tier !== 'unknown', {
    message: 'a boundary with tier "unknown" is an abstention, not a correction — do not file it',
  })
  .refine((b) => b.nomination_source !== 'low_trust_text', {
    message:
      'low-trust text may nominate a candidate, never justify a boundary; ' +
      'corroborate from the advisory record, maintainer-authored text, or branch history first',
  });

export type Boundary = z.infer<typeof Boundary>;

/**
 * Removing versions from an affected set un-flags software that consumers currently
 * treat as vulnerable. A single tier is enough to widen a range and not enough to
 * narrow one.
 */
export function narrowingIsSufficientlyEvidenced(boundaries: Boundary[]): boolean {
  const tiers = new Set(boundaries.map((b) => b.tier));
  return tiers.size >= 2;
}
