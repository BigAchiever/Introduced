import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Boundary, narrowingIsSufficientlyEvidenced } from './evidence.ts';
import { branchNameFor, GHSA_ID, redact } from './github.ts';

/**
 * Annotations are not documentation. TrueForge resolves its approval policy entirely
 * from them (`toolSelectors.ts`): `@read-only` is `readOnlyHint === true`, `@write` is
 * `readOnlyHint === false`, `@destructive` is `destructiveHint === true`. The default
 * policy gates `['@write', '@destructive']`, so a tool carrying neither hint executes
 * with no approval at all.
 *
 * Both hints are set deliberately, so the tool matches either selector however the
 * policy is configured. The same annotations also make the sandbox refuse to call
 * these tools from Code Mode, which is the second reason they are here.
 *
 * `idempotentHint` is absent on purpose. It would be a lie until the write path
 * actually is idempotent.
 */
const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: true,
  openWorldHint: true,
} as const;

/** Every tool that changes something outside this process must appear here. */
export const WRITE_TOOL_NAMES = ['open_boundary_correction', 'publish_repo_advisory'] as const;

const CorrectionInput = {
  advisory_id: z.string().regex(GHSA_ID),
  package_name: z.string().min(1),
  /** What the register says today. Recorded so the PR shows the delta, not just the result. */
  published_range: z.string().min(1),
  proposed_boundaries: z.array(Boundary).min(1),
  /** Set when the correction removes versions from the affected set. */
  narrows_affected_set: z.boolean(),
  justification: z.string().min(1),
};

export function registerTools(server: McpServer): void {
  server.registerTool(
    'open_boundary_correction',
    {
      title: 'Open a correction against github/advisory-database',
      description:
        'Files a pull request proposing a corrected affected-version range. Every boundary ' +
        'must carry a commit, the hunk it changed, and the refs where that hunk was checked. ' +
        'A correction that narrows the affected set requires two independent evidence tiers, ' +
        'because narrowing un-flags software consumers currently treat as vulnerable.',
      inputSchema: CorrectionInput,
      annotations: WRITE_ANNOTATIONS,
    },
    async (args) => {
      if (args.narrows_affected_set && !narrowingIsSufficientlyEvidenced(args.proposed_boundaries)) {
        return {
          isError: true,
          content: [
            {
              type: 'text' as const,
              text:
                'Refused: this correction removes versions from the affected set on a single ' +
                'evidence tier. Corroborate with a second tier, or emit the boundary as unknown.',
            },
          ],
        };
      }

      const branch = branchNameFor(args.advisory_id);
      // TODO: openOrFindPullRequest(branch, ...). Returning an error is the
      // honest placeholder — a stub that pretends to succeed would make the
      // approval gate look like it works when nothing is behind it.
      return {
        isError: true,
        content: [
          {
            type: 'text' as const,
            text: redact(`not implemented yet; would open or reuse branch ${branch}`),
          },
        ],
      };
    },
  );

  server.registerTool(
    'publish_repo_advisory',
    {
      title: 'Publish a repository security advisory',
      description:
        'Publishes an advisory on a repository the operator owns. Propagates to OSV, and ' +
        'cannot be withdrawn once consumers have ingested it.',
      inputSchema: {
        repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
        summary: z.string().min(1),
        affected_range: z.string().min(1),
      },
      annotations: WRITE_ANNOTATIONS,
    },
    async () => ({
      isError: true,
      content: [{ type: 'text' as const, text: 'not implemented yet' }],
    }),
  );
}
