/**
 * The only module that reads the write token.
 *
 * `rangecore` runs in a sandbox alongside code the model wrote, against packages
 * nobody has reviewed. Nothing in that container can reach this file, because the
 * token is not there — it is here, in a process the sandbox cannot address.
 *
 * Read access is a separate concern and a separate credential: advisory prose, linked
 * issues and commit data come from the `github` server in TrueForge's own catalog,
 * configured with a read-only public-repo token. The precise claim is therefore not
 * "one process holds the token" but "one process holds a token that can write".
 */

const TOKEN_ENV = 'INTRODUCED_GITHUB_WRITE_TOKEN';

export function requireWriteToken(): string {
  const token = process.env[TOKEN_ENV];
  if (!token) {
    throw new Error(
      `${TOKEN_ENV} is not set. This server refuses to start without it rather than ` +
        `failing at the moment of a write.`,
    );
  }
  return token;
}

/** Never interpolate a token into a log line, an error, or a tool result. */
export function redact(text: string): string {
  const token = process.env[TOKEN_ENV];
  return token ? text.split(token).join('[redacted]') : text;
}

export interface PullRequestRef {
  url: string;
  number: number;
  /** True when this call found an existing PR rather than opening one. */
  preexisting: boolean;
}

/**
 * Deterministic branch name, derived from the advisory id alone.
 *
 * Tool execution is at-least-once across a crash inside the write window: one human
 * approval can produce two calls, and the second arrives with no model in the loop.
 * A name derived from the advisory — rather than a timestamp or a random suffix —
 * is what lets the second call find the first call's work instead of duplicating it.
 */
// The `i` flag covers the prefix as well as the suffix. Spelling it with character
// classes left `GHSA-` literal, so the comment below promised something the pattern
// did not do and the test did not reach.
export const GHSA_ID = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i;

export function branchNameFor(advisoryId: string): string {
  // Case-insensitive, then normalised. GHSA ids are canonically lower-case, but an id
  // that arrives from a feed or a human with different casing names the same advisory,
  // and refusing it would strand a correction over punctuation. Normalising here also
  // means two spellings of one advisory cannot map to two branches, which matters
  // because this name is what makes a repeated write find the first write's work.
  if (!GHSA_ID.test(advisoryId)) {
    throw new Error(`not a GHSA id: ${advisoryId}`);
  }
  return `introduced/${advisoryId.toLowerCase()}`;
}

// TODO: openOrFindPullRequest(). Must check for an existing PR on
// branchNameFor(advisoryId) and return it with preexisting: true rather than opening
// a second one. Until this exists the write path is not safe to point at a real
// repository — see test/idempotency.test.ts, which is currently red on purpose.
