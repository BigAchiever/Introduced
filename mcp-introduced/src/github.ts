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

export interface Target {
  owner: string;
  repo: string;
  base: string;
}

export interface Correction {
  advisoryId: string;
  path: string;
  content: string;
  title: string;
  body: string;
}

/** Minimal GitHub REST surface, injectable so the write path is testable without a token. */
export type Http = (
  method: string,
  path: string,
  body?: unknown,
) => Promise<{ status: number; json: any }>;

export function githubHttp(token: string, api = "https://api.github.com"): Http {
  return async (method, path, body) => {
    const response = await fetch(`${api}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const text = await response.text();
    return { status: response.status, json: text ? JSON.parse(text) : null };
  };
}

/**
 * Open a correction, or return the one already open for this advisory.
 *
 * Every step is written so that running it twice does what running it once did. That
 * is not tidiness: tool execution is at-least-once across a crash inside the write
 * window. One human approval was measured producing two tools/call, the second firing
 * before the model was consulted again. Without this, a crash mid-write files a second
 * pull request against a real public repository with nobody in the loop.
 *
 * The order matters. The existing pull request is looked for FIRST, before anything is
 * created, because that is the check a resumed call needs and every later step is
 * cheaper if it never runs.
 */
export async function openOrFindPullRequest(
  http: Http,
  target: Target,
  correction: Correction,
): Promise<PullRequestRef> {
  const branch = branchNameFor(correction.advisoryId);
  const { owner, repo, base } = target;
  const head = `${owner}:${branch}`;

  const findOpen = async (): Promise<PullRequestRef | null> => {
    const found = await http(
      "GET",
      `/repos/${owner}/${repo}/pulls?head=${head}&state=all&per_page=1`,
    );
    if (found.status === 200 && Array.isArray(found.json) && found.json.length > 0) {
      return { url: found.json[0].html_url, number: found.json[0].number, preexisting: true };
    }
    return null;
  };

  // 1. Already open? A resumed call stops here, having created nothing.
  const already = await findOpen();
  if (already) return already;

  // 2. The branch. Creating one that exists is a 422, which means an earlier attempt
  //    got this far -- carry on rather than fail.
  const baseRef = await http("GET", `/repos/${owner}/${repo}/git/ref/heads/${base}`);
  if (baseRef.status !== 200) {
    throw new Error(`cannot read ${base} on ${owner}/${repo}: ${baseRef.status}`);
  }
  const created = await http("POST", `/repos/${owner}/${repo}/git/refs`, {
    ref: `refs/heads/${branch}`,
    sha: baseRef.json.object.sha,
  });
  if (created.status !== 201 && created.status !== 422) {
    throw new Error(`cannot create ${branch}: ${created.status}`);
  }

  // 3. The file. Identical content is not committed again, so a retry does not add an
  //    empty commit to a branch a reviewer is already reading.
  const current = await http(
    "GET",
    `/repos/${owner}/${repo}/contents/${correction.path}?ref=${branch}`,
  );
  const encoded = Buffer.from(correction.content, "utf8").toString("base64");
  const unchanged =
    current.status === 200 &&
    typeof current.json?.content === "string" &&
    current.json.content.replace(/\s/g, "") === encoded;

  if (!unchanged) {
    const put = await http("PUT", `/repos/${owner}/${repo}/contents/${correction.path}`, {
      message: correction.title,
      content: encoded,
      branch,
      ...(current.status === 200 ? { sha: current.json.sha } : {}),
    });
    if (put.status !== 200 && put.status !== 201) {
      throw new Error(`cannot write ${correction.path}: ${put.status}`);
    }
  }

  // 4. The pull request. If opening fails, look again rather than assuming why: a
  //    concurrent resume may have opened it between step 1 and here.
  const opened = await http("POST", `/repos/${owner}/${repo}/pulls`, {
    title: correction.title,
    body: correction.body,
    head: branch,
    base,
  });
  if (opened.status === 201) {
    return { url: opened.json.html_url, number: opened.json.number, preexisting: false };
  }
  const raced = await findOpen();
  if (raced) return raced;
  throw new Error(`cannot open a pull request for ${branch}: ${opened.status}`);
}
