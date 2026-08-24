import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { buildServer } from './server.ts';
import { WRITE_TOOL_NAMES } from './tools.ts';
import { requireWriteToken } from './github.ts';

const PORT = Number(process.env.PORT ?? 8931);

/**
 * Stateless, and this is not a preference.
 *
 * A stateful MCP server that restarts while TrueForge is mid-turn leaves the session
 * unrecoverable: the next call returns -32000 "Server not initialized", the approval
 * that was already granted is consumed, and retrying gets a 422. Observed on
 * TrueForge e9bf976. With no session to lose, this server can be restarted underneath
 * a live agent — which is exactly what happens during development.
 *
 * Statelessness is expressed by OMITTING sessionIdGenerator, not by passing undefined:
 * the option is declared `sessionIdGenerator?: () => string`, and the SDK's own docs
 * say "if not provided, session management is disabled".
 */
function newTransport(): StreamableHTTPServerTransport {
  return new StreamableHTTPServerTransport({});
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const server = buildServer();
  const transport = newTransport();
  res.on('close', () => {
    void transport.close();
    void server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res);
}

/**
 * What the harness sees, not what this server believes about itself.
 *
 * The claim worth checking is not "the tools are annotated" — it is "the harness
 * reads those annotations, therefore the gate engages". This route reports the
 * former; `GET /api/v1/settings/mcp-servers/introduced/tools` on TrueForge reports
 * the latter, and the coverage test asserts against that one.
 */
async function handleAnnotations(res: ServerResponse): Promise<void> {
  const server = buildServer();
  const registered = (server as unknown as { _registeredTools: Record<string, { annotations?: unknown }> })
    ._registeredTools;
  const body = Object.entries(registered ?? {}).map(([name, tool]) => ({
    name,
    annotations: tool.annotations ?? null,
    declared_write_tool: (WRITE_TOOL_NAMES as readonly string[]).includes(name),
  }));
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
  await server.close();
}

// Fail here rather than at the moment of a write.
requireWriteToken();

createServer((req, res) => {
  const url = req.url ?? '/';
  if (url.startsWith('/annotations')) {
    void handleAnnotations(res);
    return;
  }
  if (url.startsWith('/mcp')) {
    void handleMcp(req, res).catch((err: unknown) => {
      if (!res.headersSent) res.writeHead(500);
      res.end(String(err instanceof Error ? err.message : err));
    });
    return;
  }
  res.writeHead(404).end();
}).listen(PORT, () => {
  process.stderr.write(`introduced mcp server on http://127.0.0.1:${PORT}/mcp\n`);
});
