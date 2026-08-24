import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from './tools.ts';

export function buildServer(): McpServer {
  const server = new McpServer({ name: 'introduced', version: '0.1.0' });
  registerTools(server);
  return server;
}
