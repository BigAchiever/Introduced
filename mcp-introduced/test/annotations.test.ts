import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildServer } from '../src/server.ts';
import { WRITE_TOOL_NAMES } from '../src/tools.ts';

/**
 * TrueForge's default approval policy resolves entirely from tool annotations. A write
 * tool that loses its annotation does not fail loudly — it starts executing without
 * asking anyone. That failure is silent, which is why it is a test and not a review
 * checklist item.
 */

function registeredTools() {
  const server = buildServer();
  return (server as unknown as {
    _registeredTools: Record<string, { annotations?: Record<string, unknown> }>;
  })._registeredTools;
}

test('every declared write tool is registered', () => {
  const tools = registeredTools();
  for (const name of WRITE_TOOL_NAMES) {
    assert.ok(tools[name], `${name} is declared a write tool but is not registered`);
  }
});

test('every write tool carries both hints the policy selectors read', () => {
  const tools = registeredTools();
  for (const name of WRITE_TOOL_NAMES) {
    const a = tools[name]?.annotations;
    assert.ok(a, `${name} has no annotations — it would execute with no approval`);
    assert.equal(a.destructiveHint, true, `${name} is not matched by @destructive`);
    assert.equal(a.readOnlyHint, false, `${name} is not matched by @write`);
  }
});

test('no tool claims to be idempotent before the write path is', () => {
  const tools = registeredTools();
  for (const [name, tool] of Object.entries(tools)) {
    assert.notEqual(
      tool.annotations?.idempotentHint,
      true,
      `${name} claims idempotentHint, but tool execution is at-least-once across a ` +
        `crash in the write window and the write path does not yet dedupe`,
    );
  }
});

test('a tool that is not a declared write tool is not annotated destructive', () => {
  const tools = registeredTools();
  for (const [name, tool] of Object.entries(tools)) {
    if ((WRITE_TOOL_NAMES as readonly string[]).includes(name)) continue;
    assert.notEqual(tool.annotations?.destructiveHint, true, `${name} is gated but undeclared`);
  }
});
