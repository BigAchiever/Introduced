# AI usage

Use of AI coding assistants has to be disclosed. This file is that disclosure. It is written at the start
and updated as the build goes, rather than assembled at the end.

## What AI was used for

**Research and planning, before the build.**
Reading the TrueForge source and documentation, drafting the architecture, and arguing against it until
what was left held up. The behavioural findings this design rests on were produced by running TrueForge
locally against a scripted model server and a local MCP server, and reading the source to explain what was
observed.

**During the build.**
<!-- Keep this current. Be specific: which parts were drafted with assistance, which were written directly,
     and which were rewritten after review. Vague disclosure is worse than none. -->

## What was not delegated

The concept, the scope decisions, and the design trade-offs recorded in this repository's commit history and
documentation. Where a claim in this repository is load-bearing — a boundary the tool will file, a property
the benchmark asserts — it was checked against the source or by running it, not accepted because a model
stated it.

## Design decisions that came from measurement, not assumption

Each was observed on TrueForge at commit `e9bf976`.

| Decision | The observation behind it |
|---|---|
| The MCP server is stateless | A stateful MCP server restarting alongside the harness leaves the session unrecoverable |
| Write tools carry explicit `destructiveHint` annotations | The default approval policy resolves only from tool annotations; an unannotated destructive tool executes with no approval |
| The write path is designed to be idempotent, and `idempotentHint` is withheld until it is | Tool execution is at-least-once across a crash inside the write window |
| Nothing in the sandbox holds a credential | Code the sandbox runs is never gated for approval |

<!-- Add to this table as the build produces more of them. It is the strongest evidence that the decisions
     here are understood rather than inherited. -->

## Verification

<!-- Before submission: which claims in the README are checkable by a reader, and the command that checks
     each one. -->
