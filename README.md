# OpenCode permission gate

Permission prompts are useful until they aren't. Fatigue is a problem, asking whether `ls` or `rg` is safe gets old fast. Eventually you stop paying attention or just turn off permissions checks altogether and both of those options are bad.

This is an OpenCode plugin to put a local model in the middle, think of it like [Claude Code's auto mode](https://code.claude.com/docs/en/auto-mode-config).

OpenCode's existing permission rules still run first. Anything already allowed runs. Anything denied stays denied. The classifier only sees actions that OpenCode would otherwise ask you about.

**The model can only approve an action. It can't override a deny.**

```
OpenCode permission rules
          |
     already allowed? → run
     already denied?  → deny
          |
       would ask
          |
    local classifier
       /       \
    allow      ask
      |         |
     run      human
```

## Why use a model?

Static rules/scripts/hooks work well when the command is the whole story, but usually a single command isn't the whole story.

For example, `git push` is reasonable after a prompt to "push this branch", but it's not reasonable after a prompt to "review this pull request".

Another example is installing a package. It's reasonable after "add vitest" but not after "refactor this code".

So, the command matters. As does the specific request, constraints given, permissions explicitly granted, tools it just ran, the working directory, etc.

That's the part the local model classifies.

## How it works

This version targets **OpenCode 2.0.26 or newer**. It uses the V2 permission
evaluation hook, not the V1 permission-event/reply workaround. V1 users should
keep the implementation at commit `2da3f04a614a805611241b0c92aac7455ed176a2`.

This plugin keeps a small record of the current user intent:
* The task
* Specified constraints like "don't push"
* Explicit authorizations like "install whatever packages you need"
* Recent turns

When OpenCode asks for permission, the plugin sends that context and the pending action to a local model.

Intent records persist in OpenCode's plugin storage across reloads and compaction.
When resuming a session without a stored record, only actual user messages seed
the record; synthetic messages and summaries are not treated as user authority.
Full tool arguments distinguish cached approvals, new prompts invalidate the
cache, and a newer prompt invalidates any classifier result still in flight.

The inputs are separate into three channels:
* Trusted user intent
* Untrusted pending action
* Untrusted recent tool activity

The distinction matters. Tool arguments and content the agent has read may contain prompt injection or claims that the user approved something. The classifier is instructed to treat those as data, not instructions.

The local model returns one of three decisions:
* `allow`
* `ask`
* `deny`

Only `allow` changes anything. Both `ask` and `deny` fall through to the normal OpenCode prompt. Therefore, the classifier can approve an action, but it cannot reject one on the user's behalf.

## What this is
* A way to reduce permission fatigue
* A local intent-aware approval layer
* A better experience for routine development work

## What this isn't
* A security boundary
* A replacement for sandboxing
* A solved version of automatic permissions
* The only security layer you need

## Local classifying

I'm using `gemma-4-26b-a4b-it-qat-mlx` on [LM studio](https://lmstudio.ai) with their OpenAI-compatible API. I've monitored the classification decision-making, and it seems pretty good. The latency is also pretty good (<1s) and I've had three different Opencode threads going simultaneously.

Those are observations, not format evaluations. A proper test corpus and false-approval measurements are still needed. The metric that matters is how often the classifier approves something that should have reached the user.

## Configuration

The defaults can be overridden with environment variables like this:
```
OPENCODE_PERMISSION_GATE_ENDPOINT=http://127.0.0.1:1234/v1/chat/completions
OPENCODE_PERMISSION_GATE_MODEL=gemma-4-26b-a4b-it-qat-mlx
OPENCODE_PERMISSION_GATE_CLASSIFY_TIMEOUT_MS=5000
OPENCODE_PERMISSION_GATE_EXTRACT_TIMEOUT_MS=5000
OPENCODE_PERMISSION_GATE_LOG_PATH="$HOME/.config/opencode/auditor.log"
```

You can also pass `endpoint`, `model`, `classifyTimeoutMs`, `extractTimeoutMs`,
and `logPath` as plugin options. Environment variables override plugin options.
Defaults remain Gemma with 5-second extraction and classification timeouts;
select a model and timeouts suited to your machine.

## Installation
1. Run a compatible local model server like [LM studio](https://lmstudio.ai).
2. Configure the endpoint and model
3. Clone this repository and install its declared dependencies:

   ```sh
   git clone https://github.com/bencrouse/opencode-permission-gate.git
   cd opencode-permission-gate
   npm ci
   ```

4. Configure the cloned **directory**, not the individual file, in your global
   or project `opencode.jsonc`. Replace the example path with your checkout:

   ```jsonc
    {
      "$schema": "https://opencode.ai/config.json",
      "plugins": [
       {
         "package": "/absolute/path/to/opencode-permission-gate",
         "options": {
           "model": "qwen3.6-35b-a3b",
           "classifyTimeoutMs": 30000,
           "extractTimeoutMs": 30000
         }
       }
     ]
   }
   ```

   For a project-local copy, place the plugin in an immediate subdirectory of
   `.opencode/plugins/` with its `index.ts`, source, `package.json`, and dependency
   installation. The `index.ts` entrypoint supports local directory discovery.

5. Run `opencode reload`. If the running server still reports old plugin exports,
   run `opencode service restart` to clear its imported-module cache.
6. Review the audit log while testing it for your workflows, start somewhere a mistake would be annoying, not dangerous.

## Development

Requires Node.js 24 or newer and npm.

```sh
npm ci
npm run check
```

Tests cover allow-only decisions, classifier failures, argument-sensitive
caching, circuit-breaker recovery, stale in-flight verdicts, durable intent,
plugin cleanup, and configuration precedence. They do not measure the safety
or accuracy of a real classifier model.

## Security posture

The threat I'm focused on here is an overly eager model doing things I don't want. You could build on this concept by editing the system prompt to reduce whatever behavior models tend to do that you don't like. It's flexible that way.

## Status

Experimental! I am using it, watching the logs, and tightening the cases where the model is too eager. Please do not confuse “works well for me” with “proven safe.”
