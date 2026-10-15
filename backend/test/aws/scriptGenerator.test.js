/**
 * E2E cucumber-style and unit tests for the AI script generator (TASK-053,
 * AC14, AC15, AC19, AC27): `backend/src/aws/scriptGenerator.ts`.
 *
 * The Bedrock Runtime client is always a fake `{send}` -- this file never
 * constructs a real `BedrockRuntimeClient` that sends a request, and makes no
 * network call and no database connection.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const {
  createBedrockScriptGenerator,
  buildScriptGeneratorSystemPrompt,
  buildScriptGeneratorUserMessage,
  SCRIPT_GENERATE_MAX_TOKENS,
} = await import('../../dist/aws/scriptGenerator.js');
const { ConverseCommand } = await import('@aws-sdk/client-bedrock-runtime');

const __dirname = dirname(fileURLToPath(import.meta.url));

/** A fake SDK-shaped Bedrock Runtime client: records every call and answers scripted outcomes. */
class FakeBedrockClient {
  constructor() {
    this.calls = [];
    this.outcome = { kind: 'resolve', value: { output: { message: { content: [{ text: 'ok' }] } } } };
  }

  async send(command, options) {
    this.calls.push({ command, options });
    if (this.outcome.kind === 'reject') {
      throw this.outcome.value;
    }
    return this.outcome.value;
  }
}

const REQUEST = {
  prompt: 'show date',
  interpreter: 'powershell',
  platform: 'windows',
  timeoutSeconds: 60,
  description: 'd',
};

// ============================================================================
// AC14
// ============================================================================

test('Scenario: Bedrock generator sends one Converse command', async () => {
  // Given a fake SDK client whose send resolves two text blocks
  const client = new FakeBedrockClient();
  client.outcome = {
    kind: 'resolve',
    value: { output: { message: { content: [{ text: 'Get-' }, { text: 'Date' }] } } },
  };
  // And createBedrockScriptGenerator({client, modelId:"au.anthropic.claude-haiku-4-5-20251001-v1:0"})
  const generator = createBedrockScriptGenerator({ client, modelId: 'au.anthropic.claude-haiku-4-5-20251001-v1:0' });
  const controller = new AbortController();

  // When generate is called with prompt "show date", interpreter "powershell", platform "windows",
  // timeoutSeconds 60, description "d" and an AbortSignal
  const result = await generator.generate(REQUEST, controller.signal);

  // Then send was called once with a ConverseCommand whose input modelId is the given id
  assert.equal(client.calls.length, 1);
  const [{ command, options }] = client.calls;
  assert.ok(command instanceof ConverseCommand);
  assert.equal(command.input.modelId, 'au.anthropic.claude-haiku-4-5-20251001-v1:0');

  // And the input system[0].text equals the system prompt built for powershell, windows, 60
  assert.equal(command.input.system[0].text, buildScriptGeneratorSystemPrompt('powershell', 60));

  // And the input has one "user" message whose text contains "show date", "d" and "60"
  assert.equal(command.input.messages.length, 1);
  const [message] = command.input.messages;
  assert.equal(message.role, 'user');
  assert.equal(message.content.length, 1);
  const userText = message.content[0].text;
  assert.match(userText, /show date/);
  assert.match(userText, /d/);
  assert.match(userText, /60/);

  // And the input inferenceConfig.maxTokens is 4096
  assert.equal(command.input.inferenceConfig.maxTokens, 4096);
  assert.equal(SCRIPT_GENERATE_MAX_TOKENS, 4096);

  // And send's second argument has abortSignal equal to the given signal
  assert.equal(options.abortSignal, controller.signal);

  // And generate resolves "Get-Date"
  assert.equal(result, 'Get-Date');
});

test('Unit: generate resolves "" when the reply has no text content blocks', async () => {
  const client = new FakeBedrockClient();
  client.outcome = { kind: 'resolve', value: { output: { message: { content: [] } } } };
  const generator = createBedrockScriptGenerator({ client, modelId: 'm' });

  const result = await generator.generate(REQUEST, new AbortController().signal);
  assert.equal(result, '');
});

test('Unit: generate resolves "" when the response is missing output.message.content entirely', async () => {
  const client = new FakeBedrockClient();
  client.outcome = { kind: 'resolve', value: {} };
  const generator = createBedrockScriptGenerator({ client, modelId: 'm' });

  const result = await generator.generate(REQUEST, new AbortController().signal);
  assert.equal(result, '');
});

// AC14
test('Scenario: SDK error propagates from the generator', async () => {
  // Given a fake SDK client whose send rejects with a ThrottlingException
  const client = new FakeBedrockClient();
  const thrown = new Error('Too many requests');
  thrown.name = 'ThrottlingException';
  client.outcome = { kind: 'reject', value: thrown };
  const generator = createBedrockScriptGenerator({ client, modelId: 'm' });

  // When generate is called
  // Then the returned promise rejects
  await assert.rejects(generator.generate(REQUEST, new AbortController().signal), /Too many requests/);
});

// ============================================================================
// AC15
// ============================================================================

const SYSTEM_PROMPT_EXAMPLES = [
  { shell: 'cmd', platform: 'Windows', marker: 'REM ' },
  { shell: 'powershell', platform: 'Windows', marker: '# ' },
  { shell: 'bash', platform: 'macOS', marker: '# ' },
  { shell: 'zsh', platform: 'macOS', marker: '# ' },
];

for (const { shell, platform, marker } of SYSTEM_PROMPT_EXAMPLES) {
  test(`Scenario Outline: System prompt content -- ${shell}`, () => {
    // When the system prompt is built for interpreter <shell> with timeout 90
    const prompt = buildScriptGeneratorSystemPrompt(shell, 90);

    // Then it contains "<shell>", "<platform>" and "90"
    assert.match(prompt, new RegExp(shell));
    assert.match(prompt, new RegExp(platform));
    assert.match(prompt, /90/);

    // And it contains the instruction to output only the script with no markdown code fences and no explanation
    assert.match(prompt, /only the script/i);
    assert.match(prompt, /no markdown code fences/i);
    assert.match(prompt, /no explanation/i);

    // And it contains the instruction that the script must not require interactive input
    assert.match(prompt, /no interactive input/i);

    // And it contains the fallback single comment line starting with "<marker>"
    assert.ok(prompt.includes(`"${marker}"`), `expected the prompt to name the "${marker}" marker`);
  });
}

test('Unit: buildScriptGeneratorUserMessage omits the description line when null', () => {
  const message = buildScriptGeneratorUserMessage({ ...REQUEST, description: null });
  assert.doesNotMatch(message, /Description:/);
  assert.match(message, /show date/);
  assert.match(message, /60/);
});

test('Unit: buildScriptGeneratorUserMessage includes the description line when present', () => {
  const message = buildScriptGeneratorUserMessage(REQUEST);
  assert.match(message, /Description: d/);
});

// ============================================================================
// AC19
// ============================================================================

test('Scenario: Dependency pinned', () => {
  // Then backend/package.json dependencies has "@aws-sdk/client-bedrock-runtime" at "3.1146.0"
  const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
  assert.equal(pkg.dependencies['@aws-sdk/client-bedrock-runtime'], '3.1146.0');
});
