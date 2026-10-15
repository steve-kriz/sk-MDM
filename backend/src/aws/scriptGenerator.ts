/**
 * Generate a command-library script with Amazon Bedrock (TASK-053).
 *
 *   const generator = createBedrockScriptGenerator({ client: new BedrockRuntimeClient({}), modelId });
 *   const text = await generator.generate(request, signal);
 *
 * One `ConverseCommand` per request. The system prompt names the interpreter,
 * its platform and the timeout; the user message carries the admin's request,
 * the description (when present) and the timeout. The caller's `AbortSignal`
 * is passed to `send(command, { abortSignal })`. The method resolves the
 * concatenation of every `text` block of the reply; clean-up and size checks
 * are the route's job (`src/admin/scripts.ts`). A failed send rejects. The
 * client is injected, the same shape as `src/aws/hasherInvoker.ts`.
 */
import { ConverseCommand } from '@aws-sdk/client-bedrock-runtime';

/** The reply length cap sent as `inferenceConfig.maxTokens`. */
export const SCRIPT_GENERATE_MAX_TOKENS = 4096;

/** The interpreters a generated script may target. */
export type ScriptGenerateInterpreter = 'cmd' | 'powershell' | 'bash' | 'zsh';

/** The platforms a generated script runs on. */
export type ScriptGeneratePlatform = 'windows' | 'darwin';

/** One validated generate request. */
export interface ScriptGenerateRequest {
  /** The admin's request, trimmed. */
  prompt: string;
  interpreter: ScriptGenerateInterpreter;
  platform: ScriptGeneratePlatform;
  timeoutSeconds: number;
  /** The description typed with the request, or `null`. */
  description: string | null;
}

/** Turns a plain-English request into script text. */
export interface ScriptGenerator {
  generate(request: ScriptGenerateRequest, signal: AbortSignal): Promise<string>;
}

/** An SDK-shaped Bedrock Runtime client (a `BedrockRuntimeClient` satisfies it): only `send` is used. */
export interface ScriptGeneratorBedrockClient {
  send(command: ConverseCommand, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface BedrockScriptGeneratorOptions {
  /** The SDK-shaped Bedrock Runtime client. */
  client: ScriptGeneratorBedrockClient;
  /** A foundation-model id or a cross-region inference-profile id. */
  modelId: string;
}

/** The platform name the model is told, for an interpreter. */
function platformName(interpreter: ScriptGenerateInterpreter): string {
  return interpreter === 'cmd' || interpreter === 'powershell' ? 'Windows' : 'macOS';
}

/** The comment marker the fallback line starts with, for an interpreter. */
function commentMarker(interpreter: ScriptGenerateInterpreter): string {
  return interpreter === 'cmd' ? 'REM ' : '# ';
}

/** The system prompt for one request: interpreter, platform and timeout. */
export function buildScriptGeneratorSystemPrompt(interpreter: ScriptGenerateInterpreter, timeoutSeconds: number): string {
  const platform = platformName(interpreter);
  const marker = commentMarker(interpreter);
  return [
    `You write a single ${interpreter} script that runs on ${platform}.`,
    'The script is run unattended by a device management agent: it must run with no interactive input ' +
      '(never prompt, pause or wait for the user) and must finish within ' +
      `${timeoutSeconds} seconds.`,
    'Output only the script text, with no markdown code fences and no explanation before or after it.',
    `If the request cannot be met as a ${interpreter} script, output only a single comment line starting with "${marker}" saying why.`,
  ].join('\n');
}

/** The user message for one request: the admin's request, the description when present, and the timeout. */
export function buildScriptGeneratorUserMessage(request: ScriptGenerateRequest): string {
  const lines = [`Request: ${request.prompt}`];
  if (request.description !== null) {
    lines.push(`Description: ${request.description}`);
  }
  lines.push(`Timeout: ${request.timeoutSeconds} seconds`);
  return lines.join('\n');
}

/** Every `text` block of a Converse reply, concatenated; `''` when there are none. */
function replyText(response: unknown): string {
  const content = (response as { output?: { message?: { content?: unknown } } } | undefined)?.output?.message?.content;
  if (!Array.isArray(content)) {
    return '';
  }
  return content
    .map((block) => (block !== null && typeof block === 'object' && typeof (block as { text?: unknown }).text === 'string' ? (block as { text: string }).text : ''))
    .join('');
}

export function createBedrockScriptGenerator({ client, modelId }: BedrockScriptGeneratorOptions): ScriptGenerator {
  return {
    async generate(request: ScriptGenerateRequest, signal: AbortSignal): Promise<string> {
      const command = new ConverseCommand({
        modelId,
        system: [{ text: buildScriptGeneratorSystemPrompt(request.interpreter, request.timeoutSeconds) }],
        messages: [{ role: 'user', content: [{ text: buildScriptGeneratorUserMessage(request) }] }],
        inferenceConfig: { maxTokens: SCRIPT_GENERATE_MAX_TOKENS },
      });
      const response = await client.send(command, { abortSignal: signal });
      return replyText(response);
    },
  };
}
