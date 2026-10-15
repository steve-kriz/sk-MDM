#!/usr/bin/env node
/**
 * Packages the agent installers with every value read from the deployed stack.
 *
 *   node scripts/package-installers.mjs [--version] 1.2.3 [--platform windows|macos|auto]
 *     [--arch x64|amd64|arm64] [--stack MdmStack] [--profile P] [--region R] [--dry-run]
 *
 * 1. `aws cloudformation describe-stacks` -> the stack's CollectionUrl output.
 * 2. GET <CollectionUrl>/api/v1/agent-auth/config -> tenantId and clientId.
 * 3. Rebuilds the agent for each architecture with scripts/build-agent.mjs,
 *    stamped with the package version (AGENT_VERSION), so an installer can
 *    never embed a stale agent/bin binary. Go is GO_BIN, else the repo's
 *    .tools/go toolchain when present, else `go` on PATH.
 * 4. Runs the platform build with those values baked in:
 *      windows: node installers/windows/build-plan.mjs (x64 and arm64 MSIs)
 *      macos:   sh installers/macos/build.sh            (amd64 and arm64 pkgs,
 *               MDM_SIGN_IDENTITY required)
 *    --arch narrows the build to one architecture.
 *
 * Output lands in dist/ as before, so scripts/publish-installers.mjs is
 * unchanged. A dry run does the two reads, prints the resolved values and the
 * build commands, and runs no build.
 *
 * scripts/deploy/package-installers.sh is the thin shell wrapper around this.
 *
 * Exit codes: 0 success, 1 the stack or config route could not be read or a
 * build failed, 2 bad usage.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..');

/** The path of the public route that publishes the agent's Entra settings. */
export const AGENT_AUTH_CONFIG_PATH = '/api/v1/agent-auth/config';

/** The architectures each platform's installers are built for, in build order. */
export const PLATFORM_ARCHES = {
  windows: ['x64', 'arm64'],
  macos: ['amd64', 'arm64'],
};

/** --arch spellings accepted for each platform, mapped to the build's name. */
const ARCH_ALIASES = {
  windows: { x64: 'x64', amd64: 'x64', arm64: 'arm64' },
  macos: { x64: 'amd64', amd64: 'amd64', arm64: 'arm64' },
};

const DEFAULTS = { platform: 'auto', stack: 'MdmStack' };

/** The Go target (scripts/build-agent.mjs --target) an installer arch embeds. */
const AGENT_TARGETS = {
  windows: { x64: 'windows/amd64', arm64: 'windows/arm64' },
  macos: { amd64: 'darwin/amd64', arm64: 'darwin/arm64' },
};

/**
 * The go binary the agent is built with: GO_BIN when set, else the repo's own
 * .tools/go toolchain when it exists, else undefined (build-agent.mjs then
 * runs `go` from PATH).
 */
export function goBin(env, exists = existsSync) {
  if (env.GO_BIN) {
    return env.GO_BIN;
  }
  const local = path.join(REPO_ROOT, '.tools', 'go', 'bin', process.platform === 'win32' ? 'go.exe' : 'go');
  return exists(local) ? local : undefined;
}

/** The command that rebuilds the agent one installer arch embeds. */
export function agentBuildCommand({ platform, arch, version, env, node = process.execPath }) {
  const target = AGENT_TARGETS[platform][arch];
  const go = goBin(env);
  return {
    label: `agent (${target})`,
    command: node,
    args: ['scripts/build-agent.mjs', '--target', target],
    env: { ...env, AGENT_VERSION: version, ...(go ? { GO_BIN: go } : {}) },
  };
}

/** Raised for a failure with a known exit code and message. */
class Refusal extends Error {
  constructor(message, exitCode) {
    super(message);
    this.exitCode = exitCode;
  }
}

/** The installer platform for --platform on a host (`process.platform`). */
export function resolvePlatform(requested, hostPlatform) {
  if (requested === 'windows' || requested === 'macos') {
    return requested;
  }
  if (requested !== 'auto') {
    throw new Refusal(`unsupported platform: ${requested} (use windows, macos or auto)`, 2);
  }
  // Git Bash and MSYS run Node as a Windows process.
  if (hostPlatform === 'win32') return 'windows';
  if (hostPlatform === 'darwin') return 'macos';
  throw new Refusal(
    `cannot build installers on ${hostPlatform}: build the MSIs on Windows and the pkgs on macOS`,
    2,
  );
}

/** The architectures to build: all of the platform's, or the one --arch names. */
export function resolveArches(platform, requested) {
  if (requested === undefined) {
    return [...PLATFORM_ARCHES[platform]];
  }
  const arch = ARCH_ALIASES[platform][requested];
  if (arch === undefined) {
    throw new Refusal(`unsupported arch for ${platform}: ${requested}`, 2);
  }
  return [arch];
}

/** The `aws` argv that prints the stack's CollectionUrl output. */
export function describeStackArgs({ stack, profile, region }) {
  const args = [
    'cloudformation',
    'describe-stacks',
    '--stack-name',
    stack,
    '--query',
    "Stacks[0].Outputs[?OutputKey=='CollectionUrl'].OutputValue",
    '--output',
    'text',
  ];
  if (profile) args.push('--profile', profile);
  if (region) args.push('--region', region);
  return args;
}

/** Reads the CollectionUrl output with `aws`; throws a Refusal (exit 1) on failure. */
export function readCollectionUrl(options, { aws }) {
  const result = aws(describeStackArgs(options));
  if (!result || result.error || result.status !== 0) {
    const reason = result?.error?.message ?? String(result?.stderr ?? '').trim();
    throw new Refusal(`could not read stack ${options.stack}${reason ? `: ${reason}` : ''}`, 1);
  }
  const value = String(result.stdout ?? '').trim();
  if (value === '' || value === 'None') {
    throw new Refusal(`stack ${options.stack} has no CollectionUrl output; deploy the backend first`, 1);
  }
  if (!isHttpsUrl(value)) {
    throw new Refusal(`stack ${options.stack} CollectionUrl is not an https url: ${value}`, 1);
  }
  return value;
}

/** True when `raw` is an https URL with a host. */
export function isHttpsUrl(raw) {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'https:' && parsed.host !== '';
  } catch {
    return false;
  }
}

/** <collectionUrl>/api/v1/agent-auth/config, whatever the trailing slash. */
export function agentAuthConfigUrl(collectionUrl) {
  return `${collectionUrl.replace(/\/+$/, '')}${AGENT_AUTH_CONFIG_PATH}`;
}

/** Fetches tenantId and clientId from the backend; throws a Refusal (exit 1) on failure. */
export async function fetchAgentAuthConfig(collectionUrl, { fetch }) {
  const url = agentAuthConfigUrl(collectionUrl);
  let response;
  try {
    response = await fetch(url);
  } catch (error) {
    throw new Refusal(`could not reach ${url}: ${error.message}`, 1);
  }
  if (response.status !== 200) {
    throw new Refusal(`GET ${url} returned ${response.status}; is Entra configured on the backend?`, 1);
  }
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Refusal(`GET ${url} did not return JSON`, 1);
  }
  const missing = ['tenantId', 'clientId'].filter(
    (key) => typeof body?.[key] !== 'string' || !/^[A-Za-z0-9._-]+$/.test(body[key]),
  );
  if (missing.length > 0) {
    throw new Refusal(`GET ${url} returned no usable ${missing.join(' or ')}`, 1);
  }
  return { tenantId: body.tenantId, clientId: body.clientId };
}

/**
 * The build commands for a platform: one { label, command, args } per
 * architecture, run from the repo root.
 */
export function buildCommands({ platform, arches, version, collectionUrl, tenantId, clientId, node = process.execPath }) {
  const values = ['--collection-url', collectionUrl, '--tenant-id', tenantId, '--client-id', clientId];
  return arches.map((arch) =>
    platform === 'windows'
      ? {
          label: `Windows MSI (${arch})`,
          command: node,
          args: ['installers/windows/build-plan.mjs', '--version', version, '--arch', arch, ...values],
        }
      : {
          label: `macOS pkg (${arch})`,
          command: 'sh',
          args: ['installers/macos/build.sh', '--version', version, '--arch', arch, ...values],
        },
  );
}

/** A command as one printable line. */
export function formatCommand({ command, args }) {
  const quote = (part) => (/^[\w@%+=:,./-]+$/.test(part) ? part : `'${part.replaceAll("'", "'\\''")}'`);
  const name = path.basename(command).replace(/\.exe$/i, '');
  return [name, ...args].map(quote).join(' ');
}

const FLAGS = {
  '--version': 'version',
  '--platform': 'platform',
  '--arch': 'arch',
  '--stack': 'stack',
  '--profile': 'profile',
  '--region': 'region',
};

export function parseArgs(argv) {
  const options = { ...DEFAULTS, dryRun: false, version: undefined, arch: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
      continue;
    }
    if (/^\d+\.\d+\.\d+$/.test(arg) && options.version === undefined) {
      options.version = arg;
      continue;
    }
    const separator = arg.indexOf('=');
    const key = FLAGS[separator === -1 ? arg : arg.slice(0, separator)];
    if (key === undefined) {
      throw new Refusal(`unknown argument: ${arg}`, 2);
    }
    const value = separator === -1 ? argv[i + 1] : arg.slice(separator + 1);
    if (value === undefined || value === '') {
      throw new Refusal(`${arg} needs a value`, 2);
    }
    if (separator === -1) i += 1;
    options[key] = value;
  }
  if (options.version === undefined || !/^\d+\.\d+\.\d+$/.test(options.version)) {
    throw new Refusal('a version is required and must look like 1.2.3', 2);
  }
  return options;
}

function defaultAws(env) {
  return (args) => spawnSync(env.AWS_BIN || 'aws', args, { encoding: 'utf8', env });
}

/**
 * Runs the CLI and returns the process exit code.
 *
 * `aws` (the stack read), `fetch` (the config read) and `spawn` (the builds)
 * are injected so tests run without AWS, network or toolchains, and so a dry
 * run can be proven to spawn no build.
 */
export async function main(
  argv = process.argv.slice(2),
  {
    env = process.env,
    aws = defaultAws(env),
    fetch = globalThis.fetch,
    spawn = spawnSync,
    hostPlatform = process.platform,
    node = process.execPath,
  } = {},
) {
  try {
    const options = parseArgs(argv);
    const platform = resolvePlatform(options.platform, hostPlatform);
    const arches = resolveArches(platform, options.arch);

    console.log(`==> Reading CollectionUrl from stack ${options.stack}`);
    const collectionUrl = readCollectionUrl(options, { aws });
    console.log(`==> Reading ${agentAuthConfigUrl(collectionUrl)}`);
    const { tenantId, clientId } = await fetchAgentAuthConfig(collectionUrl, { fetch });

    console.log(`collection url: ${collectionUrl}`);
    console.log(`tenant id:      ${tenantId}`);
    console.log(`client id:      ${clientId}`);
    console.log(`platform:       ${platform} (${arches.join(', ')})`);

    const installers = buildCommands({ platform, arches, version: options.version, collectionUrl, tenantId, clientId, node });
    // Each installer is preceded by a fresh build of the agent it embeds.
    const commands = installers.flatMap((installer, i) => [
      agentBuildCommand({ platform, arch: arches[i], version: options.version, env, node }),
      installer,
    ]);

    if (options.dryRun) {
      for (const command of commands) {
        console.log(`would run: ${formatCommand(command)}`);
      }
      return 0;
    }

    if (platform === 'macos' && !env.MDM_SIGN_IDENTITY) {
      throw new Refusal('MDM_SIGN_IDENTITY must name a Developer ID Installer identity to build the macOS pkg', 1);
    }

    for (const command of commands) {
      console.log(`==> Building ${command.label}`);
      const result = spawn(command.command, command.args, { cwd: REPO_ROOT, stdio: 'inherit', env: command.env ?? env });
      if (!result || result.error || result.status !== 0) {
        const reason = result?.error ? `: ${result.error.message}` : '';
        throw new Refusal(`build failed: ${command.label}${reason}`, 1);
      }
    }
    console.log('==> Done. Installers are in dist/');
    return 0;
  } catch (error) {
    if (error instanceof Refusal) {
      console.error(error.message);
      return error.exitCode;
    }
    throw error;
  }
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().then((code) => {
    process.exitCode = code;
  });
}
