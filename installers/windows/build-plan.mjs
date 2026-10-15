#!/usr/bin/env node
/**
 * Plans and runs the WiX build of the Windows MSI.
 *
 *   node installers/windows/build-plan.mjs --version 1.2.3 --arch x64 \
 *     --collection-url https://mdm.example/ --tenant-id <tenant> --client-id <client> [--dry-run]
 *
 * The planning half — where the package lands, which WiX architecture it is
 * built for and the values baked into it — lives here rather than in
 * installers/windows/build.ps1, so the output name and the exit codes are the
 * same whether the build is driven from PowerShell or from Node. A dry run
 * prints the path the build would produce and spawns nothing.
 *
 * The collection URL, Entra tenant id and client id become the MSI's
 * DefaultCollectionUrl, TenantId and ClientId preprocessor variables: the
 * defaults the installer pre-fills and writes into the agent config.
 * scripts/package-installers.mjs reads all three from the deployed stack.
 *
 * Exit codes: 0 success, 1 build failure, 2 bad usage (an unsupported
 * architecture, a collection URL that is not https, an empty or malformed
 * tenant or client id).
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
const SOURCE = path.join(SCRIPT_DIR, 'Product.wxs');

/** The architectures the MSI ships for, as WiX `-arch` values. */
const ARCHITECTURES = ['x64', 'arm64'];

/** The GOARCH each WiX architecture's agent binary was built for. */
const GOARCH = { x64: 'amd64', arm64: 'arm64' };

/** The WiX extensions Product.wxs uses: UI for the wizard, Util for the service recovery actions. */
export const WIX_EXTENSIONS = ['WixToolset.UI.wixext', 'WixToolset.Util.wixext'];

export const COLLECTION_URL_MESSAGE = 'collection url must be an https url';
export const TENANT_ID_MESSAGE = 'tenant id is required (letters, digits, ".", "-" and "_" only)';
export const CLIENT_ID_MESSAGE = 'client id is required (letters, digits, ".", "-" and "_" only)';

/** True when `arch` is an architecture the MSI is built for. */
export function isSupportedArch(arch) {
  return ARCHITECTURES.includes(arch);
}

/** True when `raw` is an https URL with a host, as agent/internal/config requires. */
export function isCollectionUrl(raw) {
  if (typeof raw !== 'string' || raw === '') {
    return false;
  }
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'https:' && parsed.host !== '';
  } catch {
    return false;
  }
}

/**
 * True when `raw` is a usable Entra tenant or client id: a GUID or a domain
 * name. Nothing that could break out of a WiX `-d` value or a shell
 * substitution is accepted.
 */
export function isEntraId(raw) {
  return typeof raw === 'string' && /^[A-Za-z0-9._-]+$/.test(raw);
}

/** Every problem with the baked values, as the messages the CLI prints. */
export function valueProblems({ collectionUrl, tenantId, clientId } = {}) {
  const found = [];
  if (!isCollectionUrl(collectionUrl)) found.push(COLLECTION_URL_MESSAGE);
  if (!isEntraId(tenantId)) found.push(TENANT_ID_MESSAGE);
  if (!isEntraId(clientId)) found.push(CLIENT_ID_MESSAGE);
  return found;
}

/**
 * Where a build lands, which WiX architecture it is built for and the values
 * baked into it.
 *
 * The output path is repo-relative and uses forward slashes: it is printed
 * verbatim by a dry run and consumed by the release pipeline.
 */
export function planBuild({ version, arch, collectionUrl, tenantId, clientId } = {}) {
  if (!isSupportedArch(arch)) {
    throw new Error('unsupported arch');
  }
  if (typeof version !== 'string' || version === '') {
    throw new Error('version is required');
  }
  const [problem] = valueProblems({ collectionUrl, tenantId, clientId });
  if (problem) {
    throw new Error(problem);
  }
  return {
    outputPath: `dist/OfficeHQ-MDM-${version}-${arch}.msi`,
    wixArch: arch,
    collectionUrl,
    tenantId,
    clientId,
  };
}

/** The agent binary the package embeds for a WiX architecture. */
export function agentBinary(arch) {
  return path.join(REPO_ROOT, 'agent', 'bin', `mdmagent-windows-${GOARCH[arch]}.exe`);
}

/** The argv the WiX toolset is invoked with for a plan. */
export function wixArgs({ outputPath, wixArch, collectionUrl, tenantId, clientId }, version) {
  return [
    'build',
    '-arch',
    wixArch,
    ...WIX_EXTENSIONS.flatMap((extension) => ['-ext', extension]),
    '-d',
    `Version=${version}`,
    '-d',
    `AgentBinary=${agentBinary(wixArch)}`,
    '-d',
    `DefaultCollectionUrl=${collectionUrl}`,
    '-d',
    `TenantId=${tenantId}`,
    '-d',
    `ClientId=${clientId}`,
    '-o',
    path.join(REPO_ROOT, outputPath),
    SOURCE,
  ];
}

const FLAGS = {
  '--version': 'version',
  '--arch': 'arch',
  '--collection-url': 'collectionUrl',
  '--tenant-id': 'tenantId',
  '--client-id': 'clientId',
};

function parseArgs(argv) {
  const options = { dryRun: false, version: null, arch: null, collectionUrl: null, tenantId: null, clientId: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
      continue;
    }
    const separator = arg.indexOf('=');
    const key = FLAGS[separator === -1 ? arg : arg.slice(0, separator)];
    if (key === undefined) {
      return { error: `unknown argument: ${arg}` };
    }
    if (separator === -1) {
      options[key] = argv[i + 1] ?? '';
      i += 1;
    } else {
      options[key] = arg.slice(separator + 1);
    }
  }
  return options;
}

/**
 * Runs the CLI and returns the process exit code.
 *
 * `spawn` is injected so a dry run can be proven to spawn nothing.
 */
export function main(argv = process.argv.slice(2), { spawn = spawnSync } = {}) {
  const options = parseArgs(argv);
  if (options.error) {
    console.error(options.error);
    return 2;
  }

  // Every problem at once, so a caller with two bad flags hears about both.
  const found = [];
  if (!isSupportedArch(options.arch)) found.push('unsupported arch');
  found.push(...valueProblems(options));
  if (found.length > 0) {
    for (const problem of found) console.error(problem);
    return 2;
  }

  let plan;
  try {
    plan = planBuild(options);
  } catch (error) {
    console.error(error.message);
    return 2;
  }

  if (options.dryRun) {
    console.log(plan.outputPath);
    return 0;
  }

  const result = spawn(process.env.WIX_BIN ?? 'wix', wixArgs(plan, options.version), {
    cwd: REPO_ROOT,
    stdio: 'inherit',
  });
  if (result.error) {
    console.error(`failed to run the wix toolset: ${result.error.message}`);
    return 1;
  }
  if (result.status !== 0) {
    console.error(`build failed for ${plan.outputPath}`);
    return 1;
  }
  console.log(plan.outputPath);
  return 0;
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = main();
}
