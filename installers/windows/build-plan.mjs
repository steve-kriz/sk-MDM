#!/usr/bin/env node
/**
 * Plans and runs the WiX build of the Windows MSI.
 *
 *   node installers/windows/build-plan.mjs --version 1.2.3 --arch x64 --dry-run
 *   node installers/windows/build-plan.mjs --version 1.2.3 --arch x64
 *
 * The planning half — where the package lands and which WiX architecture it is
 * built for — lives here rather than in installers/windows/build.ps1, so the
 * output name and the unsupported-architecture exit code are the same whether
 * the build is driven from PowerShell or from Node. A dry run prints the path
 * the build would produce and spawns nothing.
 *
 * Exit codes: 0 success, 1 build failure, 2 bad usage (including an
 * unsupported architecture).
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

/** True when `arch` is an architecture the MSI is built for. */
export function isSupportedArch(arch) {
  return ARCHITECTURES.includes(arch);
}

/**
 * Where a build lands and which WiX architecture it is built for.
 *
 * The output path is repo-relative and uses forward slashes: it is printed
 * verbatim by a dry run and consumed by the release pipeline.
 */
export function planBuild({ version, arch } = {}) {
  if (!isSupportedArch(arch)) {
    throw new Error('unsupported arch');
  }
  if (typeof version !== 'string' || version === '') {
    throw new Error('version is required');
  }
  return {
    outputPath: `dist/OfficeHQ-MDM-${version}-${arch}.msi`,
    wixArch: arch,
  };
}

/** The agent binary the package embeds for a WiX architecture. */
export function agentBinary(arch) {
  return path.join(REPO_ROOT, 'agent', 'bin', `mdmagent-windows-${GOARCH[arch]}.exe`);
}

/** The argv the WiX toolset is invoked with for a plan. */
export function wixArgs({ outputPath, wixArch }, version) {
  return [
    'build',
    '-arch',
    wixArch,
    '-d',
    `Version=${version}`,
    '-d',
    `AgentBinary=${agentBinary(wixArch)}`,
    '-o',
    path.join(REPO_ROOT, outputPath),
    SOURCE,
  ];
}

function parseArgs(argv) {
  const options = { dryRun: false, version: null, arch: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--version') {
      options.version = argv[i + 1] ?? '';
      i += 1;
    } else if (arg.startsWith('--version=')) {
      options.version = arg.slice('--version='.length);
    } else if (arg === '--arch') {
      options.arch = argv[i + 1] ?? '';
      i += 1;
    } else if (arg.startsWith('--arch=')) {
      options.arch = arg.slice('--arch='.length);
    } else {
      return { error: `unknown argument: ${arg}` };
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

  if (!isSupportedArch(options.arch)) {
    console.error('unsupported arch');
    return 2;
  }

  let plan;
  try {
    plan = planBuild({ version: options.version, arch: options.arch });
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
