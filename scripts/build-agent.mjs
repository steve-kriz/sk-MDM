#!/usr/bin/env node
/**
 * Cross-compiles the Go agent for every supported target.
 *
 *   node scripts/build-agent.mjs                      # build all targets
 *   node scripts/build-agent.mjs --target darwin/arm64 # build one target
 *   node scripts/build-agent.mjs --dry-run             # list targets, build nothing
 *
 * Exit codes: 0 success, 1 build failure, 2 unsupported target / bad usage.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..');
const AGENT_DIR = path.join(REPO_ROOT, 'agent');
const OUT_DIR = path.join(AGENT_DIR, 'bin');
const PACKAGE = './cmd/mdmagent';

const TARGETS = ['windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64'];

/** The platforms the agent ships for, as "<goos>/<goarch>" strings. */
export function targets() {
  return [...TARGETS];
}

/** True when `target` is one of the supported platforms. */
export function isSupportedTarget(target) {
  return TARGETS.includes(target);
}

/** Path of the binary produced for a target, relative to the repo root. */
export function outputPath(target) {
  const [goos, goarch] = target.split('/');
  const suffix = goos === 'windows' ? '.exe' : '';
  return path.join(OUT_DIR, `mdmagent-${goos}-${goarch}${suffix}`);
}

function parseArgs(argv) {
  const options = { dryRun: false, target: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--target') {
      options.target = argv[i + 1] ?? '';
      i += 1;
    } else if (arg.startsWith('--target=')) {
      options.target = arg.slice('--target='.length);
    } else {
      return { error: `unknown argument: ${arg}` };
    }
  }
  return options;
}

function build(target, version) {
  const [goos, goarch] = target.split('/');
  const output = outputPath(target);
  mkdirSync(path.dirname(output), { recursive: true });
  const result = spawnSync(
    process.env.GO_BIN ?? 'go',
    [
      'build',
      '-trimpath',
      '-ldflags',
      `-s -w -X github.com/officehq/sk-mdm/agent/internal/version.Version=${version}`,
      '-o',
      output,
      PACKAGE,
    ],
    {
      cwd: AGENT_DIR,
      stdio: 'inherit',
      env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0' },
    },
  );
  if (result.error) {
    console.error(`failed to run the go toolchain: ${result.error.message}`);
    return false;
  }
  if (result.status !== 0) {
    console.error(`build failed for ${target}`);
    return false;
  }
  console.log(`built ${path.relative(REPO_ROOT, output).split(path.sep).join('/')}`);
  return true;
}

/** Runs the CLI and returns the process exit code. */
export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.error) {
    console.error(options.error);
    return 2;
  }

  if (options.target !== null && !isSupportedTarget(options.target)) {
    console.error(`unsupported target: ${options.target}`);
    return 2;
  }

  const selected = options.target === null ? targets() : [options.target];

  if (options.dryRun) {
    for (const target of selected) {
      console.log(target);
    }
    return 0;
  }

  const version = process.env.AGENT_VERSION ?? '0.0.0-dev';
  for (const target of selected) {
    if (!build(target, version)) {
      return 1;
    }
  }
  return 0;
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = main();
}
