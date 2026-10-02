#!/usr/bin/env node
/**
 * Plans the macOS component package: the paths the build stages the agent and
 * its LaunchDaemon into, the unsigned package `productbuild` writes and the
 * signed package `productsign` produces.
 *
 *   node installers/macos/build-plan.mjs --version 1.2.3 --arch arm64 \
 *     --collection-url https://mdm.example/ --enroll-token t1 --dry-run
 *
 * The planner never spawns a process. `pkgbuild`, `productbuild`,
 * `productsign` and `notarytool` exist only on a Mac, so installers/macos/build.sh
 * runs them and asks this module for the paths and the signing command; that
 * keeps every decision the build makes verifiable with `node --test` on any
 * platform.
 *
 * Paths are repo-root relative and always use forward slashes: they are
 * consumed by a POSIX shell script, not by Node's path module.
 *
 * Exit codes: 0 plan printed, 2 bad arguments, 3 no signing identity.
 */
import process from 'node:process';
import { pathToFileURL } from 'node:url';

/** The architectures the agent is packaged for, named as Go names them. */
const ARCHES = ['amd64', 'arm64'];

/** Where the staged install root keeps the binary. */
const STAGED_BINARY_PATH = 'build/root/usr/local/bin/mdmagent';

/**
 * Where the staged install root keeps the LaunchDaemon plist. The file name is
 * the launchd label from agent/internal/service/launchd.go.
 */
const STAGED_PLIST_PATH = 'build/root/Library/LaunchDaemons/au.com.officehq.mdmagent.plist';

/** The version used when --version says nothing, as in scripts/build-agent.mjs. */
const DEFAULT_VERSION = '0.0.0-dev';

/**
 * The refusal the agent itself prints for a collection URL it will not use.
 * It is the message of config.ErrCollectionURL in
 * agent/internal/config/config.go: the installer must refuse exactly what the
 * agent refuses, or a package would install a config the agent cannot load.
 */
export const COLLECTION_URL_MESSAGE = 'collection url must be an https url';

/** The refusal for an architecture the agent is not built for. */
export const ARCH_MESSAGE = 'unsupported arch';

/** The refusal for a build that would produce an unsigned package. */
export const SIGN_IDENTITY_MESSAGE = 'signing identity not set';

/** Exit codes, named so the CLI and its tests agree on them. */
export const EXIT_OK = 0;
export const EXIT_USAGE = 2;
export const EXIT_UNSIGNED = 3;

/** The environment variable holding the Developer ID Installer identity. */
export const SIGN_IDENTITY_VAR = 'MDM_SIGN_IDENTITY';

/** The architectures a package may be built for. */
export function arches() {
  return [...ARCHES];
}

/**
 * True when `raw` is a URL the agent may send collections to: https, with a
 * host. This mirrors config.ValidateCollectionURL.
 */
export function isCollectionUrl(raw) {
  if (typeof raw !== 'string' || raw === '') {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:' && parsed.host !== '';
}

/**
 * Everything wrong with these inputs, in order, as the messages the CLI prints.
 * An empty array means the inputs are usable.
 */
export function problems({ collectionUrl, arch } = {}) {
  const found = [];
  if (!isCollectionUrl(collectionUrl)) {
    found.push(COLLECTION_URL_MESSAGE);
  }
  if (!ARCHES.includes(arch)) {
    found.push(ARCH_MESSAGE);
  }
  return found;
}

/**
 * The plan for one package.
 *
 * Returns the two staging paths, the unsigned package and the signed package
 * the build produces, plus the `productsign` argv when a signing identity was
 * supplied. Without an identity there is no `signCommand`: an unsigned package
 * is not a package this project ships, so the caller is expected to stop.
 *
 * `enrollToken` is part of the inputs because it is what the installer writes
 * into the config; it does not appear in any path and is never logged.
 *
 * Throws on a collection URL that is not https or an architecture the agent is
 * not built for; the error carries the CLI's exit code on `exitCode`.
 */
export function planPackage({ version, arch, collectionUrl, enrollToken, signIdentity } = {}) {
  void enrollToken;

  const found = problems({ collectionUrl, arch });
  if (found.length > 0) {
    const error = new Error(found[0]);
    error.exitCode = EXIT_USAGE;
    throw error;
  }

  const stamped = version ?? DEFAULT_VERSION;
  const unsignedPath = `build/OfficeHQ-MDM-${stamped}-${arch}-unsigned.pkg`;
  const outputPath = `dist/OfficeHQ-MDM-${stamped}-${arch}.pkg`;

  const plan = {
    stagedBinaryPath: STAGED_BINARY_PATH,
    stagedPlistPath: STAGED_PLIST_PATH,
    unsignedPath,
    outputPath,
  };

  if (typeof signIdentity === 'string' && signIdentity !== '') {
    plan.signCommand = ['productsign', '--sign', signIdentity, unsignedPath, outputPath];
  }
  return plan;
}

/** The four plan paths, in the order the CLI prints them and build.sh reads them. */
export function planLines(plan) {
  return [plan.stagedBinaryPath, plan.stagedPlistPath, plan.unsignedPath, plan.outputPath];
}

const FLAGS = {
  '--version': 'version',
  '--arch': 'arch',
  '--collection-url': 'collectionUrl',
  '--enroll-token': 'enrollToken',
};

function parseArgs(argv) {
  const options = { version: undefined, arch: undefined, collectionUrl: undefined, enrollToken: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      // Accepted for symmetry with scripts/build-agent.mjs. The planner never
      // spawns anything, so a dry run is all it ever does.
      continue;
    }
    const separator = arg.indexOf('=');
    const name = separator === -1 ? arg : arg.slice(0, separator);
    const key = FLAGS[name];
    if (key === undefined) {
      return { error: `unknown argument: ${arg}` };
    }
    if (separator === -1) {
      options[key] = argv[i + 1];
      i += 1;
    } else {
      options[key] = arg.slice(separator + 1);
    }
  }
  return options;
}

/** Runs the CLI and returns the process exit code. */
export function main(argv = process.argv.slice(2), env = process.env) {
  const options = parseArgs(argv);
  if (options.error) {
    console.error(options.error);
    return EXIT_USAGE;
  }

  // Arguments first and all of them: a caller who got two flags wrong is told
  // about both, and nothing reaches stdout.
  const found = problems(options);
  if (found.length > 0) {
    for (const problem of found) {
      console.error(problem);
    }
    return EXIT_USAGE;
  }

  const signIdentity = env[SIGN_IDENTITY_VAR] ?? '';
  if (signIdentity === '') {
    console.error(SIGN_IDENTITY_MESSAGE);
    return EXIT_UNSIGNED;
  }

  for (const line of planLines(planPackage({ ...options, signIdentity }))) {
    console.log(line);
  }
  return EXIT_OK;
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = main();
}
