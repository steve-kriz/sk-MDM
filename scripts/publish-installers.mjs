#!/usr/bin/env node
/**
 * Publishes the built agent installers to the private installer bucket.
 *
 *   node scripts/publish-installers.mjs --bucket <InstallerBucketName> --version 1.2.3 --dry-run
 *   node scripts/publish-installers.mjs --bucket <InstallerBucketName> --version 1.2.3
 *
 * Each build output -- `dist/OfficeHQ-MDM-<version>-<arch>.msi` from
 * installers/windows/build-plan.mjs and `dist/OfficeHQ-MDM-<version>-<arch>.pkg`
 * from installers/macos/build-plan.mjs -- is copied with `aws s3 cp` to the
 * fixed "latest" key `GET /downloads/{platform}` serves, carrying a versioned
 * `Content-Disposition` file name. Absent files are skipped; a dry run prints
 * every planned upload and spawns nothing.
 *
 * Exit codes: 0 success, 1 nothing to upload or an upload failed, 2 bad usage.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..');

/**
 * The published installers in `DOWNLOAD_PLATFORMS` order
 * (backend/src/routes/downloads.ts): the build's arch and extension, and the
 * fixed key the download route reads.
 */
const INSTALLERS = [
  { arch: 'x64', ext: 'msi', key: 'installers/windows-x64.msi' },
  { arch: 'arm64', ext: 'msi', key: 'installers/windows-arm64.msi' },
  { arch: 'amd64', ext: 'pkg', key: 'installers/macos-amd64.pkg' },
  { arch: 'arm64', ext: 'pkg', key: 'installers/macos-arm64.pkg' },
];

const CONTENT_TYPES = { msi: 'application/x-msi', pkg: 'application/octet-stream' };

/**
 * Every upload for a version: the repo-relative, forward-slash build output,
 * its absolute path, the destination key and the content type.
 */
export function planUploads(version) {
  return INSTALLERS.map(({ arch, ext, key }) => {
    const relativePath = `dist/OfficeHQ-MDM-${version}-${arch}.${ext}`;
    return {
      relativePath,
      absolutePath: path.join(REPO_ROOT, relativePath),
      fileName: path.posix.basename(relativePath),
      key,
      contentType: CONTENT_TYPES[ext],
    };
  });
}

/** The argv `aws` is invoked with for one upload. */
export function awsArgs(upload, bucket) {
  return [
    's3',
    'cp',
    upload.absolutePath,
    `s3://${bucket}/${upload.key}`,
    '--content-type',
    upload.contentType,
    '--content-disposition',
    `attachment; filename="${upload.fileName}"`,
  ];
}

function parseArgs(argv) {
  const options = { dryRun: false, bucket: null, version: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--bucket') {
      options.bucket = argv[i + 1] ?? '';
      i += 1;
    } else if (arg.startsWith('--bucket=')) {
      options.bucket = arg.slice('--bucket='.length);
    } else if (arg === '--version') {
      options.version = argv[i + 1] ?? '';
      i += 1;
    } else if (arg.startsWith('--version=')) {
      options.version = arg.slice('--version='.length);
    } else {
      return { error: `unknown argument: ${arg}` };
    }
  }
  return options;
}

/**
 * Runs the CLI and returns the process exit code.
 *
 * `spawn` and `env` are injected so a dry run can be proven to spawn nothing
 * and a test can name the `aws` binary through `AWS_BIN`.
 */
export function main(argv = process.argv.slice(2), { spawn = spawnSync, env = process.env } = {}) {
  const options = parseArgs(argv);
  if (options.error) {
    console.error(options.error);
    return 2;
  }
  if (typeof options.bucket !== 'string' || options.bucket === '') {
    console.error('bucket is required');
    return 2;
  }
  if (typeof options.version !== 'string' || options.version === '') {
    console.error('version is required');
    return 2;
  }

  const present = [];
  for (const upload of planUploads(options.version)) {
    if (existsSync(upload.absolutePath)) {
      present.push(upload);
    } else {
      console.log(`skipped ${upload.relativePath}`);
    }
  }
  if (present.length === 0) {
    console.error(`no installers found for version ${options.version}`);
    return 1;
  }

  if (options.dryRun) {
    for (const upload of present) {
      console.log(`${upload.relativePath} -> s3://${options.bucket}/${upload.key}`);
    }
    return 0;
  }

  const command = env.AWS_BIN || 'aws';
  for (const upload of present) {
    const result = spawn(command, awsArgs(upload, options.bucket), {
      cwd: REPO_ROOT,
      stdio: 'inherit',
    });
    if (!result || result.error || result.status !== 0) {
      console.error(`upload failed for ${upload.relativePath}`);
      return 1;
    }
    console.log(`${upload.relativePath} -> s3://${options.bucket}/${upload.key}`);
  }
  return 0;
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = main();
}
