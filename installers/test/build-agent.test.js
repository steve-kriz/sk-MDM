import { test } from 'node:test';
import { deepStrictEqual, strictEqual, match } from 'node:assert';
import {
  targets,
  isSupportedTarget,
  outputPath,
  version,
  ldflags,
  buildArgs,
  buildEnv,
} from '../../scripts/build-agent.mjs';

test('targets returns all supported platforms', () => {
  const result = targets();
  deepStrictEqual(result, ['windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64']);
});

test('isSupportedTarget returns true for valid targets', () => {
  strictEqual(isSupportedTarget('windows/amd64'), true);
  strictEqual(isSupportedTarget('windows/arm64'), true);
  strictEqual(isSupportedTarget('darwin/amd64'), true);
  strictEqual(isSupportedTarget('darwin/arm64'), true);
});

test('isSupportedTarget returns false for invalid targets', () => {
  strictEqual(isSupportedTarget('linux/amd64'), false);
  strictEqual(isSupportedTarget('windows/386'), false);
  strictEqual(isSupportedTarget('invalid'), false);
});

test('outputPath for windows includes .exe suffix', () => {
  const path = outputPath('windows/amd64');
  strictEqual(path.endsWith('.exe'), true);
  strictEqual(path.includes('mdmagent-windows-amd64.exe'), true);
});

test('outputPath for darwin has no suffix', () => {
  const path = outputPath('darwin/amd64');
  strictEqual(path.endsWith('.exe'), false);
  strictEqual(path.includes('mdmagent-darwin-amd64'), true);
});

test('version returns AGENT_VERSION when set', () => {
  const env = { AGENT_VERSION: '1.2.3' };
  strictEqual(version(env), '1.2.3');
});

test('version returns default when AGENT_VERSION not set', () => {
  const env = {};
  strictEqual(version(env), '0.0.0-dev');
});

test('version with no env argument uses process.env', () => {
  // This test just ensures the function doesn't crash when called with no args
  const result = version();
  strictEqual(typeof result, 'string');
});

test('ldflags produces correct format', () => {
  const flags = ldflags('1.2.3');
  strictEqual(flags.includes('-s'), true);
  strictEqual(flags.includes('-w'), true);
  strictEqual(flags.includes('-X github.com/officehq/sk-mdm/agent/internal/version.Version=1.2.3'), true);
});

test('ldflags escapes special characters in version', () => {
  const flags = ldflags('1.2.3-beta+build');
  strictEqual(flags.includes('1.2.3-beta+build'), true);
});

test('buildArgs includes build, trimpath, ldflags, output and package', () => {
  const args = buildArgs('darwin/amd64', '1.2.3');
  deepStrictEqual(args[0], 'build');
  deepStrictEqual(args[1], '-trimpath');
  deepStrictEqual(args.includes('-ldflags'), true);
  deepStrictEqual(args.includes('-o'), true);
  deepStrictEqual(args.includes('./cmd/mdmagent'), true);
});

test('buildArgs ldflags contain version', () => {
  const args = buildArgs('darwin/amd64', '2.0.0');
  const ldflagsIdx = args.indexOf('-ldflags');
  strictEqual(ldflagsIdx !== -1, true);
  strictEqual(args[ldflagsIdx + 1].includes('2.0.0'), true);
});

test('buildArgs output path matches outputPath', () => {
  const args = buildArgs('windows/amd64', '1.0.0');
  const oIdx = args.indexOf('-o');
  const pathArg = args[oIdx + 1];
  strictEqual(pathArg, outputPath('windows/amd64'));
});

test('buildEnv sets GOOS correctly', () => {
  const env = buildEnv('windows/amd64');
  strictEqual(env.GOOS, 'windows');

  const env2 = buildEnv('darwin/arm64');
  strictEqual(env2.GOOS, 'darwin');
});

test('buildEnv sets GOARCH correctly', () => {
  const env = buildEnv('windows/amd64');
  strictEqual(env.GOARCH, 'amd64');

  const env2 = buildEnv('darwin/arm64');
  strictEqual(env2.GOARCH, 'arm64');
});

test('buildEnv sets CGO_ENABLED to 0', () => {
  const env = buildEnv('windows/amd64');
  strictEqual(env.CGO_ENABLED, '0');

  const env2 = buildEnv('darwin/amd64');
  strictEqual(env2.CGO_ENABLED, '0');
});

test('ldflags strip symbols with -s flag', () => {
  const flags = ldflags('1.0.0');
  strictEqual(flags.includes(' -s ') || flags.startsWith('-s'), true);
});

test('ldflags strip DWARF with -w flag', () => {
  const flags = ldflags('1.0.0');
  strictEqual(flags.includes(' -w ') || flags.includes('-w'), true);
});

test('buildArgs for different targets produce correct output paths', () => {
  const args1 = buildArgs('windows/amd64', '1.0.0');
  const args2 = buildArgs('darwin/arm64', '1.0.0');

  const oIdx1 = args1.indexOf('-o');
  const oIdx2 = args2.indexOf('-o');

  const path1 = args1[oIdx1 + 1];
  const path2 = args2[oIdx2 + 1];

  strictEqual(path1 !== path2, true);
  strictEqual(path1.includes('windows'), true);
  strictEqual(path2.includes('darwin'), true);
});

test('version with multiple platforms produces same version', () => {
  const env = { AGENT_VERSION: '2.3.4' };
  const v1 = version(env);
  const v2 = version(env);
  strictEqual(v1, v2);
});

test('buildEnv for all targets include CGO_ENABLED', () => {
  const allTargets = ['windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64'];
  for (const target of allTargets) {
    const env = buildEnv(target);
    strictEqual(env.CGO_ENABLED, '0');
  }
});

test('outputPath is consistent across calls', () => {
  const path1 = outputPath('darwin/amd64');
  const path2 = outputPath('darwin/amd64');
  strictEqual(path1, path2);
});
