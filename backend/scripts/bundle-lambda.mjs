/**
 * Bundle the Lambda entry points into self-contained ES modules.
 *
 *   src/lambda.ts -> dist-lambda/index.mjs   (AWS SDK bundled, not external)
 *   src/ui/public -> dist-lambda/public
 *   src/ui/views  -> dist-lambda/views
 *   src/hasher.ts -> dist-hasher/index.mjs   (the URL hasher Lambda, TASK-050; no UI files)
 *
 * The Lambda's code asset is `dist-lambda` (see `src/infra/mdm-stack.ts`) and
 * carries no `node_modules`, so every runtime dependency has to be inside the
 * bundle. `src/ui/index.ts` resolves `./public/` and `./views/` relative to
 * `import.meta.url`, which in the bundle is `index.mjs`, so the browser files
 * are copied beside it.
 *
 * Run as part of `npm run build`; bundling and copying are idempotent and overwrite.
 */
import { cpSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const DIRECTORIES = ['public', 'views'];

const root = new URL('../', import.meta.url);
const outDir = fileURLToPath(new URL('dist-lambda/', root));
const hasherOutDir = fileURLToPath(new URL('dist-hasher/', root));

/** The esbuild options both bundles share. */
const BUILD_OPTIONS = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  logLevel: 'warning',
  // Some bundled dependencies are CommonJS and call `require` for Node
  // built-ins, which an ES module does not define on its own.
  banner: {
    js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);",
  },
};

rmSync(outDir, { recursive: true, force: true });

await build({
  ...BUILD_OPTIONS,
  entryPoints: [fileURLToPath(new URL('src/lambda.ts', root))],
  outfile: fileURLToPath(new URL('dist-lambda/index.mjs', root)),
});

for (const directory of DIRECTORIES) {
  const from = fileURLToPath(new URL(`src/ui/${directory}/`, root));
  const to = fileURLToPath(new URL(`dist-lambda/${directory}/`, root));
  if (!existsSync(from)) {
    continue;
  }
  cpSync(from, to, { recursive: true });
}

// TASK-050: the URL hasher Lambda's own asset, `index.mjs` only.
rmSync(hasherOutDir, { recursive: true, force: true });

await build({
  ...BUILD_OPTIONS,
  entryPoints: [fileURLToPath(new URL('src/hasher.ts', root))],
  outfile: fileURLToPath(new URL('dist-hasher/index.mjs', root)),
});
