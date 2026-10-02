/**
 * Copy the admin console's browser files into the build output.
 *
 *   src/ui/public -> dist/ui/public
 *   src/ui/views  -> dist/ui/views
 *
 * `tsc` compiles `.ts` and ignores everything else, but the Lambda's code asset
 * is `dist` (see `src/infra/mdm-stack.ts`), so the HTML, CSS and browser
 * modules have to land there to be shipped -- and to sit next to the compiled
 * `dist/ui/index.js` that resolves them relative to `import.meta.url`.
 *
 * Run as part of `npm run build`; copying is idempotent and overwrites.
 */
import { cpSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DIRECTORIES = ['public', 'views'];

const root = new URL('../', import.meta.url);

for (const directory of DIRECTORIES) {
  const from = fileURLToPath(new URL(`src/ui/${directory}/`, root));
  const to = fileURLToPath(new URL(`dist/ui/${directory}/`, root));
  if (!existsSync(from)) {
    continue;
  }
  cpSync(from, to, { recursive: true });
}
