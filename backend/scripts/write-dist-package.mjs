/**
 * Write `dist/package.json` marking the build output as ES modules.
 *
 * `tsc` emits ESM, and Node only loads `.js` files as ESM when the nearest
 * `package.json` says `"type": "module"`. The Lambda's code asset is `dist`
 * alone (see `src/infra/mdm-stack.ts`), so `backend/package.json` is not
 * shipped and, without this file, the runtime loads `index.js` as CommonJS and
 * fails at init with "Cannot use import statement outside a module".
 *
 * Run as part of `npm run build`; writing is idempotent and overwrites.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const dist = new URL('../dist/', import.meta.url);

mkdirSync(fileURLToPath(dist), { recursive: true });
writeFileSync(fileURLToPath(new URL('package.json', dist)), `${JSON.stringify({ type: 'module' }, null, 2)}\n`);
