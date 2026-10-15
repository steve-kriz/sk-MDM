import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeBmp, encodePng, render } from '../branding/render.mjs';

const BRANDING = fileURLToPath(new URL('../branding/', import.meta.url));

/** Width, height, bits per pixel and compression of a BMP. */
function bmpInfo(buffer) {
  return {
    magic: buffer.toString('ascii', 0, 2),
    fileSize: buffer.readUInt32LE(2),
    width: buffer.readInt32LE(18),
    height: buffer.readInt32LE(22),
    bitsPerPixel: buffer.readUInt16LE(28),
    compression: buffer.readUInt32LE(30),
  };
}

/** Width and height from a PNG's IHDR. */
function pngSize(buffer) {
  strictEqual(buffer.readUInt32BE(0), 0x89504e47);
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

const TEST_SVG = Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50" viewBox="0 0 200 50">' +
    '<rect width="200" height="50" fill="#e4002b"/></svg>',
);

test('encodeBmp writes an uncompressed 24-bit bottom-up BMP', () => {
  // 2x1: red then half-transparent blue (composited onto white).
  const bmp = encodeBmp(2, 1, Buffer.from([255, 0, 0, 255, 0, 0, 255, 128]));
  deepStrictEqual(bmpInfo(bmp), {
    magic: 'BM',
    fileSize: 54 + 8,
    width: 2,
    height: 1,
    bitsPerPixel: 24,
    compression: 0,
  });
  // BGR, row padded to 8 bytes.
  deepStrictEqual([...bmp.subarray(54)], [0, 0, 255, 255, 127, 127, 0, 0]);
});

test('encodeBmp refuses a buffer of the wrong size', () => {
  throws(() => encodeBmp(2, 2, Buffer.alloc(4)), /does not match/);
});

test('encodePng writes a PNG of the given size', () => {
  deepStrictEqual(pngSize(encodePng(3, 2, Buffer.alloc(24))), { width: 3, height: 2 });
});

test('render produces every output at the size the installers need', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'mdm-branding-'));
  try {
    await render({ svg: TEST_SVG, directory });
    const banner = bmpInfo(readFileSync(path.join(directory, 'banner.bmp')));
    strictEqual(banner.width, 493);
    strictEqual(banner.height, 58);
    strictEqual(banner.bitsPerPixel, 24);
    const dialog = bmpInfo(readFileSync(path.join(directory, 'dialog.bmp')));
    strictEqual(dialog.width, 493);
    strictEqual(dialog.height, 312);
    deepStrictEqual(pngSize(readFileSync(path.join(directory, 'macos-background.png'))), {
      width: 1240,
      height: 836,
    });
    strictEqual(pngSize(readFileSync(path.join(directory, 'logo.png'))).width, 480);

    // The banner's logo sits on the right: the left edge stays white and the
    // right side carries the logo's colour.
    const bmp = readFileSync(path.join(directory, 'banner.bmp'));
    const rowSize = Math.ceil((493 * 3) / 4) * 4;
    const pixel = (x, y) => [...bmp.subarray(54 + (57 - y) * rowSize + x * 3, 54 + (57 - y) * rowSize + x * 3 + 3)];
    deepStrictEqual(pixel(10, 29), [255, 255, 255]);
    deepStrictEqual(pixel(470, 29), [0x2b, 0x00, 0xe4]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

const committed = ['logo-au.svg', 'banner.bmp', 'dialog.bmp', 'macos-background.png', 'logo.png'];
const missing = committed.filter((name) => !existsSync(path.join(BRANDING, name)));

test(
  'the committed branding assets have the expected formats and sizes',
  { skip: missing.length > 0 && `missing ${missing.join(', ')}: fetch logo-au.svg and run render.mjs` },
  () => {
    ok(readFileSync(path.join(BRANDING, 'logo-au.svg'), 'utf8').includes('<svg'));
    const banner = bmpInfo(readFileSync(path.join(BRANDING, 'banner.bmp')));
    deepStrictEqual([banner.width, banner.height, banner.bitsPerPixel, banner.compression], [493, 58, 24, 0]);
    const dialog = bmpInfo(readFileSync(path.join(BRANDING, 'dialog.bmp')));
    deepStrictEqual([dialog.width, dialog.height, dialog.bitsPerPixel, dialog.compression], [493, 312, 24, 0]);
    deepStrictEqual(pngSize(readFileSync(path.join(BRANDING, 'macos-background.png'))), { width: 1240, height: 836 });
    strictEqual(pngSize(readFileSync(path.join(BRANDING, 'logo.png'))).width, 480);
  },
);
