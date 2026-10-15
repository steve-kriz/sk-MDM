#!/usr/bin/env node
/**
 * Renders the OfficeHQ logo into the bitmaps the installers ship.
 *
 *   node installers/branding/render.mjs
 *
 * Input:  installers/branding/logo-au.svg, a committed copy of
 *         https://www.officehq.com.au/wp-content/themes/thevariousartists/dist/images/logo-au.svg
 * Output (all committed next to this script, builds never render or fetch):
 *
 *   banner.bmp            493x58   WixUIBannerBmp: logo right-aligned on white
 *   dialog.bmp            493x312  WixUIDialogBmp: logo in the left panel
 *   macos-background.png  1240x836 Installer.app background (620x418 at 2x),
 *                                  transparent with the logo bottom-left
 *   logo.png              480 wide welcome page / sign-in pages logo
 *
 * The MSI bitmaps must be uncompressed 24-bit BMPs, which no dependency
 * writes, so `encodeBmp` below does it.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const LOGO_SVG = path.join(HERE, 'logo-au.svg');

const WHITE = [255, 255, 255, 255];
const PANEL = [243, 244, 246, 255];

/**
 * Every output: its file, canvas size, encoding, background fills and where the
 * logo goes. `logo` fits the logo inside a box (x, y, width, height) and aligns
 * it in that box horizontally (`align`: left | center | right) and vertically
 * (`valign`: top | middle | bottom).
 */
export const OUTPUTS = [
  {
    file: 'banner.bmp',
    width: 493,
    height: 58,
    format: 'bmp',
    fills: [{ x: 0, y: 0, width: 493, height: 58, color: WHITE }],
    logo: { x: 313, y: 11, width: 168, height: 36, align: 'right', valign: 'middle' },
  },
  {
    file: 'dialog.bmp',
    width: 493,
    height: 312,
    format: 'bmp',
    // The welcome and exit dialogs draw their text over the right-hand 329px,
    // so only the left panel carries the logo.
    fills: [
      { x: 0, y: 0, width: 493, height: 312, color: WHITE },
      { x: 0, y: 0, width: 164, height: 312, color: PANEL },
    ],
    logo: { x: 16, y: 24, width: 132, height: 60, align: 'center', valign: 'top' },
  },
  {
    file: 'macos-background.png',
    width: 1240,
    height: 836,
    format: 'png',
    fills: [],
    logo: { x: 40, y: 716, width: 260, height: 80, align: 'left', valign: 'bottom' },
  },
  {
    file: 'logo.png',
    width: 480,
    height: null,
    format: 'png',
    fills: [],
    logo: null,
  },
];

/**
 * An uncompressed, bottom-up, 24-bit BMP of an RGBA buffer. Transparent pixels
 * are composited onto white, since the format carries no alpha.
 */
export function encodeBmp(width, height, rgba) {
  if (rgba.length !== width * height * 4) {
    throw new Error('rgba buffer does not match the image size');
  }
  const rowSize = Math.ceil((width * 3) / 4) * 4;
  const imageSize = rowSize * height;
  const fileSize = 54 + imageSize;
  const out = Buffer.alloc(fileSize);

  // BITMAPFILEHEADER
  out.write('BM', 0, 'ascii');
  out.writeUInt32LE(fileSize, 2);
  out.writeUInt32LE(54, 10);
  // BITMAPINFOHEADER
  out.writeUInt32LE(40, 14);
  out.writeInt32LE(width, 18);
  out.writeInt32LE(height, 22);
  out.writeUInt16LE(1, 26);
  out.writeUInt16LE(24, 28);
  out.writeUInt32LE(0, 30); // BI_RGB: uncompressed
  out.writeUInt32LE(imageSize, 34);
  out.writeInt32LE(2835, 38); // 72 dpi
  out.writeInt32LE(2835, 42);

  for (let y = 0; y < height; y += 1) {
    const row = 54 + (height - 1 - y) * rowSize;
    for (let x = 0; x < width; x += 1) {
      const i = (y * width + x) * 4;
      const a = rgba[i + 3] / 255;
      const o = row + x * 3;
      out[o] = Math.round(rgba[i + 2] * a + 255 * (1 - a));
      out[o + 1] = Math.round(rgba[i + 1] * a + 255 * (1 - a));
      out[o + 2] = Math.round(rgba[i] * a + 255 * (1 - a));
    }
  }
  return out;
}

/** Source-over composite of `src` (sw x sh RGBA) onto `dst` at (dx, dy). */
export function composite(dst, dw, dh, src, sw, sh, dx, dy) {
  for (let y = 0; y < sh; y += 1) {
    const ty = dy + y;
    if (ty < 0 || ty >= dh) continue;
    for (let x = 0; x < sw; x += 1) {
      const tx = dx + x;
      if (tx < 0 || tx >= dw) continue;
      const s = (y * sw + x) * 4;
      const d = (ty * dw + tx) * 4;
      const sa = src[s + 3] / 255;
      const da = dst[d + 3] / 255;
      const oa = sa + da * (1 - sa);
      for (let c = 0; c < 3; c += 1) {
        dst[d + c] = oa === 0 ? 0 : Math.round((src[s + c] * sa + dst[d + c] * da * (1 - sa)) / oa);
      }
      dst[d + 3] = Math.round(oa * 255);
    }
  }
}

function fill(dst, dw, { x, y, width, height, color }) {
  for (let row = y; row < y + height; row += 1) {
    for (let col = x; col < x + width; col += 1) {
      dst.set(color, (row * dw + col) * 4);
    }
  }
}

/** The logo rendered to fit inside `box`, as { width, height, pixels }. */
function renderLogo(Resvg, svg, box) {
  const probe = new Resvg(svg).render();
  const scale = Math.min(box.width / probe.width, box.height / probe.height);
  const fitted = new Resvg(svg, { fitTo: { mode: 'zoom', value: scale } }).render();
  return { width: fitted.width, height: fitted.height, pixels: fitted.pixels };
}

function offset(start, room, size, align) {
  if (align === 'right' || align === 'bottom') return start + room - size;
  if (align === 'center' || align === 'middle') return start + Math.floor((room - size) / 2);
  return start;
}

/** Renders every output from `svg` into `directory` and returns the files written. */
export async function render({ svg = readFileSync(LOGO_SVG), directory = HERE } = {}) {
  const { Resvg } = await import('@resvg/resvg-js');
  const written = [];

  for (const output of OUTPUTS) {
    let png;
    let width = output.width;
    let height = output.height;
    let rgba;

    if (output.logo === null) {
      const image = new Resvg(svg, { fitTo: { mode: 'width', value: output.width } }).render();
      width = image.width;
      height = image.height;
      rgba = Buffer.from(image.pixels);
      png = image.asPng();
    } else {
      rgba = Buffer.alloc(width * height * 4);
      for (const area of output.fills) fill(rgba, width, area);
      const logo = renderLogo(Resvg, svg, output.logo);
      composite(
        rgba,
        width,
        height,
        logo.pixels,
        logo.width,
        logo.height,
        offset(output.logo.x, output.logo.width, logo.width, output.logo.align),
        offset(output.logo.y, output.logo.height, logo.height, output.logo.valign),
      );
    }

    const target = path.join(directory, output.file);
    if (output.format === 'bmp') {
      writeFileSync(target, encodeBmp(width, height, rgba));
    } else {
      writeFileSync(target, png ?? encodePng(width, height, rgba));
    }
    written.push(`${output.file} ${width}x${height}`);
  }
  return written;
}

/** A minimal RGBA PNG encoder (one IDAT, no filtering), via node:zlib. */
export function encodePng(width, height, rgba) {
  const { deflateSync, crc32 } = zlib;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    raw[y * (width * 4 + 1)] = 0;
    rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const chunk = (type, data) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body) >>> 0);
    return Buffer.concat([length, body, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  render().then(
    (written) => {
      for (const line of written) console.log(line);
    },
    (error) => {
      console.error(error.message);
      process.exitCode = 1;
    },
  );
}
