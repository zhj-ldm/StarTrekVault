#!/usr/bin/env node
'use strict';
/* Star Trek Vault - icon generator (dependency-free).
   Raw RGBA scanlines + zlib deflate + hand-rolled CRC32.

   Writes:
     resources/assets/drag-icon.png   64x64   drag-out badge
     build/icon.png                   1024x1024  application icon */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');

/* ------------------------------------------------------------------ PNG writer */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function writePng(size, pixelFn, out) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  let offset = 0;
  for (let y = 0; y < size; y++) {
    raw[offset++] = 0; // filter type: none
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixelFn(x, y);
      raw[offset++] = r;
      raw[offset++] = g;
      raw[offset++] = b;
      raw[offset++] = a;
    }
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // colour type: RGBA
  ihdr[10] = 0;  // compression
  ihdr[11] = 0;  // filter
  ihdr[12] = 0;  // interlace

  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, png);
  console.log('wrote ' + out + ' (' + png.length + ' bytes, ' + size + 'x' + size + ')');
}

/* -------------------------------------------------------------------- geometry */

// Coordinate-agnostic rounded-rect test: works for integer pixels or 0..1 space.
function roundedRect(x, y, x0, y0, x1, y1, r) {
  if (x < x0 || x > x1 || y < y0 || y > y1) return false;
  const cx = x < x0 + r ? x0 + r : (x > x1 - r ? x1 - r : x);
  const cy = y < y0 + r ? y0 + r : (y > y1 - r ? y1 - r : y);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

/* ------------------------------------------------------------- drag-out badge */

const DRAG_SIZE = 64;

function dragPixel(x, y) {
  // Two LCARS bars: salmon (#ff9966) main bar, mauve (#c9c) notch.
  if (roundedRect(x, y, 3, 22, 61, 38, 6)) return [0xff, 0x99, 0x66, 0xff];
  if (roundedRect(x, y, 40, 42, 61, 56, 6)) return [0xcc, 0x99, 0xcc, 0xff];
  if (roundedRect(x, y, 3, 42, 34, 56, 6)) return [0x99, 0x99, 0xff, 0xff];
  return [0, 0, 0, 0];
}

/* ------------------------------------------------------------ application icon */

// LCARS palette: salmon #ff9966, mauve #cc99cc, blue #9999ff, amber #ff9900.
const APP_SIZE = 1024;

function keyhole(x, y) {
  // Amber vault keyhole: round head plus tapered stem, centred.
  const head = roundedRect(x, y, 0.355, 0.255, 0.645, 0.545, 0.145);
  const stem = roundedRect(x, y, 0.435, 0.470, 0.565, 0.700, 0.065);
  return head || stem;
}

function appPixel(x, y) {
  // Normalise pixel centre to 0..1 space.
  const nx = (x + 0.5) / APP_SIZE;
  const ny = (y + 0.5) / APP_SIZE;

  // Rounded black tile with a transparent margin.
  if (!roundedRect(nx, ny, 0.03, 0.03, 0.97, 0.97, 0.20)) return [0, 0, 0, 0];
  let c = [0x08, 0x08, 0x10, 0xff];

  // LCARS elbow frame with deliberate gaps, painted back-to-front.
  if (roundedRect(nx, ny, 0.795, 0.300, 0.875, 0.870, 0.040)) c = [0xcc, 0x99, 0xcc, 0xff];  // right  (mauve)
  if (roundedRect(nx, ny, 0.330, 0.795, 0.875, 0.870, 0.040)) c = [0x99, 0x99, 0xff, 0xff];  // bottom (blue)
  if (roundedRect(nx, ny, 0.130, 0.130, 0.210, 0.700, 0.040)) c = [0xff, 0x99, 0x66, 0xff];  // left   (salmon)
  if (roundedRect(nx, ny, 0.130, 0.130, 0.560, 0.210, 0.040)) c = [0xff, 0x99, 0x66, 0xff];  // top    (salmon)
  if (keyhole(nx, ny)) c = [0xff, 0x99, 0x00, 0xff];                                        // keyhole (amber)

  return c;
}

/* --------------------------------------------------------------------- main */

writePng(DRAG_SIZE, dragPixel, path.join(ROOT, 'resources', 'assets', 'drag-icon.png'));
writePng(APP_SIZE, appPixel, path.join(ROOT, 'build', 'icon.png'));
