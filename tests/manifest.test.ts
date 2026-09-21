/**
 * @file The manifest and the package agree.
 *
 * They are two files with one version between them, and nothing but attention
 * keeps them equal. A release is named after `package.json` and installs
 * whatever `manifest.json` says, so a drift ships an archive called one thing
 * that the browser reports as another — and the first person to notice is
 * someone trying to work out which build they are running.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const read = (path: string): Record<string, unknown> =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../${path}`, import.meta.url)), 'utf8')) as Record<
    string,
    unknown
  >;

describe('the manifest', () => {
  const pkg = read('package.json');
  const manifest = read('public/manifest.json');

  it('carries the same version as the package', () => {
    expect(manifest['version']).toBe(pkg['version']);
  });

  it('uses a version the browsers accept', () => {
    // Up to four dot-separated integers, which is all Chrome and Firefox take.
    expect(String(manifest['version'])).toMatch(/^\d+(\.\d+){0,3}$/);
  });
});
