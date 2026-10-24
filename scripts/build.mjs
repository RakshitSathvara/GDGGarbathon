#!/usr/bin/env node
/**
 * Produces a self-contained static bundle in dist/ for static hosts:
 *   dist/index.html      – the app shell (copied from static/index.html)
 *   dist/static/**       – CSS and JS modules referenced by the shell
 *   dist/calls/**        – demo call recordings and manifest
 *
 * The Node (server.ts) and Python (app/main.py) servers serve static/ directly,
 * so dist/ is only needed for deployments that host the frontend separately.
 *
 * Usage: node scripts/build.mjs [--clean]
 */
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(rootDir, 'dist');

rmSync(distDir, { recursive: true, force: true });
if (process.argv.includes('--clean')) {
  console.log('Removed dist/');
  process.exit(0);
}

mkdirSync(distDir, { recursive: true });
cpSync(join(rootDir, 'static'), join(distDir, 'static'), { recursive: true });
cpSync(join(rootDir, 'static', 'index.html'), join(distDir, 'index.html'));
cpSync(join(rootDir, 'calls'), join(distDir, 'calls'), { recursive: true });
console.log('Built dist/ (index.html, static/, calls/)');
