import assert from 'node:assert/strict';
import { readFileSync, utimesSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { CallCatalog, callIdOf } from '../../server/calls.ts';
import { createTempProject, makeWav, readFixture } from './support.ts';

const projects: ReturnType<typeof createTempProject>[] = [];
after(() => {
  for (const project of projects) project.cleanup();
});

function catalogFor(calls = ['fake_kyc.wav'], audioCacheEntries = 8) {
  const project = createTempProject(calls);
  projects.push(project);
  const warnings: string[] = [];
  const catalog = new CallCatalog({
    callsDir: project.config.paths.calls,
    cacheDir: project.config.paths.cache,
    manifestPath: project.config.paths.manifest,
    chunkSec: 6,
    audioCacheEntries,
    logger: { warn: (message: string) => warnings.push(message) },
  });
  return { project, catalog, warnings };
}

describe('CallCatalog manifest', () => {
  test('lists calls with silence-aware chunks from the golden fixture', () => {
    const { catalog } = catalogFor();
    const [call] = catalog.list();
    const golden = readFixture<{ demo_calls: { file: string; boundaries: number[][] }[] }>(
      'chunk_boundaries.json',
    ).demo_calls.find((c) => c.file === 'fake_kyc.wav');
    assert.equal(call?.id, 'fake_kyc');
    assert.equal(call?.has_cache, false);
    assert.deepEqual(
      call?.chunks.map((c) => [c.start_s, c.end_s]),
      golden?.boundaries,
    );
  });

  test('skips invalid entries and survives unreadable manifests', () => {
    const { project, catalog, warnings } = catalogFor();
    writeFileSync(
      project.config.paths.manifest,
      JSON.stringify([
        { file: 'fake_kyc.wav', title: 'ok', expected: 'SCAM' },
        { file: '../escape.wav', title: 'bad', expected: 'SCAM' },
        { file: 'x.wav', title: 'bad', expected: 'MAYBE' },
      ]),
    );
    assert.equal(catalog.loadManifest().length, 1);
    assert.equal(warnings.length, 2);

    writeFileSync(project.config.paths.manifest, '{not json');
    assert.deepEqual(catalog.loadManifest(), []);
    writeFileSync(project.config.paths.manifest, '{"not": "an array"}');
    assert.deepEqual(catalog.loadManifest(), []);
  });

  test('saves the manifest atomically and finds entries by id or file', () => {
    const { project, catalog } = catalogFor();
    catalog.saveManifest([{ file: 'fake_kyc.wav', title: 'Renamed', expected: 'SAFE' }]);
    assert.equal(project.readManifest()[0]?.title, 'Renamed');
    assert.ok(readFileSync(project.config.paths.manifest, 'utf8').endsWith('\n'));
    assert.equal(catalog.findEntry('fake_kyc')?.title, 'Renamed');
    assert.equal(catalog.findEntry('fake_kyc.wav')?.expected, 'SAFE');
    assert.equal(catalog.findEntry('missing'), undefined);
  });

  test('returns an empty catalog when there is no manifest', () => {
    const { catalog } = catalogFor([]);
    catalog.saveManifest([]);
    assert.deepEqual(catalog.list(), []);
    const empty = new CallCatalog({
      callsDir: '/nonexistent',
      cacheDir: '/nonexistent',
      manifestPath: '/nonexistent/manifest.json',
      chunkSec: 6,
      audioCacheEntries: 1,
    });
    assert.deepEqual(empty.loadManifest(), []);
  });
});

describe('CallCatalog audio', () => {
  test('reports a missing recording as having no chunks', () => {
    const { catalog } = catalogFor();
    const call = catalog.describe({ file: 'ghost.wav', title: 'Ghost', expected: 'SAFE' });
    assert.deepEqual([call.duration, call.chunks], [0, []]);
    assert.equal(catalog.readAudio('ghost.wav'), null);
  });

  test('caches decoded audio until the file changes', () => {
    const { project, catalog } = catalogFor();
    const first = catalog.readAudio('fake_kyc.wav');
    assert.equal(catalog.readAudio('fake_kyc.wav'), first);

    const filePath = path.join(project.config.paths.calls, 'fake_kyc.wav');
    writeFileSync(filePath, makeWav([{ seconds: 1, amplitude: 100 }]));
    const later = new Date(Date.now() + 5_000);
    utimesSync(filePath, later, later);
    const refreshed = catalog.readAudio('fake_kyc.wav');
    assert.notEqual(refreshed, first);
    assert.equal(refreshed?.info.durationSec, 1);
    assert.equal(
      catalog.describe({ file: 'fake_kyc.wav', title: 't', expected: 'SCAM' }).duration,
      1,
    );
  });

  test('keeps at most N decoded recordings in memory', () => {
    const { project, catalog } = catalogFor(['fake_kyc.wav'], 1);
    writeFileSync(
      path.join(project.config.paths.calls, 'second.wav'),
      makeWav([{ seconds: 1, amplitude: 1 }]),
    );
    const first = catalog.readAudio('fake_kyc.wav');
    catalog.readAudio('second.wav');
    assert.notEqual(catalog.readAudio('fake_kyc.wav'), first);
  });

  test('logs and skips recordings that are not valid WAVs', () => {
    const { project, catalog, warnings } = catalogFor();
    writeFileSync(path.join(project.config.paths.calls, 'broken.wav'), 'not audio');
    const call = catalog.describe({ file: 'broken.wav', title: 'Broken', expected: 'SCAM' });
    assert.deepEqual(call.chunks, []);
    assert.match(warnings.join('\n'), /Cannot chunk broken\.wav/);
  });
});

describe('CallCatalog replay cache', () => {
  test('reads cache/<call>.json and flags its presence', () => {
    const { project, catalog } = catalogFor();
    assert.equal(catalog.readReplayCache('fake_kyc'), null);
    writeFileSync(path.join(project.config.paths.cache, 'fake_kyc.json'), '{"chunks": []}');
    assert.deepEqual(catalog.readReplayCache('fake_kyc'), { chunks: [] });
    assert.equal(catalog.list()[0]?.has_cache, true);
  });

  test('derives call ids from file names', () => {
    assert.equal(callIdOf('upload_mom.wav'), 'upload_mom');
  });
});
