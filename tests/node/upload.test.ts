import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { CallCatalog } from '../../server/calls.ts';
import { HttpError } from '../../server/errors.ts';
import {
  type AudioConverter,
  createFfmpegConverter,
  storeUpload,
  UPLOAD_PREFIX,
} from '../../server/upload.ts';
import { readWavInfo } from '../../server/wav.ts';
import { createTempProject, makeWav, silentLogger } from './support.ts';

const projects: ReturnType<typeof createTempProject>[] = [];
after(() => {
  for (const project of projects) project.cleanup();
});

const copyConverter: AudioConverter = async (input, output) => {
  copyFileSync(input, output);
};
const failingConverter: AudioConverter = async () => {
  throw new Error('spawn ffmpeg ENOENT');
};

function setup(convert: AudioConverter = copyConverter, maxUploadedCalls = 20) {
  const project = createTempProject();
  projects.push(project);
  const catalog = new CallCatalog({
    callsDir: project.config.paths.calls,
    cacheDir: project.config.paths.cache,
    manifestPath: project.config.paths.manifest,
    chunkSec: 6,
    audioCacheEntries: 4,
    logger: silentLogger,
  });
  const deps = {
    catalog,
    rawCallsDir: project.config.paths.rawCalls,
    maxUploadedCalls,
    convert,
    logger: silentLogger,
  };
  return { project, catalog, deps };
}

const wavBase64 = (wav = makeWav([{ seconds: 1, amplitude: 2000 }])) => wav.toString('base64');

async function expectHttpError(promise: Promise<unknown>, status: number, message: RegExp) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof HttpError);
    assert.equal(error.status, status);
    assert.match(error.message, message);
    return true;
  });
}

describe('storeUpload', () => {
  test('stores a namespaced, playable call and registers it in the manifest', async () => {
    const { project, deps } = setup();
    const entry = await storeUpload(
      { filename: 'Mom Call.wav', data_base64: wavBase64(), expected: 'SAFE' },
      deps,
    );
    assert.deepEqual(entry, {
      file: `${UPLOAD_PREFIX}mom_call.wav`,
      title: 'Uploaded — Mom Call',
      expected: 'SAFE',
      uploaded: true,
    });
    assert.ok(existsSync(path.join(project.config.paths.rawCalls, entry.file)));
    const stored = readFileSync(path.join(project.config.paths.calls, entry.file));
    assert.equal(readWavInfo(stored).durationSec, 1);
    assert.equal(project.readManifest().at(-1)?.file, entry.file);
    assert.ok(
      !readdirSync(project.config.paths.calls).some((name) => name.endsWith('.converting.wav')),
    );
  });

  test('cannot overwrite a curated demo call', async () => {
    const { project, deps } = setup();
    const entry = await storeUpload({ filename: 'fake_kyc.wav', data_base64: wavBase64() }, deps);
    assert.equal(entry.file, 'upload_fake_kyc.wav');
    assert.equal(project.readManifest()[0]?.title, 'Fake Bank KYC — Account Block & OTP Demand');
  });

  test('re-uploading the same name updates the existing entry', async () => {
    const { project, deps } = setup();
    await storeUpload({ filename: 'a.wav', data_base64: wavBase64(), title: 'First' }, deps);
    const manifest = project.readManifest();
    project.writeManifest(
      manifest.map((item) =>
        item.file === 'upload_a.wav' ? { ...item, first_demand_at: 3 } : item,
      ),
    );
    const entry = await storeUpload(
      { filename: 'a.wav', data_base64: wavBase64(), title: 'Second' },
      deps,
    );
    assert.equal(entry.title, 'Second');
    assert.equal(entry.first_demand_at, 3);
    assert.equal(project.readManifest().filter((item) => item.file === 'upload_a.wav').length, 1);
  });

  test('rejects invalid payloads with clear 4xx errors', async () => {
    const { deps } = setup();
    await expectHttpError(
      storeUpload({ filename: 'a.wav', data_base64: '@@@@' }, deps),
      400,
      /Invalid base64/,
    );
    await expectHttpError(
      storeUpload({ filename: 'a.mp3', data_base64: wavBase64() }, deps),
      400,
      /Only \.wav/,
    );
    await expectHttpError(
      storeUpload({ filename: 'a.wav', data_base64: Buffer.alloc(100).toString('base64') }, deps),
      400,
      /RIFF\/WAVE/,
    );
    const headerOnly = makeWav([{ seconds: 1, amplitude: 1 }]).subarray(0, 60);
    headerOnly.write('junk', 36, 'ascii');
    await expectHttpError(
      storeUpload({ filename: 'a.wav', data_base64: headerOnly.toString('base64') }, deps),
      400,
      /empty or corrupted/,
    );
  });

  test('caps the number of uploaded recordings', async () => {
    const { deps } = setup(copyConverter, 1);
    await storeUpload({ filename: 'one.wav', data_base64: wavBase64() }, deps);
    await expectHttpError(
      storeUpload({ filename: 'two.wav', data_base64: wavBase64() }, deps),
      409,
      /Upload limit reached/,
    );
    await storeUpload({ filename: 'one.wav', data_base64: wavBase64() }, deps);
  });

  test('keeps 16-bit PCM as-is when ffmpeg is unavailable', async () => {
    const { project, deps } = setup(failingConverter);
    const entry = await storeUpload({ filename: 'pcm.wav', data_base64: wavBase64() }, deps);
    assert.ok(existsSync(path.join(project.config.paths.calls, entry.file)));
  });

  test('refuses audio it can neither convert nor chunk', async () => {
    const { project, deps } = setup(failingConverter);
    const eightBit = makeWav([{ seconds: 1, amplitude: 2000 }], { bitsPerSample: 8 });
    await expectHttpError(
      storeUpload({ filename: 'old.wav', data_base64: eightBit.toString('base64') }, deps),
      422,
      /Could not convert/,
    );
    assert.equal(existsSync(path.join(project.config.paths.calls, 'upload_old.wav')), false);
  });
});

const hasFfmpeg = (() => {
  try {
    execFileSync('ffmpeg', ['-version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

describe('createFfmpegConverter', { skip: !hasFfmpeg && 'ffmpeg is not installed' }, () => {
  test('converts 8 kHz stereo to 16 kHz mono 16-bit PCM', async () => {
    const { project, deps } = setup(createFfmpegConverter(30_000));
    const stereo = makeWav([{ seconds: 1, amplitude: 3000 }], { sampleRate: 8_000, channels: 2 });
    const entry = await storeUpload(
      { filename: 'stereo.wav', data_base64: stereo.toString('base64') },
      deps,
    );
    const info = readWavInfo(readFileSync(path.join(project.config.paths.calls, entry.file)));
    assert.deepEqual([info.sampleRate, info.numChannels, info.bitsPerSample], [16_000, 1, 16]);
  });
});
