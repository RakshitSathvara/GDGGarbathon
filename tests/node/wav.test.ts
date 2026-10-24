import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import {
  computeChunkBoundaries,
  computeChunks,
  computeFrameRms,
  InvalidWavError,
  isPcm16,
  readWavInfo,
  sliceWav,
} from '../../server/wav.ts';
import { makeWav, REPO_ROOT, readFixture } from './support.ts';

interface BoundaryFixture {
  demo_calls: { file: string; target_sec: number; duration: number; boundaries: number[][] }[];
  rms_cases: {
    name: string;
    duration: number;
    target_sec: number;
    frames: number;
    fill: number;
    dips: Record<string, number>;
    expected: number[][];
  }[];
}

const fixture = readFixture<BoundaryFixture>('chunk_boundaries.json');

describe('readWavInfo', () => {
  test('parses format and data location of a canonical WAV', () => {
    const info = readWavInfo(makeWav([{ seconds: 1, amplitude: 1000 }]));
    assert.equal(info.sampleRate, 16_000);
    assert.equal(info.numChannels, 1);
    assert.equal(info.bitsPerSample, 16);
    assert.equal(info.dataOffset, 44);
    assert.equal(info.totalFrames, 16_000);
    assert.equal(info.durationSec, 1);
    assert.ok(isPcm16(info));
  });

  test('skips unknown chunks, including odd-sized ones with padding', () => {
    const wav = makeWav([{ seconds: 0.5, amplitude: 1000 }], {
      extraChunk: { id: 'LIST', body: Buffer.from('odd') },
    });
    const info = readWavInfo(wav);
    assert.equal(info.dataOffset, 44 + 8 + 4);
    assert.equal(info.durationSec, 0.5);
  });

  test('rejects data that is not RIFF/WAVE', () => {
    assert.throws(() => readWavInfo(Buffer.from('ID3\u0003 not a wav at all')), InvalidWavError);
  });

  test('rejects a WAV without a data chunk', () => {
    const headerOnly = makeWav([{ seconds: 0.1, amplitude: 0 }]).subarray(0, 36);
    assert.throws(() => readWavInfo(headerOnly), /empty or corrupted/);
  });

  test('reports non-PCM16 formats', () => {
    assert.equal(
      isPcm16(readWavInfo(makeWav([{ seconds: 0.1, amplitude: 0 }], { bitsPerSample: 8 }))),
      false,
    );
    assert.equal(
      isPcm16(readWavInfo(makeWav([{ seconds: 0.1, amplitude: 0 }], { audioFormat: 3 }))),
      false,
    );
  });
});

describe('computeFrameRms', () => {
  test('measures loud and silent 20 ms frames', () => {
    const wav = makeWav([
      { seconds: 0.1, amplitude: 8000 },
      { seconds: 0.1, amplitude: 0 },
    ]);
    const rms = computeFrameRms(wav, readWavInfo(wav));
    assert.equal(rms.length, 10);
    assert.ok((rms[0] ?? 0) > 5000);
    assert.equal(rms[9], 0);
  });

  test('averages channels of stereo audio', () => {
    const mono = makeWav([{ seconds: 0.2, amplitude: 4000 }]);
    const stereo = makeWav([{ seconds: 0.2, amplitude: 4000 }], { channels: 2 });
    assert.deepEqual(
      computeFrameRms(stereo, readWavInfo(stereo)),
      computeFrameRms(mono, readWavInfo(mono)),
    );
  });

  test('returns a single silent frame for audio shorter than one frame', () => {
    const wav = makeWav([{ seconds: 0.005, amplitude: 4000 }]);
    assert.deepEqual(computeFrameRms(wav, readWavInfo(wav)), [0]);
  });

  test('refuses audio that is not 16-bit PCM', () => {
    const wav = makeWav([{ seconds: 0.1, amplitude: 4000 }], { bitsPerSample: 8 });
    assert.throws(() => computeFrameRms(wav, readWavInfo(wav)), InvalidWavError);
  });
});

describe('computeChunkBoundaries', () => {
  for (const rmsCase of fixture.rms_cases) {
    test(`shared fixture: ${rmsCase.name}`, () => {
      const rms = new Array<number>(rmsCase.frames).fill(rmsCase.fill);
      for (const [index, value] of Object.entries(rmsCase.dips)) rms[Number(index)] = value;
      assert.deepEqual(
        computeChunkBoundaries(rms, rmsCase.duration, rmsCase.target_sec),
        rmsCase.expected,
      );
    });
  }

  test('returns no chunks for empty audio', () => {
    assert.deepEqual(computeChunkBoundaries([], 0, 6), []);
  });

  test('enforces the 3 s minimum target', () => {
    const rms = new Array<number>(500).fill(10);
    for (const [start, end] of computeChunkBoundaries(rms, 10, 1)) {
      assert.ok(end - start >= 3 - 1e-9);
    }
  });
});

describe('computeChunks', () => {
  for (const call of fixture.demo_calls) {
    test(`matches the golden boundaries for ${call.file}`, () => {
      const wav = readFileSync(path.join(REPO_ROOT, 'calls', call.file));
      const { boundaries, duration } = computeChunks(wav, call.target_sec);
      assert.equal(duration, call.duration);
      assert.deepEqual(boundaries, call.boundaries);
    });
  }

  test('cuts in the pause between two phrases', () => {
    const wav = makeWav([
      { seconds: 5.5, amplitude: 6000 },
      { seconds: 0.4, amplitude: 0 },
      { seconds: 5.5, amplitude: 6000 },
    ]);
    const { boundaries } = computeChunks(wav, 6);
    const firstCut = boundaries[0]?.[1] ?? 0;
    assert.ok(firstCut >= 5.5 && firstCut <= 5.9, `cut at ${firstCut}`);
  });
});

describe('sliceWav', () => {
  const wav = makeWav([{ seconds: 2, amplitude: 3000 }]);
  const info = readWavInfo(wav);

  test('produces a standalone WAV with the requested span', () => {
    const slice = sliceWav(wav, info, 0.5, 1.5);
    const sliceInfo = readWavInfo(slice);
    assert.equal(sliceInfo.totalFrames, 16_000);
    assert.equal(slice.readUInt32LE(4), slice.length - 8);
    assert.deepEqual(slice.subarray(44), wav.subarray(44 + 8_000 * 2, 44 + 24_000 * 2));
  });

  test('clamps out-of-range and inverted spans', () => {
    assert.equal(readWavInfo(sliceWav(wav, info, 1.5, 99)).totalFrames, 8_000);
    assert.equal(readWavInfo(sliceWav(wav, info, -1, 0.25)).totalFrames, 4_000);
    assert.equal(sliceWav(wav, info, 1.5, 1).length, 44);
  });
});
