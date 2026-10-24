import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import {
  applySessionRules,
  buildContextBlock,
  createEmptySession,
  SessionState,
  validateWavUpload,
} from './src/utils/rules';

dotenv.config();

const ROOT_DIR = process.cwd();
const CALLS_DIR = path.join(ROOT_DIR, 'calls');
const CACHE_DIR = path.join(ROOT_DIR, 'cache');
const STATIC_DIR = path.join(ROOT_DIR, 'static');
const MANIFEST_PATH = path.join(CALLS_DIR, 'manifest.json');
const PROMPT_PATH = path.join(ROOT_DIR, 'prompts', 'detector_system.md');

const DETECTOR_PROMPT = fs.existsSync(PROMPT_PATH)
  ? fs.readFileSync(PROMPT_PATH, 'utf-8')
  : 'You are Saavdhan, a phone scam detector.';

const CHUNK_SCHEMA = {
  type: 'object',
  properties: {
    transcript: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          speaker: { type: 'string', enum: ['CALLER', 'RECEIVER', 'UNKNOWN'] },
          text: { type: 'string' },
        },
        required: ['speaker', 'text'],
      },
    },
    new_red_flags: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          type: {
            type: 'string',
            enum: [
              'AUTHORITY_CLAIM',
              'URGENCY',
              'THREAT',
              'OTP_OR_CREDENTIALS',
              'MONEY_REQUEST',
              'REMOTE_ACCESS_OR_LINK',
              'SECRECY',
              'HANDOFF_TO_OFFICIAL',
            ],
          },
          quote: { type: 'string' },
          why: { type: 'string' },
        },
        required: ['type', 'quote', 'why'],
      },
    },
    new_genuine_signals: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          quote: { type: 'string' },
          why: { type: 'string' },
        },
        required: ['quote', 'why'],
      },
    },
    scam_type: {
      type: 'string',
      enum: ['DIGITAL_ARREST', 'FAKE_KYC', 'FAKE_COURIER', 'OTHER_FRAUD', 'NONE'],
    },
    risk_score: {
      type: 'integer',
      minimum: 0,
      maximum: 100,
    },
    verdict: {
      type: 'string',
      enum: ['SAFE', 'SUSPICIOUS', 'SCAM'],
    },
    warning_gu: { type: 'string' },
    warning_hi: { type: 'string' },
    warning_en: { type: 'string' },
  },
  required: [
    'transcript',
    'new_red_flags',
    'new_genuine_signals',
    'scam_type',
    'risk_score',
    'verdict',
    'warning_gu',
    'warning_hi',
    'warning_en',
  ],
};

// Silence-aware WAV chunker matching app/chunker.py
function parseWavHeader(buf: Buffer) {
  let offset = 12;
  let sampleRate = 16000;
  let numChannels = 1;
  let bitsPerSample = 16;
  let dataOffset = 44;
  let dataSize = Math.max(0, buf.length - 44);

  while (offset + 8 <= buf.length) {
    const chunkId = buf.toString('ascii', offset, offset + 4);
    const chunkSize = buf.readUInt32LE(offset + 4);
    if (chunkId === 'fmt ') {
      numChannels = buf.readUInt16LE(offset + 10);
      sampleRate = buf.readUInt32LE(offset + 12);
      bitsPerSample = buf.readUInt16LE(offset + 22);
    } else if (chunkId === 'data') {
      dataOffset = offset + 8;
      dataSize = Math.min(chunkSize, buf.length - dataOffset);
      break;
    }
    offset += 8 + chunkSize + (chunkSize % 2);
  }
  return { sampleRate, numChannels, bitsPerSample, dataOffset, dataSize };
}

function computeChunksFromWav(wavPath: string, targetSec?: number): {
  boundaries: [number, number][];
  duration: number;
} {
  const chunkSec = Math.max(3.0, targetSec || Number(process.env.CHUNK_SEC || 6.0));
  const minChunkSec = 3.0;
  const searchWindowSec = 1.0;
  const frameMs = 20;

  if (!fs.existsSync(wavPath)) {
    return { boundaries: [], duration: 0 };
  }

  const buf = fs.readFileSync(wavPath);
  const { sampleRate, numChannels, bitsPerSample, dataOffset, dataSize } = parseWavHeader(buf);
  const bytesPerSample = Math.max(1, bitsPerSample / 8);
  const bytesPerFrameSample = bytesPerSample * numChannels;
  const totalSamples = Math.floor(dataSize / bytesPerFrameSample);
  const duration = sampleRate > 0 ? Number((totalSamples / sampleRate).toFixed(3)) : 0;

  if (duration <= chunkSec) {
    return { boundaries: duration > 0 ? [[0, duration]] : [], duration };
  }

  const samplesPer20ms = Math.max(1, Math.floor((sampleRate * frameMs) / 1000));
  const nRmsFrames = Math.floor(totalSamples / samplesPer20ms);
  const frameRms: number[] = [];

  for (let i = 0; i < nRmsFrames; i++) {
    let sumSq = 0;
    const baseSample = i * samplesPer20ms;
    for (let j = 0; j < samplesPer20ms; j++) {
      const bytePos = dataOffset + (baseSample + j) * bytesPerFrameSample;
      if (bytePos + 2 <= buf.length) {
        const val = buf.readInt16LE(bytePos);
        sumSq += val * val;
      }
    }
    frameRms.push(Math.sqrt(sumSq / samplesPer20ms));
  }

  const frameSec = frameMs / 1000.0;
  const boundaries: [number, number][] = [];
  let cursorS = 0.0;

  while (cursorS < duration) {
    const remaining = duration - cursorS;
    if (remaining <= chunkSec) {
      boundaries.push([Number(cursorS.toFixed(3)), Number(duration.toFixed(3))]);
      break;
    }

    const idealCutS = cursorS + chunkSec;
    const winStartS = Math.max(cursorS + minChunkSec, idealCutS - searchWindowSec);
    const winEndS = Math.min(duration, idealCutS + searchWindowSec);

    const startIdx = Math.max(0, Math.round(winStartS / frameSec));
    const endIdx = Math.min(frameRms.length - 1, Math.round(winEndS / frameSec));

    let cutS = Number(idealCutS.toFixed(3));
    if (startIdx <= endIdx && frameRms.length > 0) {
      let bestIdx = startIdx;
      for (let idx = startIdx + 1; idx <= endIdx; idx++) {
        if (frameRms[idx] < frameRms[bestIdx]) {
          bestIdx = idx;
        }
      }
      cutS = Number((bestIdx * frameSec).toFixed(3));
    }

    if (cutS - cursorS < minChunkSec) {
      cutS = Number(Math.min(duration, cursorS + chunkSec).toFixed(3));
    }

    boundaries.push([Number(cursorS.toFixed(3)), cutS]);
    cursorS = cutS;
  }

  if (boundaries.length >= 2) {
    const [lastStart, lastEnd] = boundaries[boundaries.length - 1];
    if (lastEnd - lastStart < minChunkSec) {
      const [prevStart] = boundaries[boundaries.length - 2];
      boundaries[boundaries.length - 2] = [prevStart, lastEnd];
      boundaries.pop();
    }
  }

  return { boundaries, duration };
}

function sliceWavBytes(wavPath: string, startS: number, endS: number): Buffer {
  const buf = fs.readFileSync(wavPath);
  const { sampleRate, numChannels, bitsPerSample, dataOffset, dataSize } = parseWavHeader(buf);
  const bytesPerSample = Math.max(1, bitsPerSample / 8);
  const blockAlign = numChannels * bytesPerSample;
  const totalSamples = Math.floor(dataSize / blockAlign);

  const startSample = Math.max(0, Math.min(totalSamples, Math.round(startS * sampleRate)));
  const endSample = Math.max(startSample, Math.min(totalSamples, Math.round(endS * sampleRate)));

  const sliceByteOffset = dataOffset + startSample * blockAlign;
  const sliceByteLen = (endSample - startSample) * blockAlign;
  const pcmSlice = buf.subarray(sliceByteOffset, sliceByteOffset + sliceByteLen);

  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + pcmSlice.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(numChannels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * blockAlign, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write('data', 36);
  header.writeUInt32LE(pcmSlice.length, 40);

  return Buffer.concat([header, pcmSlice]);
}

async function analyzeChunkWithGemini(wavBytes: Buffer, contextBlock: string) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return {
      status: 'unavailable',
      error: 'GEMINI_API_KEY is not configured',
      latency_ms: 0,
    };
  }

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: { 'User-Agent': 'aistudio-build' },
    },
  });

  const preferredModel = process.env.MODEL || 'gemini-3.5-flash-lite';
  const preferredThinking = process.env.THINKING_LEVEL || (preferredModel.includes('3.8-flash') ? 'low' : 'minimal');
  const wavB64 = wavBytes.toString('base64');
  const t0 = Date.now();
  let lastError = '';

  const modelsToTry =
    preferredModel === 'gemini-3.8-flash'
      ? [
          { model: 'gemini-3.8-flash', thinking: 'low' },
          { model: 'gemini-3.5-flash-lite', thinking: 'minimal' },
        ]
      : [
          { model: preferredModel, thinking: preferredThinking },
          { model: 'gemini-3.5-flash-lite', thinking: 'minimal' },
        ];

  for (let attempt = 0; attempt < 2; attempt++) {
    const target = modelsToTry[Math.min(attempt, modelsToTry.length - 1)];
    try {
      const interaction = await ai.interactions.create(
        {
          model: target.model,
          system_instruction: DETECTOR_PROMPT,
          input: [
            { type: 'audio', data: wavB64, mime_type: 'audio/wav' },
            { type: 'text', text: contextBlock },
          ],
          response_format: CHUNK_SCHEMA as any,
          generation_config: { thinking_level: target.thinking as any },
          store: false,
        },
        { timeout: 12000 }
      );

      let textOut = interaction.output_text || '';
      if (!textOut && interaction.steps) {
        for (const step of interaction.steps) {
          if (step.type === 'model_output') {
            const tc = step.content?.find((c: any) => c.type === 'text');
            if (tc && (tc as any).text) textOut += (tc as any).text;
          }
        }
      }
      let cleaned = textOut.trim();
      if (cleaned.startsWith('```')) {
        const lines = cleaned.split('\n');
        cleaned = lines
          .slice(1, lines[lines.length - 1].startsWith('```') ? -1 : undefined)
          .join('\n')
          .trim();
      }
      const parsed = JSON.parse(cleaned);
      const latencyMs = Date.now() - t0;
      return {
        status: 'ok',
        latency_ms: latencyMs,
        model: target.model,
        ...parsed,
      };
    } catch (err: any) {
      lastError = err?.message || String(err);
      if (attempt === 0) {
        const delayMs = lastError.includes('429') ? 1500 : 400;
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  }

  return {
    status: 'unavailable',
    error: lastError,
    latency_ms: Date.now() - t0,
  };
}

const app = express();
// Allow up to 16MB JSON body so a 10MB binary WAV encoded as base64 (~13.4MB) is accepted and validated
app.use(express.json({ limit: '16mb' }));

const SESSIONS = new Map<string, SessionState & { call_meta: any }>();
const CALL_META_CACHE = new Map<string, { mtime: number; data: any }>();

function loadManifest(): any[] {
  if (!fs.existsSync(MANIFEST_PATH)) return [];
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
}

function getCallMetadata(entry: any) {
  const fileName = entry.file;
  const callId = path.parse(fileName).name;
  const wavPath = path.join(CALLS_DIR, fileName);
  const mtime = fs.existsSync(wavPath) ? fs.statSync(wavPath).mtimeMs : 0;

  const cached = CALL_META_CACHE.get(callId);
  if (cached && cached.mtime === mtime) {
    return cached.data;
  }

  const { boundaries, duration } = computeChunksFromWav(wavPath);
  const cacheFile = path.join(CACHE_DIR, `${callId}.json`);
  const data = {
    id: callId,
    file: fileName,
    title: entry.title,
    expected: entry.expected,
    first_demand_at: entry.first_demand_at ?? null,
    duration,
    chunks: boundaries.map((b, idx) => ({
      index: idx,
      start_s: b[0],
      end_s: b[1],
    })),
    has_cache: fs.existsSync(cacheFile),
  };
  CALL_META_CACHE.set(callId, { mtime, data });
  return data;
}

app.get('/api/calls', (_req, res) => {
  const manifest = loadManifest();
  const calls = manifest.map(getCallMetadata);
  const demoReplay = process.env.DEMO_REPLAY === '1';
  res.json({
    calls,
    demo_replay: demoReplay,
    model: process.env.MODEL || 'gemini-3.8-flash',
  });
});

app.post('/api/upload', (req, res) => {
  const { filename, data_base64, title, expected } = req.body || {};
  if (!filename || typeof filename !== 'string' || !data_base64 || typeof data_base64 !== 'string') {
    res.status(400).json({ detail: 'Missing filename or base64 audio payload.' });
    return;
  }

  let rawBuf: Buffer;
  try {
    rawBuf = Buffer.from(data_base64, 'base64');
  } catch {
    res.status(400).json({ detail: 'Invalid base64 audio payload.' });
    return;
  }

  const check = validateWavUpload(filename, rawBuf.length, rawBuf.subarray(0, 12));
  if (!check.valid || !check.sanitizedStem) {
    res.status(400).json({ detail: check.error || 'Invalid .wav file.' });
    return;
  }

  const stem = check.sanitizedStem;
  const outFileName = `${stem}.wav`;
  const rawCallsDir = path.join(CALLS_DIR, 'raw');
  fs.mkdirSync(rawCallsDir, { recursive: true });
  fs.mkdirSync(CALLS_DIR, { recursive: true });

  const rawPath = path.join(rawCallsDir, outFileName);
  const destPath = path.join(CALLS_DIR, outFileName);
  fs.writeFileSync(rawPath, rawBuf);

  try {
    execFileSync('ffmpeg', [
      '-y',
      '-hide_banner',
      '-loglevel',
      'error',
      '-i',
      rawPath,
      '-ar',
      '16000',
      '-ac',
      '1',
      '-c:a',
      'pcm_s16le',
      destPath,
    ]);
  } catch {
    fs.writeFileSync(destPath, rawBuf);
  }

  CALL_META_CACHE.delete(stem);
  const manifest = loadManifest();
  const resolvedExpected = expected === 'SAFE' ? 'SAFE' : 'SCAM';
  const resolvedTitle =
    (typeof title === 'string' && title.trim()) ||
    `Uploaded — ${path.parse(filename).name}`;

  let entry = manifest.find((m) => m.file === outFileName);
  if (entry) {
    entry.title = resolvedTitle;
    entry.expected = resolvedExpected;
  } else {
    entry = { file: outFileName, title: resolvedTitle, expected: resolvedExpected };
    manifest.push(entry);
  }

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2), 'utf-8');
  const callMeta = getCallMetadata(entry);
  const calls = manifest.map(getCallMetadata);
  res.json({ call: callMeta, calls });
});

app.post('/api/session', (req, res) => {
  const { call_id } = req.body || {};
  const manifest = loadManifest();
  const matched = manifest.find(
    (m) => path.parse(m.file).name === call_id || m.file === call_id
  );
  if (!matched) {
    res.status(404).json({ detail: `Unknown call_id: ${call_id}` });
    return;
  }
  const callMeta = getCallMetadata(matched);
  const sessionId = crypto.randomUUID();
  const session = {
    ...createEmptySession(callMeta.id, sessionId),
    call_meta: callMeta,
  };
  SESSIONS.set(sessionId, session);
  res.json({ session_id: sessionId, call: callMeta });
});

app.post('/api/analyze', async (req, res) => {
  const { session_id, chunk_index, replay } = req.body || {};
  const session = SESSIONS.get(session_id);
  if (!session) {
    res.status(404).json({ detail: 'Session not found' });
    return;
  }

  const callMeta = session.call_meta;
  const chunks = callMeta.chunks || [];
  if (typeof chunk_index !== 'number' || chunk_index < 0 || chunk_index >= chunks.length) {
    res.status(400).json({ detail: `Invalid chunk_index ${chunk_index}` });
    return;
  }

  const existing = session.chunks.find((c: any) => c.chunk_index === chunk_index);
  if (existing) {
    const { call_meta, ...pub } = session;
    res.json({ chunk: existing, session: pub });
    return;
  }

  const chunkInfo = chunks[chunk_index];
  const startS = chunkInfo.start_s;
  const endS = chunkInfo.end_s;
  const callId = callMeta.id;
  const useReplay = typeof replay === 'boolean' ? replay : process.env.DEMO_REPLAY === '1';

  let chunkResult: any;
  if (useReplay) {
    const cachePath = path.join(CACHE_DIR, `${callId}.json`);
    if (!fs.existsSync(cachePath)) {
      res.status(404).json({ detail: `Replay cache cache/${callId}.json not found.` });
      return;
    }
    const cacheData = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
    const cachedChunks = cacheData.chunks || [];
    const rawCached = cachedChunks[chunk_index];
    if (!rawCached) {
      res.status(404).json({ detail: 'Chunk missing from replay cache' });
      return;
    }
    // Serve cache/ results at their recorded latency (capped at 1.2s for responsive playback)
    const simDelayMs = Math.min(1200, Math.max(80, Number(rawCached.latency_ms || 350)));
    await new Promise((r) => setTimeout(r, simDelayMs));
    chunkResult = {
      status: rawCached.status || 'ok',
      latency_ms: rawCached.latency_ms || simDelayMs,
      model: rawCached.model || cacheData.model || 'replay',
      transcript: rawCached.raw_transcript || rawCached.transcript || [],
      new_red_flags: rawCached.raw_new_red_flags || rawCached.new_red_flags || [],
      new_genuine_signals: rawCached.raw_new_genuine_signals || rawCached.new_genuine_signals || [],
      scam_type: rawCached.scam_type || 'NONE',
      risk_score: rawCached.model_risk_score ?? rawCached.risk_score ?? 0,
      verdict: rawCached.verdict || 'SAFE',
      warning_gu: rawCached.warning_gu || '',
      warning_hi: rawCached.warning_hi || '',
      warning_en: rawCached.warning_en || '',
    };
  } else {
    const wavPath = path.join(CALLS_DIR, callMeta.file);
    if (!fs.existsSync(wavPath)) {
      res.status(404).json({ detail: `Audio file missing: ${callMeta.file}` });
      return;
    }
    const wavBytes = sliceWavBytes(wavPath, startS, endS);
    const contextBlock = buildContextBlock(chunk_index + 1, chunks.length, startS, endS, session);
    chunkResult = await analyzeChunkWithGemini(wavBytes, contextBlock);
  }

  const processed = applySessionRules(session, chunk_index, startS, endS, chunkResult);
  processed.mode = useReplay ? 'REPLAY' : 'LIVE';
  const { call_meta, ...pub } = session;
  res.json({ chunk: processed, session: pub });
});

app.use('/calls', express.static(CALLS_DIR));
app.use('/static', express.static(STATIC_DIR));

app.get('/', (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Saavdhan server listening on http://0.0.0.0:${PORT}`);
});
