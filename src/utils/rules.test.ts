import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applySessionRules,
  buildContextBlock,
  createEmptySession,
  MAX_WAV_UPLOAD_BYTES,
  SCAM_FALLBACK_GU,
  SCAM_FALLBACK_HI,
  validateWavUpload,
  verdictFromRisk,
} from './rules';

test('validateWavUpload accepts valid .wav up to 10 MB and rejects non-.wav or >10 MB files', () => {
  const validHeader = new Uint8Array([
    0x52, 0x49, 0x46, 0x46, // RIFF
    0x24, 0x08, 0x00, 0x00,
    0x57, 0x41, 0x56, 0x45, // WAVE
  ]);

  const ok = validateWavUpload('My Call Recording.wav', 512 * 1024, validHeader);
  assert.equal(ok.valid, true);
  assert.equal(ok.sanitizedStem, 'my_call_recording');

  const exact10Mb = validateWavUpload('max.WAV', MAX_WAV_UPLOAD_BYTES, validHeader);
  assert.equal(exact10Mb.valid, true);

  const tooLarge = validateWavUpload('huge.wav', MAX_WAV_UPLOAD_BYTES + 1, validHeader);
  assert.equal(tooLarge.valid, false);
  assert.ok(tooLarge.error?.includes('10 MB'));

  const wrongExt = validateWavUpload('audio.mp3', 10240, validHeader);
  assert.equal(wrongExt.valid, false);
  assert.ok(wrongExt.error?.includes('Only .wav files'));

  const badHeader = new Uint8Array([0x49, 0x44, 0x33, 0x03, 0, 0, 0, 0, 0, 0, 0, 0]);
  const invalidMime = validateWavUpload('fake.wav', 10240, badHeader);
  assert.equal(invalidMime.valid, false);
  assert.ok(invalidMime.error?.includes('Invalid WAV'));
});

test('verdictFromRisk maps thresholds <30 SAFE, 30-69 SUSPICIOUS, >=70 SCAM', () => {
  assert.equal(verdictFromRisk(0), 'SAFE');
  assert.equal(verdictFromRisk(29), 'SAFE');
  assert.equal(verdictFromRisk(30), 'SUSPICIOUS');
  assert.equal(verdictFromRisk(69), 'SUSPICIOUS');
  assert.equal(verdictFromRisk(70), 'SCAM');
  assert.equal(verdictFromRisk(95), 'SCAM');
});

test('hard red flag raises risk to >=75 and populates fallback warnings when model warnings are empty', () => {
  const session = createEmptySession('fake_kyc', 's1');
  const res = applySessionRules(session, 0, 0, 6.0, {
    status: 'ok',
    latency_ms: 420,
    transcript: [{ speaker: 'CALLER', text: 'તમારો OTP આપો' }],
    new_red_flags: [{ type: 'OTP_OR_CREDENTIALS', quote: 'તમારો OTP આપો', why: 'Asking for OTP' }],
    new_genuine_signals: [],
    scam_type: 'FAKE_KYC',
    risk_score: 40,
    verdict: 'SUSPICIOUS',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  });

  assert.equal(res.risk_score, 75);
  assert.equal(res.verdict, 'SCAM');
  assert.equal(session.first_scam_at, 6.0);
  assert.ok(session.warning_gu.includes(SCAM_FALLBACK_GU));
  assert.ok(session.warning_hi.includes(SCAM_FALLBACK_HI));
  assert.ok(session.warning_gu.includes('તમારો OTP આપો'));
});

test('accumulated AUTHORITY_CLAIM + THREAT + URGENCY raises risk to >=70 and SCAM is sticky', () => {
  const session = createEmptySession('digital_arrest', 's2');
  applySessionRules(session, 0, 0, 5.8, {
    status: 'ok',
    latency_ms: 350,
    transcript: [{ speaker: 'CALLER', text: 'मैं सीबीआई से बोल रहा हूँ, वारंट है' }],
    new_red_flags: [
      { type: 'AUTHORITY_CLAIM', quote: 'मैं सीबीआई से बोल रहा हूँ', why: 'CBI claim' },
      { type: 'THREAT', quote: 'वारंट है', why: 'Warrant threat' },
    ],
    new_genuine_signals: [],
    scam_type: 'DIGITAL_ARREST',
    risk_score: 55,
    verdict: 'SUSPICIOUS',
    warning_gu: 'સાવચેત રહો',
    warning_hi: 'सतर्क रहें',
    warning_en: 'Be cautious',
  });
  assert.equal(session.verdict, 'SUSPICIOUS');

  // Adding URGENCY completes the trio -> risk >= 70 (SCAM)
  applySessionRules(session, 1, 5.8, 11.5, {
    status: 'ok',
    latency_ms: 360,
    transcript: [{ speaker: 'CALLER', text: 'अभी दस मिनट में अकाउंट फ्रीज होगा' }],
    new_red_flags: [{ type: 'URGENCY', quote: 'अभी दस मिनट में', why: '10 min urgency' }],
    new_genuine_signals: [],
    scam_type: 'DIGITAL_ARREST',
    risk_score: 60,
    verdict: 'SUSPICIOUS',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  });
  assert.equal(session.verdict, 'SCAM');
  assert.equal(session.risk, 70);

  // Subsequent calm chunk cannot drop SCAM below 70
  applySessionRules(session, 2, 11.5, 17.0, {
    status: 'ok',
    latency_ms: 310,
    transcript: [{ speaker: 'RECEIVER', text: 'ठीक है' }],
    new_red_flags: [],
    new_genuine_signals: [],
    scam_type: 'NONE',
    risk_score: 10,
    verdict: 'SAFE',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  });
  assert.equal(session.risk, 70);
  assert.equal(session.verdict, 'SCAM');
});

test('SUSPICIOUS may fall back to SAFE if SCAM was never reached', () => {
  const session = createEmptySession('genuine_bank', 's3');
  applySessionRules(session, 0, 0, 6.0, {
    status: 'ok',
    latency_ms: 300,
    transcript: [{ speaker: 'CALLER', text: 'હું બેંકમાંથી બોલું છું' }],
    new_red_flags: [{ type: 'AUTHORITY_CLAIM', quote: 'હું બેંકમાંથી બોલું છું', why: 'Bank claim' }],
    new_genuine_signals: [],
    scam_type: 'NONE',
    risk_score: 35,
    verdict: 'SUSPICIOUS',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  });
  assert.equal(session.verdict, 'SUSPICIOUS');

  applySessionRules(session, 1, 6.0, 12.0, {
    status: 'ok',
    latency_ms: 300,
    transcript: [{ speaker: 'CALLER', text: 'ફોન પર કોઈ OTP આપવાનો નથી' }],
    new_red_flags: [],
    new_genuine_signals: [{ quote: 'ફોન પર કોઈ OTP આપવાનો નથી', why: 'Never asks OTP' }],
    scam_type: 'NONE',
    risk_score: 5,
    verdict: 'SAFE',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  });
  assert.equal(session.verdict, 'SAFE');
  assert.equal(session.risk, 5);
});

test('buildContextBlock formats header, transcript, flags, and current risk', () => {
  const session = createEmptySession('digital_arrest', 's4');
  session.risk = 55;
  session.verdict = 'SUSPICIOUS';
  session.transcript.push({ speaker: 'CALLER', text: 'Arrest warrant issued' });
  session.red_flags.push({ type: 'THREAT', quote: 'Arrest warrant issued', why: 'Threat' });

  const block = buildContextBlock(4, 14, 18.2, 24.6, session);
  assert.ok(block.includes('CHUNK 4/14 | 00:18.2–00:24.6'));
  assert.ok(block.includes('RED FLAGS SO FAR: THREAT "Arrest warrant issued"'));
  assert.ok(block.includes('CURRENT: risk 55, SUSPICIOUS'));
});
