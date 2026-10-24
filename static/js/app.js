/**
 * Saavdhan UI controller: plays a recorded call and sends each silence-aligned chunk for analysis
 * only after the playhead has passed it, one request at a time, in order.
 */
import { api } from './api.js';
import { playScamBeep, stopSpeaking } from './feedback.js';
import {
  arrayBufferToBase64,
  chunksReadyToSend,
  formatPaddedClock,
  hasWavHeader,
  validateWavFile,
} from './helpers.js';
import { createView, queryDom } from './view.js';

function emptySession() {
  return {
    transcript: [],
    red_flags: [],
    genuine_signals: [],
    scam_type: 'NONE',
    risk: 0,
    verdict: 'SAFE',
    first_scam_at: null,
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
  };
}

/** Per-call fields reset whenever a call is (re)selected. */
function freshCallState(call) {
  return {
    activeCall: call,
    sessionId: null,
    inFlight: false,
    /** @type {number[]} chunk indexes awaiting analysis; the head is in flight */
    queue: [],
    sent: new Set(),
    results: new Map(),
    session: emptySession(),
    lastChunkUnavailable: false,
    beeped: false,
  };
}

const dom = queryDom();
const state = {
  calls: [],
  selectToken: 0,
  lang: 'gu',
  replayMode: false,
  speakWarning: false,
  ...freshCallState(null),
};
const view = createView(dom, { onSelectCall: (callId) => void selectCall(callId) });
const render = () => view.render(state);

async function selectCall(callId) {
  const token = ++state.selectToken;
  dom.audio.pause();
  stopSpeaking();
  view.hideError();

  const call = state.calls.find((item) => item.id === callId) ?? state.calls[0];
  if (!call) return;
  Object.assign(state, freshCallState(call));
  dom.audio.src = `/calls/${encodeURIComponent(call.file)}`;
  dom.callTimer.textContent = '00:00';
  dom.callerStatus.textContent = 'Ready to Play Call';
  render();

  try {
    const data = await api.createSession(call.id);
    if (token !== state.selectToken) return;
    state.sessionId = data.session_id;
    state.activeCall = data.call ?? call;
  } catch (error) {
    if (token === state.selectToken) view.showError(`Could not start a session: ${error.message}`);
  }
  render();
}

function applyChunkResult(chunkIndex, data) {
  state.results.set(chunkIndex, data.chunk);
  state.session = data.session;
  state.lastChunkUnavailable = data.chunk.status === 'unavailable';
  if (state.lastChunkUnavailable) {
    const reason = data.chunk.error || 'unavailable';
    view.showError(`Chunk #${chunkIndex + 1} analysis failed (${reason}).`, {
      offerReplay: !state.replayMode,
    });
  } else if (data.session.verdict === 'SCAM' && !state.beeped) {
    state.beeped = true;
    playScamBeep();
  }
}

function recordFailedChunk(chunkIndex, error) {
  const chunk = state.activeCall?.chunks[chunkIndex];
  state.results.set(chunkIndex, {
    chunk_index: chunkIndex,
    start_s: chunk?.start_s ?? 0,
    end_s: chunk?.end_s ?? 0,
    status: 'unavailable',
    verdict: 'unavailable',
    risk_score: state.session.risk || 0,
    latency_ms: 0,
  });
  state.lastChunkUnavailable = true;
  view.showError(`Analysis error: ${error.message}`, { offerReplay: !state.replayMode });
}

async function processQueue() {
  if (state.inFlight || state.queue.length === 0 || !state.sessionId) return;
  const sessionId = state.sessionId;
  const chunkIndex = state.queue[0];
  state.inFlight = true;
  render();
  try {
    const data = await api.analyzeChunk(sessionId, chunkIndex, state.replayMode);
    if (state.sessionId === sessionId) applyChunkResult(chunkIndex, data);
  } catch (error) {
    if (state.sessionId === sessionId) recordFailedChunk(chunkIndex, error);
  } finally {
    if (state.sessionId === sessionId) {
      state.queue.shift();
      state.inFlight = false;
      render();
      void processQueue();
    }
  }
}

function enqueueReadyChunks(callEnded) {
  if (!state.activeCall || !state.sessionId) return;
  const chunks = state.activeCall.chunks;
  for (const index of chunksReadyToSend(chunks, dom.audio.currentTime, state.sent, callEnded)) {
    state.sent.add(index);
    state.queue.push(index);
  }
  render();
  void processQueue();
}

async function handleUpload(event) {
  event.preventDefault();
  const file = dom.fileInput.files?.[0];
  const problem = validateWavFile(file);
  if (problem || !file) {
    view.setUploadFeedback(problem ?? 'Please select a .wav file to upload.', 'error');
    dom.fileInput.focus();
    return;
  }

  dom.uploadSubmit.disabled = true;
  view.setUploadFeedback('Validating and converting .wav to 16 kHz mono PCM…', 'pending');
  try {
    const buffer = await file.arrayBuffer();
    if (!hasWavHeader(new Uint8Array(buffer, 0, Math.min(12, buffer.byteLength)))) {
      throw new Error('Invalid WAV file header (expected RIFF/WAVE).');
    }
    const data = await api.uploadWav({
      filename: file.name,
      title: dom.titleInput.value.trim() || undefined,
      expected: dom.expectedSelect.value,
      data_base64: arrayBufferToBase64(buffer),
    });
    state.calls = data.calls ?? state.calls;
    state.replayMode = false; // a fresh upload has no replay cache yet
    await selectCall(data.call.id);
    const summary = `${data.call.duration}s, ${data.call.chunks.length} chunks`;
    view.setUploadFeedback(`Uploaded "${data.call.title}" (${summary}). Ready to play!`, 'success');
    dom.uploadForm.reset();
  } catch (error) {
    view.setUploadFeedback(error.message || 'Upload failed.', 'error');
  } finally {
    dom.uploadSubmit.disabled = false;
  }
}

function startCall() {
  const call = state.activeCall;
  if (!call) return;
  const finished = dom.audio.ended || dom.audio.currentTime >= call.duration - 0.2;
  const ready = finished ? selectCall(call.id) : Promise.resolve();
  void ready.then(() =>
    dom.audio.play().catch((error) => view.showError(`Playback failed: ${error.message}`)),
  );
}

function bindEvents() {
  dom.audio.addEventListener('timeupdate', () => {
    dom.callTimer.textContent = formatPaddedClock(dom.audio.currentTime);
    enqueueReadyChunks(false);
  });
  dom.audio.addEventListener('play', () => {
    dom.callerStatus.textContent = 'Call in Progress · Saavdhan Active';
  });
  dom.audio.addEventListener('ended', () => {
    dom.callerStatus.textContent = 'Call Ended';
    enqueueReadyChunks(true);
  });

  dom.playButton.addEventListener('click', startCall);
  dom.stopButton.addEventListener('click', () => {
    dom.audio.pause();
    stopSpeaking();
    dom.callerStatus.textContent = 'Call Cut / Stopped';
  });

  for (const button of dom.langButtons) {
    button.addEventListener('click', () => {
      state.lang = button.dataset.lang === 'hi' ? 'hi' : 'gu';
      render();
    });
  }
  dom.ttsButton.addEventListener('click', () => {
    state.speakWarning = !state.speakWarning;
    if (!state.speakWarning) stopSpeaking();
    render();
  });
  dom.modeButton.addEventListener('click', () => {
    state.replayMode = !state.replayMode;
    render();
    if (state.activeCall) void selectCall(state.activeCall.id);
  });
  dom.offerReplayButton.addEventListener('click', () => {
    state.replayMode = true;
    render();
    if (!state.activeCall) return;
    void selectCall(state.activeCall.id).then(startCall);
  });
  dom.dismissErrorButton.addEventListener('click', view.hideError);

  dom.uploadToggle.addEventListener('click', () => {
    const opening = dom.uploadBar.hidden;
    dom.uploadBar.hidden = !opening;
    dom.uploadToggle.setAttribute('aria-expanded', String(opening));
    view.setUploadFeedback('');
    if (opening) dom.fileInput.focus();
  });
  dom.fileInput.addEventListener('change', () => {
    const file = dom.fileInput.files?.[0];
    if (!file) return view.setUploadFeedback('');
    const problem = validateWavFile(file);
    if (problem) return view.setUploadFeedback(problem, 'error');
    const size = `${(file.size / 1024).toFixed(1)} KB`;
    return view.setUploadFeedback(`Ready: ${file.name} (${size})`, 'success');
  });
  dom.uploadForm.addEventListener('submit', handleUpload);
}

async function init() {
  bindEvents();
  render();
  try {
    const data = await api.listCalls();
    state.calls = data.calls ?? [];
    state.replayMode = Boolean(data.demo_replay);
    render();
    if (state.calls.length > 0) await selectCall(state.calls[0].id);
  } catch (error) {
    view.showError(`Could not load the demo calls: ${error.message}`);
  }
}

void init();
