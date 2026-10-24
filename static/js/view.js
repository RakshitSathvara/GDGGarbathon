/**
 * Renders the elder's phone screen and the judge console from application state.
 * Each section re-renders only when its data signature changes, so 4 Hz `timeupdate` events stay
 * cheap and assistive technology is not flooded with repeated content.
 */
import { byId, createRenderCache, el } from './dom.js';
import { announce, speak } from './feedback.js';
import {
  analysisLag,
  describeChunkState,
  detectScriptLang,
  formatClock,
  formatPaddedClock,
  formatSpan,
  highlightSegments,
  warningLead,
} from './helpers.js';
import { ACTION_LABELS, CHIP_LABELS, flagsHeading, STATUS_TEXT, VERDICT_BADGES } from './i18n.js';

const DEFAULT_TITLE = 'Saavdhan — Mid-Call Scam Detector for Elders';
const SPEAKERS = new Set(['CALLER', 'RECEIVER', 'UNKNOWN']);
const EMPTY_TRANSCRIPT =
  'Press "Start Call" on the phone to play the recording. Each chunk is sent only after the playhead passes its boundary.';

export function queryDom() {
  return {
    audio: /** @type {HTMLAudioElement} */ (byId('callAudio')),
    callSelector: byId('callSelector'),
    langButtons: [byId('langGuBtn'), byId('langHiBtn')],
    ttsButton: byId('ttsToggleBtn'),
    ttsState: byId('ttsState'),
    modeButton: byId('modeBadgeBtn'),
    playButton: byId('playCallBtn'),
    stopButton: byId('stopCallBtn'),
    errorBanner: byId('errorBanner'),
    errorText: byId('errorBannerText'),
    offerReplayButton: byId('offerReplayBtn'),
    dismissErrorButton: byId('dismissErrorBtn'),
    callerStatus: byId('callerStatusLabel'),
    callTitle: byId('activeCallTitle'),
    callTimer: byId('callTimerText'),
    callDuration: byId('callDurationText'),
    warningCard: byId('phoneWarningCard'),
    verdictLabel: byId('phoneVerdictLabel'),
    verdictLocal: byId('phoneVerdictLocal'),
    riskPill: byId('phoneRiskPill'),
    warningText: byId('phoneWarningText'),
    actionPanel: byId('actionPanel'),
    actionCallLabel: byId('actionCallLabel'),
    actionReportLabel: byId('actionReportLabel'),
    flagsHeader: byId('phoneFlagsHeader'),
    flagsList: byId('phoneFlagsList'),
    riskMeter: /** @type {HTMLMeterElement} */ (byId('judgeRiskMeter')),
    riskScore: byId('judgeRiskScore'),
    riskVerdict: byId('judgeVerdictLabel'),
    warnedAt: byId('warnedAtText'),
    demandDelta: byId('demandDeltaText'),
    inFlight: byId('inFlightStatus'),
    queueLag: byId('queueLagStatus'),
    scamType: byId('scamTypeStatus'),
    englishWarning: byId('judgeWarningEn'),
    chunkSummary: byId('chunkSummaryMeta'),
    timeline: byId('chunkTimelineGrid'),
    transcript: byId('transcriptContainer'),
    transcriptMeta: byId('transcriptMeta'),
    politeRegion: byId('srPolite'),
    alertRegion: byId('srAlert'),
    uploadToggle: byId('toggleUploadBarBtn'),
    uploadBar: byId('uploadBar'),
    uploadForm: /** @type {HTMLFormElement} */ (byId('wavUploadForm')),
    fileInput: /** @type {HTMLInputElement} */ (byId('wavFileInput')),
    titleInput: /** @type {HTMLInputElement} */ (byId('wavTitleInput')),
    expectedSelect: /** @type {HTMLSelectElement} */ (byId('wavExpectedSelect')),
    uploadSubmit: /** @type {HTMLButtonElement} */ (byId('wavUploadSubmitBtn')),
    uploadFeedback: byId('uploadFeedback'),
  };
}

/** The verdict to display: a failed latest chunk shows "unavailable" until the next result. */
export function displayedVerdict(state) {
  return state.lastChunkUnavailable ? 'unavailable' : state.session.verdict || 'SAFE';
}

function elderWarning(state, verdict) {
  if (verdict === 'SAFE') return STATUS_TEXT.SAFE[state.lang];
  if (verdict === 'unavailable') return STATUS_TEXT.unavailable[state.lang];
  const fromServer = state.lang === 'gu' ? state.session.warning_gu : state.session.warning_hi;
  return fromServer || STATUS_TEXT.CAUTION[state.lang];
}

function judgeSummary(state, verdict) {
  if (verdict === 'unavailable') return 'Live analysis is unavailable for the latest chunk.';
  if (state.session.warning_en) return state.session.warning_en;
  return verdict === 'SAFE' ? 'No risk detected so far.' : 'Suspicious activity detected.';
}

function highlightedText(text, flags, signals) {
  const segments = highlightSegments(
    text,
    flags.map((flag) => flag.quote),
    signals.map((signal) => signal.quote),
  );
  return segments.map((segment) =>
    segment.kind === 'plain'
      ? document.createTextNode(segment.text)
      : el('mark', { className: `${segment.kind}-quote`, text: segment.text }),
  );
}

/**
 * @param {ReturnType<typeof queryDom>} dom
 * @param {{ onSelectCall: (callId: string) => void }} actions
 */
export function createView(dom, actions) {
  const cache = createRenderCache();

  function renderCallSelector(state) {
    const list = state.calls.map((c) => `${c.id}:${c.expected}:${c.title}`).join('|');
    // Rebuild only when the list changes, so the focused button survives a selection.
    cache.renderOnChange('calls', list, () => {
      dom.callSelector.replaceChildren(
        ...state.calls.map((call, position) => {
          const button = el(
            'button',
            {
              className: 'call-btn',
              attrs: { type: 'button', title: call.title, 'data-call-id': call.id },
            },
            [
              el('span', { text: `${position + 1}. ${call.title.split('—')[0].trim()}` }),
              el('span', { className: 'call-tag', text: `[${call.expected}]` }),
            ],
          );
          button.addEventListener('click', () => actions.onSelectCall(call.id));
          return button;
        }),
      );
    });
    const activeId = state.activeCall?.id ?? '';
    cache.renderOnChange('activeCall', `${list}#${activeId}`, () => {
      for (const button of dom.callSelector.querySelectorAll('button')) {
        button.setAttribute('aria-pressed', String(button.dataset.callId === activeId));
      }
    });
  }

  function renderToggles(state) {
    cache.renderOnChange(
      'toggles',
      `${state.lang}|${state.replayMode}|${state.speakWarning}`,
      () => {
        for (const button of dom.langButtons) {
          button.setAttribute('aria-pressed', String(button.dataset.lang === state.lang));
        }
        dom.ttsButton.setAttribute('aria-pressed', String(state.speakWarning));
        dom.ttsState.textContent = state.speakWarning ? 'ON' : 'OFF';
        dom.modeButton.textContent = state.replayMode ? 'REPLAY' : 'LIVE';
        dom.modeButton.dataset.mode = state.replayMode ? 'replay' : 'live';
      },
    );
  }

  /** What was last announced / spoken, reset whenever a call is (re)started. */
  let feedback = { selection: -1, announced: '', spoken: '' };

  function renderVerdict(state) {
    const call = state.activeCall;
    const verdict = displayedVerdict(state);
    const risk = state.session.risk || 0;
    const warning = elderWarning(state, verdict);
    const summary = judgeSummary(state, verdict);
    const signature = [
      verdict,
      risk,
      state.lang,
      warning,
      summary,
      call?.id,
      state.selectToken,
      state.speakWarning,
    ].join('|');

    cache.renderOnChange('verdict', signature, () => {
      if (feedback.selection !== state.selectToken) {
        feedback = { selection: state.selectToken, announced: '', spoken: '' };
      }
      const badge = VERDICT_BADGES[verdict] ?? VERDICT_BADGES.SAFE;
      dom.callTitle.textContent = call ? call.title : 'No call selected';
      dom.callDuration.textContent = formatPaddedClock(call?.duration ?? 0);

      dom.warningCard.dataset.verdict = verdict;
      dom.verdictLabel.textContent = badge.label;
      dom.verdictLocal.textContent = badge[state.lang];
      dom.verdictLocal.lang = state.lang;
      dom.riskPill.textContent = `Risk ${risk}/100`;
      dom.warningText.textContent = warning;
      dom.warningText.lang = state.lang;

      dom.actionPanel.hidden = verdict !== 'SCAM';
      dom.actionCallLabel.textContent = ACTION_LABELS.call[state.lang];
      dom.actionCallLabel.lang = state.lang;
      dom.actionReportLabel.textContent = ACTION_LABELS.report[state.lang];
      dom.actionReportLabel.lang = state.lang;

      dom.riskScore.textContent = String(risk);
      dom.riskVerdict.textContent = badge.label;
      dom.riskVerdict.dataset.verdict = verdict;
      dom.riskMeter.value = Math.min(100, Math.max(0, risk));
      dom.riskMeter.dataset.verdict = verdict;
      dom.riskMeter.textContent = `${risk} out of 100`;
      dom.riskMeter.setAttribute('aria-valuetext', `${risk} out of 100, ${badge.label}`);
      dom.englishWarning.textContent = summary;
      document.title = verdict === 'SCAM' ? `SCAM ALERT · ${DEFAULT_TITLE}` : DEFAULT_TITLE;

      // Announce changes only (not the initial SAFE state), assertively for SCAM.
      const announcement = `${badge.label} — ${badge[state.lang]}. ${warning}`;
      const isNews = announcement !== feedback.announced;
      if (call && isNews && (verdict !== 'SAFE' || feedback.announced)) {
        feedback.announced = announcement;
        const region = verdict === 'SCAM' ? dom.alertRegion : dom.politeRegion;
        announce(region, announcement, state.lang);
      }
      if (!state.speakWarning) {
        feedback.spoken = '';
      } else if (verdict === 'SCAM' && warning !== feedback.spoken) {
        feedback.spoken = warning;
        speak(warning, state.lang);
      }
    });
  }

  function renderFlags(state) {
    const flags = state.session.red_flags || [];
    cache.renderOnChange('flags', `${state.activeCall?.id}|${flags.length}|${state.lang}`, () => {
      dom.flagsHeader.textContent = flagsHeading(state.lang, flags.length);
      dom.flagsHeader.lang = state.lang;
      dom.flagsList.replaceChildren(
        ...flags
          .slice()
          .reverse()
          .map((flag) => {
            const meta = CHIP_LABELS[flag.type] ?? { gu: flag.type, hi: flag.type, tone: 'danger' };
            return el('li', { className: `flag-chip tone-${meta.tone}` }, [
              el('div', { className: 'flag-chip-top' }, [
                el('span', { text: meta[state.lang], lang: state.lang }),
                el('span', {
                  className: 'flag-chip-time',
                  text: flag.time_mm_ss || formatPaddedClock(flag.end_s),
                }),
              ]),
              el('q', {
                className: 'flag-chip-quote',
                text: flag.quote,
                lang: detectScriptLang(flag.quote),
              }),
            ]);
          }),
      );
    });
  }

  function renderTiming(state) {
    const call = state.activeCall;
    const firstScamAt = state.session.first_scam_at;
    const second = Math.floor(dom.audio.currentTime || 0);
    cache.renderOnChange('timing', `${call?.id}|${firstScamAt}|${second}`, () => {
      let headline = 'Monitoring call chunks in real time…';
      let detail = 'Genuine benchmark call (no scam demand expected)';
      let tone = 'neutral';
      if (call && firstScamAt != null) {
        headline = `Warned at ${formatClock(firstScamAt)} of ${formatClock(call.duration)}`;
        const lead = warningLead(firstScamAt, call.first_demand_at);
        const demandAt = formatClock(call.first_demand_at ?? 0);
        if (lead === null) {
          detail = 'Scam warning active on call';
        } else if (lead >= 0) {
          detail = `${lead} s before the first demand (at ${demandAt})`;
          tone = 'ahead';
        } else {
          detail = `${Math.abs(lead)} s after the first demand (at ${demandAt})`;
          tone = 'behind';
        }
      } else if (call) {
        if (call.expected === 'SAFE') {
          headline = `Call Status: SAFE (${formatClock(second)} of ${formatClock(call.duration)})`;
        }
        if (call.first_demand_at != null) {
          detail = `First caller demand benchmark at ${formatClock(call.first_demand_at)}`;
        }
      }
      dom.warnedAt.textContent = headline;
      dom.demandDelta.textContent = detail;
      dom.demandDelta.dataset.tone = tone;
    });
  }

  function renderTelemetry(state) {
    const lag = analysisLag(dom.audio.currentTime, state.results.values()).toFixed(1);
    const signature = `${state.inFlight}|${state.queue.length}|${lag}|${state.session.scam_type}`;
    cache.renderOnChange('telemetry', signature, () => {
      dom.inFlight.textContent = state.inFlight ? 'In-flight: 1 request' : 'In-flight: idle';
      dom.queueLag.textContent = `Queue: ${state.queue.length} | Lag: ${lag}s`;
      dom.scamType.textContent = `Type: ${state.session.scam_type || 'NONE'}`;
    });
  }

  function renderTimeline(state) {
    const chunks = state.activeCall?.chunks ?? [];
    const cells = chunks.map((chunk) =>
      describeChunkState(state.results.get(chunk.index), {
        queued: state.queue.includes(chunk.index),
        analyzing: state.inFlight && state.queue[0] === chunk.index,
      }),
    );
    cache.renderOnChange('timeline', `${state.activeCall?.id}|${JSON.stringify(cells)}`, () => {
      const analyzed = `${state.results.size} / ${chunks.length} chunks analyzed`;
      dom.chunkSummary.textContent = `${analyzed} · Playhead gated`;
      dom.timeline.replaceChildren(
        ...chunks.map((chunk, position) => {
          const cell = cells[position];
          return el('li', { className: 'chunk-cell', attrs: { 'data-state': cell.verdict } }, [
            el('div', { className: 'chunk-cell-top' }, [
              el('span', { text: `#${chunk.index + 1}` }),
              el('span', { text: cell.label }),
            ]),
            el('div', {
              className: 'chunk-cell-time',
              text: formatSpan(chunk.start_s, chunk.end_s),
            }),
            el('div', { className: 'chunk-cell-bottom' }, [
              el('span', { text: 'Latency' }),
              el('span', { text: cell.latency }),
            ]),
          ]);
        }),
      );
    });
  }

  function renderTranscript(state) {
    const { transcript = [], red_flags = [], genuine_signals = [] } = state.session;
    const counts = `${transcript.length}|${red_flags.length}|${genuine_signals.length}`;
    cache.renderOnChange('transcript', `${state.activeCall?.id}|${counts}`, () => {
      dom.transcriptMeta.textContent = `${transcript.length} utterances`;
      if (transcript.length === 0) {
        dom.transcript.replaceChildren(
          el('li', { className: 'transcript-empty', text: EMPTY_TRANSCRIPT }),
        );
        return;
      }
      dom.transcript.replaceChildren(
        ...transcript.map((turn) => {
          const speaker = SPEAKERS.has(turn.speaker) ? turn.speaker : 'UNKNOWN';
          const span = `${formatPaddedClock(turn.start_s)}–${formatPaddedClock(turn.end_s)}`;
          return el('li', { className: 'transcript-turn' }, [
            el('div', { className: 'transcript-turn-meta' }, [
              el('span', { className: `speaker speaker-${speaker}`, text: speaker }),
              el('span', { text: `Chunk #${(turn.chunk_index ?? 0) + 1} · ${span}` }),
            ]),
            el(
              'p',
              { className: 'transcript-turn-text', lang: detectScriptLang(turn.text) },
              highlightedText(turn.text, red_flags, genuine_signals),
            ),
          ]);
        }),
      );
    });
  }

  return {
    render(state) {
      renderCallSelector(state);
      renderToggles(state);
      renderVerdict(state);
      renderFlags(state);
      renderTiming(state);
      renderTelemetry(state);
      renderTimeline(state);
      renderTranscript(state);
    },

    /** @param {string} message @param {{ offerReplay?: boolean }} [options] */
    showError(message, { offerReplay = false } = {}) {
      dom.errorBanner.hidden = false;
      dom.offerReplayButton.hidden = !offerReplay;
      dom.errorText.textContent = message;
    },

    hideError() {
      dom.errorBanner.hidden = true;
    },

    /** @param {string} message @param {'' | 'pending' | 'error' | 'success'} [tone] */
    setUploadFeedback(message, tone = '') {
      dom.uploadFeedback.textContent = message;
      dom.uploadFeedback.dataset.tone = tone;
      dom.fileInput.setAttribute('aria-invalid', String(tone === 'error'));
    },
  };
}
