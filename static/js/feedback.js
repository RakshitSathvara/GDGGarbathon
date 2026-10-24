/**
 * Non-visual feedback: screen-reader announcements, spoken warnings and the scam alert beep.
 * All of it is best-effort; the on-screen warning is always authoritative.
 */
import { speechLocale } from './i18n.js';

/**
 * Speaks `message` through a visually hidden live region.
 * @param {HTMLElement} region element with aria-live
 * @param {string} message
 * @param {string} [lang] BCP 47 tag so the screen reader picks the right voice
 */
export function announce(region, message, lang) {
  if (lang) region.lang = lang;
  else region.removeAttribute('lang');
  region.textContent = '';
  // Clearing first guarantees an identical message is announced again.
  requestAnimationFrame(() => {
    region.textContent = message;
  });
}

let audioContext = null;

/** Two short tones when a call first turns SCAM (one shared AudioContext for the page). */
export function playScamBeep() {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    audioContext ??= new AudioContextClass();
    const now = audioContext.currentTime;
    for (const offset of [0, 0.18]) {
      const oscillator = audioContext.createOscillator();
      const gain = audioContext.createGain();
      oscillator.type = 'sawtooth';
      oscillator.frequency.setValueAtTime(880, now + offset);
      gain.gain.setValueAtTime(0.18, now + offset);
      gain.gain.exponentialRampToValueAtTime(0.001, now + offset + 0.14);
      oscillator.connect(gain);
      gain.connect(audioContext.destination);
      oscillator.start(now + offset);
      oscillator.stop(now + offset + 0.15);
    }
  } catch {
    // Autoplay policies can block audio; the visual warning still shows.
  }
}

/** Reads a warning aloud in Gujarati or Hindi. @param {string} text @param {'gu' | 'hi'} lang */
export function speak(text, lang) {
  if (!text || !('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.lang = speechLocale(lang);
  utterance.rate = 0.95;
  window.speechSynthesis.speak(utterance);
}

export function stopSpeaking() {
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
}
