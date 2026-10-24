/**
 * Localized text shown to the elder. Gujarati (gu) and Hindi (hi) strings are rendered with the
 * matching `lang` attribute so screen readers and text-to-speech pick the right voice.
 * Warning sentences themselves come from the server (shared/detection_policy.json + Gemini).
 */

/** @typedef {'gu' | 'hi'} Lang */

/** Red-flag chip labels; `tone` selects the chip colour (notice < warning < danger). */
export const CHIP_LABELS = {
  AUTHORITY_CLAIM: { gu: 'પોલીસ/બેંક હોવાનો દાવો', hi: 'पुलिस/बैंक होने का दावा', tone: 'notice' },
  URGENCY: { gu: 'ઉતાવળ કરાવે છે', hi: 'जल्दबाज़ी का दबाव', tone: 'warning' },
  THREAT: { gu: 'ધમકી', hi: 'धमकी', tone: 'warning' },
  OTP_OR_CREDENTIALS: { gu: 'OTP/PIN માંગ્યો', hi: 'OTP/PIN माँगा', tone: 'danger' },
  MONEY_REQUEST: { gu: 'પૈસા માંગ્યા', hi: 'पैसे माँगे', tone: 'danger' },
  REMOTE_ACCESS_OR_LINK: {
    gu: 'એપ/લિંક ખોલાવવાનો પ્રયાસ',
    hi: 'ऐप/लिंक खुलवाने की कोशिश',
    tone: 'danger',
  },
  SECRECY: { gu: 'કોઈને ન કહેવાનું કહ્યું', hi: 'किसी को न बताने को कहा', tone: 'danger' },
  HANDOFF_TO_OFFICIAL: { gu: 'કોલ "પોલીસ"ને ટ્રાન્સફર', hi: 'कॉल "पुलिस" को ट्रांसफ़र', tone: 'danger' },
};

/** Verdict badge: English label for the judge plus the elder's language. */
export const VERDICT_BADGES = {
  SAFE: { label: 'SAFE', gu: 'સુરક્ષિત', hi: 'सुरक्षित' },
  SUSPICIOUS: { label: 'SUSPICIOUS', gu: 'શંકાસ્પદ કોલ', hi: 'संदिग्ध कॉल' },
  SCAM: { label: 'SCAM ALERT', gu: 'સાવધાન ફ્રોડ કોલ!', hi: 'सावधान फ्रॉड कॉल!' },
  unavailable: { label: 'UNAVAILABLE', gu: 'ચકાસણી અપ્રાપ્ય', hi: 'जाँच अनुपलब्ध' },
};

export const STATUS_TEXT = {
  SAFE: { gu: 'અત્યાર સુધી કોઈ જોખમ સંભળાયું નથી', hi: 'अभी तक कोई ख़तरा सुनाई नहीं दिया' },
  unavailable: {
    gu: 'કોલ ચકાસણી અત્યારે ઉપલબ્ધ નથી — સાવચેત રહો',
    hi: 'कॉल जाँच अभी उपलब्ध नहीं है — सतर्क रहें',
  },
  /** Defensive fallback if a risky verdict ever arrives without warning text. */
  CAUTION: {
    gu: 'સાવધાન! કોઈ માહિતી ન આપો. ફોન કાપી નાખો અને 1930 પર ફોન કરો.',
    hi: 'सावधान! कोई जानकारी मत दीजिए। फ़ोन काट दीजिए और 1930 पर कॉल कीजिए।',
  },
};

/** One-tap actions offered once a call is judged a scam. */
export const ACTION_LABELS = {
  call: { gu: '1930 પર ફોન કરો', hi: '1930 पर कॉल करें' },
  report: { gu: 'ઓનલાઇન ફરિયાદ નોંધાવો', hi: 'ऑनलाइन शिकायत दर्ज करें' },
};

/** @param {Lang} lang @param {number} count */
export function flagsHeading(lang, count) {
  return lang === 'gu' ? `સંભળાયેલા જોખમી સંકેતો (${count})` : `सुने गए ख़तरे के संकेत (${count})`;
}

/** BCP 47 voice for the Web Speech API. @param {Lang} lang */
export function speechLocale(lang) {
  return lang === 'gu' ? 'gu-IN' : 'hi-IN';
}
