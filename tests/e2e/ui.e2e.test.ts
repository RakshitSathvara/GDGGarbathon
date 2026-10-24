/**
 * End-to-end test in headless Chromium: the real Express app and frontend (under its strict CSP)
 * with a scripted detector. Audits WCAG 2.2 A/AA with axe-core before and after a scam is detected.
 *
 * Run with `npm run test:e2e` (needs `npx playwright install chromium` once).
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { after, before, describe, test } from 'node:test';
import { type Browser, chromium, type Page } from 'playwright';
import { createApp } from '../../server/app.ts';
import type { DetectorResult } from '../../server/types.ts';
import {
  analysis,
  createTempProject,
  scriptedDetector,
  silentLogger,
  startServer,
} from '../node/support.ts';

const require = createRequire(import.meta.url);
const AXE_SOURCE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'];

const CALM: DetectorResult = {
  status: 'ok',
  latency_ms: 150,
  model: 'test-model',
  ...analysis({ transcript: [{ speaker: 'CALLER', text: 'નમસ્તે, બેંકમાંથી બોલું છું' }], risk_score: 15 }),
};
const SCAM: DetectorResult = {
  status: 'ok',
  latency_ms: 180,
  model: 'test-model',
  ...analysis({
    transcript: [{ speaker: 'CALLER', text: 'તમારો OTP આપો નહીં તો ખાતું બંધ થશે' }],
    new_red_flags: [{ type: 'OTP_OR_CREDENTIALS', quote: 'તમારો OTP આપો', why: 'Asks for OTP' }],
    scam_type: 'FAKE_KYC',
    risk_score: 85,
    verdict: 'SCAM',
    warning_gu: 'સાવધાન! "તમારો OTP આપો" — OTP ન આપો. ફોન કાપો અને 1930 પર ફોન કરો.',
    warning_hi: 'सावधान! "તમારો OTP આપો" — OTP मत दीजिए। फ़ोन काटिए और 1930 पर कॉल कीजिए।',
    warning_en: 'Warning! Caller asked for your OTP ("તમારો OTP આપો"). Hang up and call 1930.',
  }),
};

interface AxeViolation {
  id: string;
  impact: string;
  nodes: string[];
}

async function axeViolations(page: Page): Promise<AxeViolation[]> {
  return page.evaluate(async (tags) => {
    type AxeResult = {
      violations: { id: string; impact: string; nodes: { target: string[] }[] }[];
    };
    const { axe } = window as unknown as {
      axe: { run(context: Document, options: object): Promise<AxeResult> };
    };
    // preload: false stops axe fetching the Google Fonts stylesheet over XHR, which the page's
    // connect-src 'self' policy (correctly) blocks and would report as a console error.
    const results = await axe.run(document, {
      runOnly: { type: 'tag', values: tags },
      preload: false,
    });
    return results.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((node) => node.target.join(' ')),
    }));
  }, AXE_TAGS);
}

describe('Saavdhan UI in Chromium', () => {
  const project = createTempProject(['fake_kyc.wav']);
  const consoleErrors: string[] = [];
  let browser: Browser;
  let page: Page;
  let server: Awaited<ReturnType<typeof startServer>>;

  before(async () => {
    const { detector } = scriptedDetector((chunk) => (chunk >= 2 ? SCAM : CALM));
    server = await startServer(
      createApp({ config: project.config, detector, logger: silentLogger }),
    );
    browser = await chromium.launch();
    page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    page.on('pageerror', (error) => consoleErrors.push(error.message));
    // Init scripts are injected by the browser, so axe runs without weakening the page's CSP.
    await page.addInitScript({ content: AXE_SOURCE });
    await page.goto(server.url);
    await page.locator('#callSelector button[aria-pressed="true"]').waitFor();
  });

  after(async () => {
    await browser?.close();
    await server?.close();
    project.cleanup();
  });

  test('the initial screen has no WCAG 2.2 AA violations', async () => {
    assert.deepEqual(await axeViolations(page), []);
  });

  test('the skip link moves keyboard focus to the main content', async () => {
    await page.keyboard.press('Tab');
    assert.equal(
      await page.evaluate(() => document.activeElement?.textContent?.trim()),
      'Skip to main content',
    );
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'main');
  });

  test('playing a scam call escalates to SCAM with evidence and actions', async () => {
    await page.getByRole('button', { name: 'Start Call' }).click();
    await page.evaluate(() => {
      const audio = document.querySelector('audio');
      if (audio) audio.playbackRate = 8;
    });
    await page.locator('#phoneWarningCard[data-verdict="SCAM"]').waitFor({ timeout: 30_000 });

    assert.ok(await page.locator('#actionPanel').isVisible());
    assert.equal(await page.locator('#actionPanel a[href="tel:1930"]').count(), 1);
    assert.match((await page.locator('#phoneWarningText').textContent()) ?? '', /OTP/);
    assert.ok((await page.locator('#phoneFlagsList li').count()) >= 1);
    assert.ok((await page.locator('#transcriptContainer mark.flag-quote').count()) >= 1);
    assert.equal(
      await page.locator('#judgeRiskMeter').evaluate((m) => (m as HTMLMeterElement).value),
      85,
    );
    assert.match(await page.title(), /^SCAM ALERT/);
    await page.waitForFunction(() =>
      document.getElementById('srAlert')?.textContent?.includes('SCAM ALERT'),
    );
  });

  test('the SCAM state has no WCAG 2.2 AA violations', async () => {
    assert.deepEqual(await axeViolations(page), []);
  });

  test('switching to Hindi updates text, lang attributes and pressed state', async () => {
    await page.locator('#langHiBtn').click();
    assert.equal(await page.locator('#langHiBtn').getAttribute('aria-pressed'), 'true');
    assert.equal(await page.locator('#langGuBtn').getAttribute('aria-pressed'), 'false');
    assert.equal(await page.locator('#phoneWarningText').getAttribute('lang'), 'hi');
    assert.match((await page.locator('#phoneWarningText').textContent()) ?? '', /सावधान/);
  });

  test('runs without console errors or CSP violations', () => {
    assert.deepEqual(consoleErrors, []);
  });
});
