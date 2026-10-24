/**
 * Saavdhan Node server entrypoint (used by `npm run dev` / `npm start` and Google AI Studio).
 * All behaviour lives in server/; this file only wires configuration to the app and starts listening.
 */
import dotenv from 'dotenv';
import { createApp } from './server/app.ts';
import { loadConfig } from './server/config.ts';
import {
  createDetector,
  createGeminiGenerate,
  loadDetectorPrompt,
  planAttempts,
} from './server/detector.ts';

dotenv.config({ quiet: true });

const config = loadConfig();
const { apiKey, model, thinkingLevel, fallbackModel, timeoutMs } = config.gemini;

const detector = createDetector({
  generate: apiKey ? createGeminiGenerate(apiKey, loadDetectorPrompt(config.paths.prompt)) : null,
  attempts: planAttempts(model, thinkingLevel, fallbackModel),
  timeoutMs,
});

if (!apiKey) {
  console.warn('GEMINI_API_KEY is not set: live analysis is disabled (replay mode still works).');
}

const server = createApp({ config, detector }).listen(
  config.server.port,
  config.server.host,
  () => {
    console.log(`Saavdhan server listening on http://${config.server.host}:${config.server.port}`);
  },
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
  });
}
