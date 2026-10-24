import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, test } from 'node:test';
import { DEFAULT_MODEL, loadConfig, ROOT_DIR } from '../../server/config.ts';

describe('loadConfig', () => {
  test('uses safe defaults without any environment', () => {
    const config = loadConfig({}, '/srv/app');
    assert.equal(config.paths.manifest, path.join('/srv/app', 'calls', 'manifest.json'));
    assert.equal(config.server.port, 3000);
    assert.equal(config.server.trustProxy, 1);
    assert.equal(config.server.frameAncestors, null);
    assert.equal(config.gemini.apiKey, null);
    assert.equal(config.gemini.model, DEFAULT_MODEL);
    assert.equal(config.gemini.thinkingLevel, 'minimal');
    assert.equal(config.analysis.chunkSec, 6);
    assert.equal(config.analysis.demoReplay, false);
  });

  test('reads overrides and clamps numbers into range', () => {
    const config = loadConfig({
      PORT: '8080',
      CHUNK_SEC: '1',
      MODEL: 'gemini-3.8-flash',
      THINKING_LEVEL: 'HIGH',
      DEMO_REPLAY: '1',
      GEMINI_API_KEY: ' key-123 ',
      FRAME_ANCESTORS: "'self' https://aistudio.google.com",
    });
    assert.equal(config.server.port, 8080);
    assert.equal(config.analysis.chunkSec, 3);
    assert.equal(config.gemini.model, 'gemini-3.8-flash');
    assert.equal(config.gemini.thinkingLevel, 'high');
    assert.equal(config.analysis.demoReplay, true);
    assert.equal(config.gemini.apiKey, 'key-123');
    assert.deepEqual(config.server.frameAncestors, ["'self'", 'https://aistudio.google.com']);
  });

  test('ignores invalid values and the placeholder API key', () => {
    const config = loadConfig({
      PORT: 'eighty',
      CHUNK_SEC: '',
      THINKING_LEVEL: 'extreme',
      MODEL: 'gemini-3.8-flash',
      GEMINI_API_KEY: 'MY_GEMINI_API_KEY',
    });
    assert.equal(config.server.port, 3000);
    assert.equal(config.analysis.chunkSec, 6);
    assert.equal(config.gemini.thinkingLevel, 'low');
    assert.equal(config.gemini.apiKey, null);
  });

  test('resolves the project root from the module location', () => {
    assert.equal(path.join(ROOT_DIR, 'server', 'config.ts'), path.resolve('server', 'config.ts'));
  });
});
