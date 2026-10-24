/**
 * Thin client for the Saavdhan HTTP API with per-request timeouts and readable errors.
 */

export class ApiError extends Error {
  /** @param {string} message @param {number} status HTTP status (0 for network/timeout) */
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: unknown, timeoutMs?: number, fetchImpl?: typeof fetch }} [options]
 */
export async function request(path, options = {}) {
  const { method = 'GET', body, timeoutMs = 30_000, fetchImpl = fetch } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof data?.detail === 'string' ? data.detail : '';
      throw new ApiError(detail || `Request failed (HTTP ${response.status})`, response.status);
    }
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error?.name === 'AbortError') {
      throw new ApiError('The server took too long to respond.', 0);
    }
    throw new ApiError('Network error: could not reach the Saavdhan server.', 0);
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  listCalls: () => request('/api/calls'),
  /** @param {string} callId */
  createSession: (callId) => request('/api/session', { method: 'POST', body: { call_id: callId } }),
  /** @param {string} sessionId @param {number} chunkIndex @param {boolean} replay */
  analyzeChunk: (sessionId, chunkIndex, replay) =>
    request('/api/analyze', {
      method: 'POST',
      body: { session_id: sessionId, chunk_index: chunkIndex, replay },
      timeoutMs: 45_000,
    }),
  /** @param {{ filename: string, data_base64: string, title?: string, expected: string }} payload */
  uploadWav: (payload) =>
    request('/api/upload', { method: 'POST', body: payload, timeoutMs: 90_000 }),
};
