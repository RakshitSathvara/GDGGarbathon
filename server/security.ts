/**
 * HTTP hardening: strict Content-Security-Policy and companion headers (helmet),
 * a deny-all Permissions-Policy, no-store for API responses, and per-IP rate limits.
 */
import type { RequestHandler } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import type { RateLimitRule } from './config.ts';

const PERMISSIONS_POLICY = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()';

export function securityHeaders(frameAncestors: readonly string[] | null): RequestHandler {
  const directives: Record<string, string[]> = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'script-src-attr': ["'none'"],
    'style-src': ["'self'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:'],
    'media-src': ["'self'", 'blob:'],
    'connect-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
  };
  if (frameAncestors) directives['frame-ancestors'] = [...frameAncestors];

  const headers = helmet({
    contentSecurityPolicy: { useDefaults: false, directives },
    // Embedding is governed by CSP frame-ancestors (FRAME_ANCESTORS) rather than X-Frame-Options,
    // because Google AI Studio renders the app preview inside a cross-origin iframe.
    frameguard: false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  });

  return (req, res, next) => {
    res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
    headers(req, res, next);
  };
}

/** Session data and analysis results must never be cached by browsers or proxies. */
export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
};

export function createRateLimiter(rule: RateLimitRule): RequestHandler {
  return rateLimit({
    windowMs: rule.windowMs,
    limit: rule.limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { detail: 'Too many requests. Please wait a moment and try again.' },
  });
}
