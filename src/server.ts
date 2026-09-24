/**
 * `@cboxdk/id-js/server` — what needs your client secret and must never reach a browser
 * bundle. Import it from server code only (a route handler, an API middleware, a worker).
 */
export {
  ApiKeyVerifier,
  MAX_API_KEY_CACHE_TTL_MS,
  type ActiveApiKey,
  type ApiKeyVerification,
  type ApiKeyVerifierConfig,
  type InactiveApiKey,
} from './api-keys.js';
