import { ConfigurationError } from '../errors.js';

/**
 * Uppercase letters and digits a person cannot confuse when reading them off one screen
 * and matching them on another: no 0/O, 1/I/L, 5/S, 2/Z, 8/B.
 */
export const BINDING_CODE_ALPHABET = 'ACDEFGHJKMNPQRTUVWXY34679';

/**
 * A short random code for a CIBA `binding_message`, e.g. `K7QM`.
 *
 * Show it in your terminal and put it in the binding message; Cbox ID shows the message
 * beside Approve, and the person approves only when the two match. That is what stops a
 * prompt somebody else triggered from being approved by reflex. Cbox ID requires a
 * binding message from self-registered clients.
 *
 * Uniform over the alphabet (rejection sampling, WebCrypto randomness).
 */
export function createBindingCode(length = 4): string {
  if (!Number.isInteger(length) || length < 1 || length > 32) {
    throw new ConfigurationError('A binding code length must be an integer from 1 to 32.');
  }

  const size = BINDING_CODE_ALPHABET.length;
  // The largest multiple of `size` that fits in a byte; bytes at or above it are dropped so
  // every character is equally likely.
  const limit = 256 - (256 % size);
  let code = '';

  while (code.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && code.length < length) {
        code += BINDING_CODE_ALPHABET[byte % size];
      }
    }
  }

  return code;
}
