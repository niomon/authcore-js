import { createVerifier } from '../crypto/spake2.js'
import { randomTOTPSecret } from '../crypto/random.js'

/**
 * Create a password verifier based on current settings.
 *
 * @param {string} password The plaintext password.
 * @returns {object} A password verifier.
 */
export async function createPasswordVerifier (password) {
  const v = await createVerifier(password)
  // The format used by API 2.0 is different
  return {
    method: 'spake2plus',
    salt: v.salt,
    w0: v.verifier.w0,
    l: v.verifier.L
  }
}

/**
 * Create a new TOTP secret.
 *
 * @returns {string} A random TOTP secret.
 */
export function generateTOTPSecret () {
  return randomTOTPSecret().toString('utf-8')
}
