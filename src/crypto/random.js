import crypto from 'crypto'
import base32Encode from 'base32-encode'
import { fromString } from '../utils/formatBuffer'

/**
 * Generate a random secret for time-based one-time password (TOTP).
 * - 20-byte entropy is used as suggested from
 *   [section 4 of RFC4226](https://tools.ietf.org/html/rfc4226#section-4), which "RECOMMENDs a
 *   shared secret length of 160 bits".
 * - Base32 is commonly used to store secrets for one-time passwords.
 *
 * @private
 * @returns {Buffer} A random secret for the time-based one-time password.
 */
function randomTOTPSecret () {
  const randomBuffer = crypto.randomBytes(32)
  const hash = crypto.createHash('sha1').update(randomBuffer).digest()
  return fromString(base32Encode(hash, 'RFC4648'))
}

export { randomTOTPSecret }
