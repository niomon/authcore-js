import spake2 from '../../crypto/spake2.js'

/**
 * A higher-level API for performance authentication transaction.
 */
class AuthnTransaction {
  constructor (authcore) {
    this.authcore = authcore
  }

  /**
   * Start a primary authentication transaction.
   *
   * @param {string} handle A user handle.
   * @param {string} redirectURI URL to redirect to after a successful authentication transaction.
   * @param {object} options The options specific for this request.
   * @returns {object} An authentication state.
   */
  async start (handle, redirectURI, options = {}) {
    return this.authcore.authn.start(handle, redirectURI, options)
  }

  /**
   * Verify password factor. This method performs verification handshake if needed.
   *
   * @param {object} state The authentication state returned by start.
   * @param {string} password A plaintext password.
   * @returns {object} An authentication state.
   */
  async verifyPassword (state, password) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    if (state['password_method'] !== 'spake2plus') {
      throw new Error('password authentication is not allowed')
    }
    if (typeof state['password_salt'] !== 'string') {
      throw new Error('password_salt is undefined')
    }
    if (typeof password !== 'string') {
      throw new Error('password is required')
    }
    const stateToken = state['state_token']
    const salt = Buffer.from(state['password_salt'], 'base64')
    const ps = await spake2().startClient('authcoreuser', 'authcore', password, salt)
    const message = ps.getMessage()
    const challenge = await this.authcore.authn.requestPassword(stateToken, message)

    const sharedSecret = ps.finish(challenge)
    const confirmation = sharedSecret.getConfirmation()

    return this.authcore.authn.verifyPassword(stateToken, confirmation)
  }

  /**
   * Request a SMS OTP challenge.
   *
   * @param {object} state The authentication state returned by start.
   * @returns {object} An authentication state.
   */
  async requestSMSOTP (state) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    const stateToken = state['state_token']
    const message = Buffer.alloc()
    return this.authcore.authn.requestMFA(stateToken, 'sms_otp', message)
  }

  /**
   * Verify a SMS OTP factor.
   *
   * @param {object} state The authentication state returned by start.
   * @param {string} code A SMS code.
   * @returns {object} An authentication state.
   */
  async verifySMSOTP (state, code) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    if (typeof code !== 'string') {
      throw new Error('code is required')
    }
    const stateToken = state['state_token']
    const verifier = Buffer.from(code)
    return this.authcore.authn.verifyMFA(stateToken, 'sms_otp', verifier)
  }

  /**
   * Verify a TOTP factor.
   *
   * @param {object} state The authentication state returned by start.
   * @param {string} code A TOTP code.
   * @returns {object} An authentication state.
   */
  async verifyTOTP (state, code) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    if (typeof code !== 'string') {
      throw new Error('code is required')
    }
    const stateToken = state['state_token']
    const verifier = Buffer.from(code)
    return this.authcore.authn.verifyMFA(stateToken, 'totp', verifier)
  }

  /**
   * Verify a backup code factor.
   *
   * @param {object} state The authentication state returned by start.
   * @param {string} code A backup code.
   * @returns {object} An authentication state.
   */
  async verifyBackupCode (state, code) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    if (typeof code !== 'string') {
      throw new Error('code is required')
    }
    const stateToken = state['state_token']
    const verifier = Buffer.from(code)
    return this.authcore.authn.verifyMFA(stateToken, 'backup_code', verifier)
  }
}

export default AuthnTransaction
