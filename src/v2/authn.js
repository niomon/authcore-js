import spake2 from '../crypto/spake2.js'

/**
 * A higher-level API for performing authentication transaction.
 */
class Authn {
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
    return this.authcore.client.start(handle, redirectURI, options)
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
    const challenge = await this.authcore.client.requestPassword(stateToken, message)

    const sharedSecret = ps.finish(challenge)
    const confirmation = sharedSecret.getConfirmation()

    return this.authcore.client.verifyPassword(stateToken, confirmation)
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
    return this.authcore.client.requestMFA(stateToken, 'sms_otp', message)
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
    return this.authcore.client.verifyMFA(stateToken, 'sms_otp', verifier)
  }

  async requestPass (state) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    const stateToken = state['state_token']
    const message = Buffer.alloc(0)
    console.log('requestPass')
    return this.authcore.client.requestMFA(stateToken, 'pass', message)
  }

  async verifyPass (state, code) {
    if (typeof state !== 'object') {
      throw new Error('state is required')
    }
    if (typeof state['state_token'] !== 'string') {
      throw new Error('state_token is undefined')
    }
    if (typeof code !== 'object') {
      throw new Error('code is required')
    }
    if (typeof code.type !== 'string') {
      throw new Error('code.type is required')
    }
    if (typeof code.message !== 'string' && typeof code.code !== 'string') {
      throw new Error('code.message / code.code is required')
    }
    const stateToken = state['state_token']
    const verifier = Buffer.from(JSON.stringify(code))
    return this.authcore.client.verifyMFA(stateToken, 'pass', verifier)
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
    return this.authcore.client.verifyMFA(stateToken, 'totp', verifier)
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
    return this.authcore.client.verifyMFA(stateToken, 'backup_code', verifier)
  }

  /**
   * Perform password step-up authentication. This method performs verification handshake if needed.
   *
   * @param {string} password A plaintext password.
   * @returns {object} An authentication state.
   */
  async verifyPasswordStepUp (password) {
    if (typeof password !== 'string') {
      throw new Error('password is required')
    }

    const state = await this.authcore.client.startStepUp()

    const stateToken = state['state_token']
    const salt = Buffer.from(state['password_salt'], 'base64')
    const ps = await spake2().startClient('authcoreuser', 'authcore', password, salt)
    const message = ps.getMessage()
    const challenge = await this.authcore.client.requestPasswordStepUp(stateToken, message)

    const sharedSecret = ps.finish(challenge)
    const confirmation = sharedSecret.getConfirmation()
    return this.authcore.client.verifyPasswordStepUp(stateToken, confirmation)
  }
}

export default Authn
