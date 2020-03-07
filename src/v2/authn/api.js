import { Buffer } from 'buffer'

const basePath = '/api/v2'

/**
 * API client for Authcore Authn API v2. Use AuthnTransaction for a higher level API.
 */
class AuthnAPI {
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
    if (typeof handle !== 'string') {
      throw new Error('handle is required')
    }
    if (typeof redirectURI !== 'string') {
      throw new Error('redirectURI is required')
    }
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    if (options.codeChallengeMethod && typeof options.codeChallengeMethod !== 'string') {
      throw new Error('codeChallengeMethod must be a string')
    }
    if (options.codeChallenge && typeof options.codeChallenge !== 'string') {
      throw new Error('codeChallenge must be a string')
    }
    const resp = await this.authcore._http().post(basePath + '/authn', {
      'client_id': this.authcore.clientId,
      'handle': handle,
      'redirect_uri': redirectURI,
      'code_challenge_method': options.codeChallengeMethod,
      'code_challenge': options.codeChallenge
    })
    return resp.data
  }

  /**
   * Request a password key exchange challenge.
   *
   * @param {string} stateToken A state token.
   * @param {Buffer} message A password key exchange message.
   * @returns {Buffer} A password key exchange challenge message.
   */
  async requestPassword (stateToken, message) {
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(message)) {
      throw new Error('message must be a buffer')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/password', {
      'state_token': stateToken,
      'message': message.toString('base64')
    })
    const challenge = resp.data['challenge']
    return Buffer.from(challenge, 'base64')
  }

  /**
   * Verify password factor.
   *
   * @param {string} stateToken A state token.
   * @param {Buffer} response A password verification response.
   * @returns {object} An authentication state.
   */
  async verifyPassword (stateToken, response) {
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(response)) {
      throw new Error('response must be a buffer')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/password/verify', {
      'state_token': stateToken,
      'verifier': response.toString('base64')
    })
    return resp.data
  }

  /**
   * Request a MFA challenge.
   *
   * @param {string} stateToken A state token.
   * @param {string} method A MFA method.
   * @param {Buffer} message A request message.
   * @returns {Buffer} A password key exchange challenge message.
   */
  async requestMFA (stateToken, method, message) {
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (typeof method !== 'string') {
      throw new Error('method is required')
    }
    if (!/^\w+$/.test(method)) {
      throw new Error('invalid method')
    }
    if (!message) {
      message = Buffer.alloc(0)
    }
    if (!Buffer.isBuffer(message)) {
      throw new Error('message must be a buffer')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/mfa/' + method, {
      'state_token': stateToken,
      'message': message.toString('base64')
    })
    const challenge = resp.data['challenge']
    return Buffer.from(challenge, 'base64')
  }

  /**
   * Verify MFA factor.
   *
   * @param {string} stateToken A state token.
   * @param {string} method A MFA method.
   * @param {Buffer} verifier A MFA verification response.
   * @returns {object} An authentication state.
   */
  async verifyMFA (stateToken, method, verifier) {
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (typeof method !== 'string') {
      throw new Error('method is required')
    }
    if (!/^\w+$/.test(method)) {
      throw new Error('invalid method')
    }
    if (!Buffer.isBuffer(verifier)) {
      throw new Error('verifier must be a buffer')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/mfa/' + method + '/verify', {
      'state_token': stateToken,
      'verifier': verifier.toString('base64')
    })
    return resp.data
  }

  /**
   * Start a third-party IDP authentication transaction.
   *
   * @param {string} idp Name of the third-party IDP.
   * @param {string} redirectURI URL to redirect to after a successful authentication transaction.
   * @param {object} options The options specific for this request.
   * @returns {object} An authentication state.
   */
  async startIDP (idp, redirectURI, options = {}) {
    if (typeof idp !== 'string') {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
    }
    if (typeof idp !== 'string') {
      throw new Error('idp is required')
    }
    if (typeof redirectURI !== 'string') {
      throw new Error('redirectURI is required')
    }
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    if (options.codeChallengeMethod && typeof options.codeChallengeMethod !== 'string') {
      throw new Error('codeChallengeMethod must be a string')
    }
    if (options.codeChallenge && typeof options.codeChallenge !== 'string') {
      throw new Error('codeChallenge must be a string')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/idp/' + encodeURIComponent(idp), {
      'client_id': this.authcore.clientId,
      'redirect_uri': redirectURI,
      'code_challenge_method': options.codeChallengeMethod,
      'code_challenge': options.codeChallenge
    })
    return resp.data
  }

  /**
   * Verify a third-party IDP authorization grant.
   *
   * @param {string} stateToken A state token.
   * @param {string} code A authorization code grant.
   * @returns {object} An authentication state.
   */
  async verifyIDP (stateToken, code) {
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (typeof code !== 'string') {
      throw new Error('code is required')
    }
    const resp = await this.authcore._http().post(basePath + '/authn/idp/-/verify', {
      'state_token': stateToken,
      'code': code
    })
    return resp.data
  }

  /**
   * Exchange authorization grant for access token.
   *
   * @param {string} type Grant type.
   * @param {string} token A authorization code or refresh token.
   * @param {object} options Other parameters to be passed to token endpoint.
   * @returns {object} An object containing access token.
   */
  async exchange (type, token, options = {}) {
    if (typeof type !== 'string') {
      throw new Error('type is required')
    }
    if (typeof token !== 'string') {
      throw new Error('token is required')
    }
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    var tokenParam = type === 'refresh_token' ? 'refresh_token' : 'code'
    var req = {
      client_id: this.authcore.clientId,
      grant_type: type,
      [tokenParam]: token
    }
    Object.assign(req, options)
    const resp = await this.authcore._http().post(basePath + '/token', req)
    return resp.data
  }
}

export default AuthnAPI
