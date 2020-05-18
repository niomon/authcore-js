import axios from 'axios'
import { typeChecker } from '../utils/util'

const basePath = '/api/v2'

/**
 * Authcore API 2.0 Client.
 */
class Client {
  constructor (authcore, options = {}) {
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    if (options.errorHandler) {
      if (typeof options.errorHandler !== 'function') {
        throw new Error('options.errorHandler must be a function')
      }
      this.errorHandler = options.errorHandler
    } else {
      this.errorHandler = defaultErrorHandler
    }
    this.authcore = authcore
  }

  /**
   * Start a primary authentication transaction.
   *
   * @param {string} handle A user handle.
   * @param {string} redirectURI URL to redirect to after a successful authentication transaction.
   * @param {object} options The options specific for this request.
   * @param {string} options.codeChallenge A PKCE challenge.
   * @param {string} options.codeChallengeMethod A PKCE challenge method.
   * @param {string} options.clientState A state from OAuth client.
   * @returns {object} An authentication state.
   */
  async start (handle, redirectURI, options = {}) {
    if (!typeChecker(handle, 'string', true)) {
      throw new Error('handle is required')
    }
    if (!typeChecker(redirectURI, 'string', true)) {
      throw new Error('redirectURI is required')
    }
    if (!typeChecker(options, 'object', true)) {
      throw new Error('options must be an object')
    }
    if (!typeChecker(options.codeChallengeMethod, 'string')) {
      throw new Error('codeChallengeMethod must be a string')
    }
    if (!typeChecker(options.codeChallenge, 'string')) {
      throw new Error('codeChallenge must be a string')
    }
    if (!typeChecker(options.clientState, 'string')) {
      throw new Error('clientState must be a string')
    }
    const resp = await this._http(false).post(basePath + '/authn', {
      'client_id': this.authcore.clientId,
      'handle': handle,
      'redirect_uri': redirectURI,
      'code_challenge_method': options.codeChallengeMethod,
      'code_challenge': options.codeChallenge,
      'client_state': options.clientState
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
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(message)) {
      throw new Error('message must be a buffer')
    }
    const resp = await this._http(false).post(basePath + '/authn/password', {
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
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(response)) {
      throw new Error('response must be a buffer')
    }
    const resp = await this._http(false).post(basePath + '/authn/password/verify', {
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
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!typeChecker(method, 'string', true)) {
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
    const resp = await this._http(false).post(basePath + '/authn/mfa/' + method, {
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
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!typeChecker(method, 'string', true)) {
      throw new Error('method is required')
    }
    if (!/^\w+$/.test(method)) {
      throw new Error('invalid method')
    }
    if (!Buffer.isBuffer(verifier)) {
      throw new Error('verifier must be a buffer')
    }
    const resp = await this._http(false).post(basePath + '/authn/mfa/' + method + '/verify', {
      'state_token': stateToken,
      'verifier': verifier.toString('base64')
    })
    return resp.data
  }

  /**
   * Create a new user with primary authentication method.
   *
   * @param {string} redirectURI URL to redirect to after a successful authentication transaction.
   * @param {object} user The new user.
   * @param {string} user.email The user's email address.
   * @param {string} user.phone The user's phone number.
   * @param {string} user.name The user's full name.
   * @param {object} user.password_verifier The password verifier generated from user's password.
   * @returns {object} An authentication state.
   */
  async signUp (redirectURI, user) {
    if (!typeChecker(redirectURI, 'string', true)) {
      throw new Error('redirectURI is required')
    }
    if (!typeChecker(user, 'object')) {
      throw new Error('user must be an object')
    }
    if (user.email && !typeChecker(user.email, 'string')) {
      throw new Error('user.email must be a string')
    }
    if (user.phone && !typeChecker(user.phone, 'string')) {
      throw new Error('user.phone must be a string')
    }
    if (user.name && !typeChecker(user.name, 'string')) {
      throw new Error('user.name must be a string')
    }
    if (!typeChecker(user.password_verifier, 'object')) {
      throw new Error('user.password_verifier must be an object')
    }
    const resp = await this._http(false).post(basePath + '/signup', {
      'client_id': this.authcore.clientId,
      'redirect_uri': redirectURI,
      'email': user.email,
      'phone': user.phone,
      'name': user.name,
      'password_verifier': user.password_verifier
    })
    return resp.data
  }

  /**
   * Start a third-party IDP authentication transaction.
   *
   * @param {string} idp Name of the third-party IDP.
   * @param {string} redirectURI URL to redirect to after a successful authentication transaction.
   * @param {object} options The options specific for this request.
   * @param {string} options.codeChallenge A PKCE challenge.
   * @param {string} options.codeChallengeMethod A PKCE challenge method.
   * @param {string} options.clientState A state from OAuth client.
   * @returns {object} An authentication state.
   */
  async startIDP (idp, redirectURI, options = {}) {
    if (!typeChecker(idp, 'string', true)) {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
    }
    if (!typeChecker(redirectURI, 'string', true)) {
      throw new Error('redirectURI is required')
    }
    if (!typeChecker(options, 'object')) {
      throw new Error('options must be an object')
    }
    if (!typeChecker(options.codeChallengeMethod, 'string')) {
      throw new Error('codeChallengeMethod must be a string')
    }
    if (!typeChecker(options.codeChallenge, 'string')) {
      throw new Error('codeChallenge must be a string')
    }
    if (!typeChecker(options.clientState, 'string')) {
      throw new Error('clientState must be a string')
    }
    const resp = await this._http(false).post(basePath + '/authn/idp/' + encodeURIComponent(idp), {
      'client_id': this.authcore.clientId,
      'redirect_uri': redirectURI,
      'code_challenge_method': options.codeChallengeMethod,
      'code_challenge': options.codeChallenge,
      'client_state': options.clientState
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
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!typeChecker(code, 'string')) {
      throw new Error('code is required')
    }
    const resp = await this._http(false).post(basePath + '/authn/idp/-/verify', {
      'state_token': stateToken,
      'code': code
    })
    return resp.data
  }

  /**
   * Start a third-party IDP binding transaction.
   *
   * @param {string} idp Name of the third-party IDP.
   * @param {string} redirectURI URL to redirect to after a successful binding transaction.
   * @returns {object} An authentication state.
   */
  async startIDPBinding (idp, redirectURI) {
    if (!typeChecker(idp, 'string', true)) {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
    }
    if (!typeChecker(redirectURI, 'string', true)) {
      throw new Error('redirectURI is required')
    }
    const resp = await this._http(true).post(basePath + '/authn/idp_binding/' + encodeURIComponent(idp), {
      'redirect_uri': redirectURI
    })
    return resp.data
  }

  /**
   * Verify a third-party IDP authorization grant for IDP binding.
   *
   * @param {string} stateToken A state token.
   * @param {string} code A authorization code grant.
   * @returns {object} An authentication state.
   */
  async verifyIDPBinding (stateToken, code) {
    if (!typeChecker(stateToken, 'string')) {
      throw new Error('stateToken is required')
    }
    if (!typeChecker(code, 'string')) {
      throw new Error('code is required')
    }
    const resp = await this._http(true).post(basePath + '/authn/idp_binding/-/verify', {
      'state_token': stateToken,
      'code': code
    })
    return resp.data
  }

  /**
   * Start a session step-up transaction.
   *
   * @returns {object} An authentication state.
   */
  async startStepUp () {
    const resp = await this._http(true).post(basePath + '/authn/step_up', {})
    return resp.data
  }

  /**
   * Request a password key exchange challenge for a step-up transaction.
   *
   * @param {string} stateToken A state token.
   * @param {Buffer} message A password key exchange message.
   * @returns {Buffer} A password key exchange challenge message.
   */
  async requestPasswordStepUp (stateToken, message) {
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(message)) {
      throw new Error('message must be a buffer')
    }
    const resp = await this._http(true).post(basePath + '/authn/step_up/password', {
      'state_token': stateToken,
      'message': message.toString('base64')
    })
    const challenge = resp.data['challenge']
    return Buffer.from(challenge, 'base64')
  }

  /**
   * Verify password for a step-up transaction.
   *
   * @param {string} stateToken A state token.
   * @param {Buffer} response A password verification response.
   * @returns {object} An authentication state.
   */
  async verifyPasswordStepUp (stateToken, response) {
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    if (!Buffer.isBuffer(response)) {
      throw new Error('response must be a buffer')
    }
    const resp = await this._http(true).post(basePath + '/authn/step_up/password/verify', {
      'state_token': stateToken,
      'verifier': response.toString('base64')
    })
    return resp.data
  }

  /**
   * Get a authentication state by state token.
   *
   * @param {string} stateToken A state token.
   * @returns {object} An authentication state.
   */
  async getAuthnState (stateToken) {
    if (!typeChecker(stateToken, 'string', true)) {
      throw new Error('stateToken is required')
    }
    const resp = await this._http(true).post(basePath + '/authn/get_state', {
      'state_token': stateToken
    })
    return resp.data
  }

  // Returns a URL to Authcore's OAuth 2.0 sign in page.
  authCodeURL (state, redirectURI, options = {}) {
    if (!typeChecker(state, 'string', true)) {
      throw new Error('state is required')
    }
    if (!typeChecker(redirectURI, 'string', true)) {
      throw new Error('redirectURI is required')
    }
    if (!typeChecker(options, 'object')) {
      throw new Error('options must be an object')
    }
    const params = new URLSearchParams()
    params.append('client_id', this.authcore.clientId)
    params.append('response_type', 'code')
    params.append('redirect_uri', redirectURI)
    params.append('scope', options.scope || '')
    params.append('state', state)
    return new URL('/oauth/authorize?' + params.toString(), this.authcore.baseURL).toString()
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
    if (!typeChecker(type, 'string', true)) {
      throw new Error('type is required')
    }
    if (!typeChecker(token, 'string', true)) {
      throw new Error('token is required')
    }
    if (!typeChecker(options, 'object')) {
      throw new Error('options must be an object')
    }
    const tokenParam = type === 'refresh_token' ? 'refresh_token' : 'code'
    let req = {
      client_id: this.authcore.clientId,
      grant_type: type,
      [tokenParam]: token
    }
    Object.assign(req, options)
    const resp = await this._http(false).post('/oauth/token', req)
    return resp.data
  }

  /**
   * Get current user.
   *
   * @returns {object} Current user.
   */
  async getCurrentUser () {
    const resp = await this._http(true).get(basePath + '/users/current')
    return resp.data
  }

  /**
   * List current user's IDP bindings.
   *
   * @returns {object} List of user's IDP bindings.
   */
  async listCurrentUserIDP () {
    const resp = await this._http(true).get(`${basePath}/users/current/idp`)
    return resp.data
  }

  /**
   * Delete a current user's IDP bindings.
   *
   * @param {string} idp An IDP name.
   */
  async deleteCurrentUserIDP (idp) {
    if (!typeChecker(idp, 'string', true)) {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
    }
    await this._http(true).delete(`${basePath}/users/current/idp/${encodeURIComponent(idp)}`)
  }

  /**
   * List the event logs of a user from user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} limit The number of events returns in a page.
   * @returns {object} Result including the event logs list, page token for previous and next page and number of total items.
   */
  async listUserEvents (userId, pageToken, limit) {
    if (!typeChecker(userId, 'number')) {
      throw new Error('userId has to be number format')
    }
    if (!typeChecker(pageToken, 'string')) {
      throw new Error('pageToken has to be in string format')
    }
    const params = {
      user_id: userId,
      limit: limit,
      page_token: pageToken
    }
    const resp = await this._http(true).get(`${basePath}/audit_logs`, { params })
    return resp.data
  }

  /**
   * List all events logs.
   *
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} limit The number of events returns in a page.
   * @returns {object} Result including the event logs list, page token for previous and next page and number of total items.
   */
  async listEvents (pageToken, limit) {
    if (!typeChecker(pageToken, 'string')) {
      throw new Error('pageToken has to be in string format')
    }
    const params = {
      limit: limit,
      page_token: pageToken
    }
    const resp = await this._http(true).get(`${basePath}/audit_logs`, { params })
    return resp.data
  }

  /**
   * List the sessions of a user from user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} limit The number of events returns in a page.
   * @returns {object} Result including the sessions list, page token for previous and next page and number of total items.
   */
  async listUserSessions (userId, pageToken, limit) {
    if (!typeChecker(userId, 'number')) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(pageToken, 'string')) {
      throw new Error('pageToken has to be in string format')
    }
    const params = {
      limit: limit,
      page_token: pageToken
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/sessions`, { params })
    return resp.data
  }

  /**
   * Get a session by session ID.
   *
   * @param {number} sessionId The session's ID.
   * @returns {object} A session object.
   */
  async getSession (sessionId) {
    if (!typeChecker(sessionId, 'number')) {
      throw new Error('sessionId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/sessions/${sessionId}`)
    return resp.data
  }

  /**
   * Delete a session by session ID.
   *
   * @param {number} sessionId The session's ID.
   */
  async deleteSession (sessionId) {
    if (!typeChecker(sessionId, 'number')) {
      throw new Error('sessionId is required and has to be number format')
    }
    await this._http(true).delete(`${basePath}/sessions/${sessionId}`)
  }

  /**
   * List available languages for template.
   *
   * @returns {object} List of available languages.
   */
  async listTemplateLanguages () {
    const resp = await this._http(true).get(`${basePath}/templates`)
    return resp.data
  }

  /**
   * List templates with template type and language.
   *
   * @param {string} type Template type ('email'/'sms').
   * @param {string} language Language string.
   * @returns {object} List of template objects.
   */
  async listTemplates (type, language) {
    if (type !== 'email' && type !== 'sms') {
      throw new Error('type is not email or sms')
    }
    if (!typeChecker(language, 'string')) {
      throw new Error('language has to be in string format')
    }
    const resp = await this._http(true).get(`${basePath}/templates/${type}/${language}`)
    return resp.data
  }

  /**
   * Get a template specified by template type, language and name.
   *
   * @param {string} type Template type ('email'/'sms').
   * @param {string} language Language string.
   * @param {string} templateName Template name.
   * @returns {object} A template object.
   */
  async getTemplate (type, language, templateName) {
    if (type !== 'email' && type !== 'sms') {
      throw new Error('type is not email or sms')
    }
    if (!typeChecker(language, 'string')) {
      throw new Error('language has to be in string format')
    }
    if (!typeChecker(templateName, 'string')) {
      throw new Error('templateName has to be in string format')
    }
    const resp = await this._http(true).get(`${basePath}/templates/${type}/${language}/${templateName}`)
    return resp.data
  }

  /**
   * Update a template specified by template type, language and name.
   *
   * @param {string} type Template type ('email'/'sms').
   * @param {string} language Language string.
   * @param {string} templateName Template name.
   * @param {object} newTemplate A updated template object.
   */
  async updateTemplate (type, language, templateName, newTemplate) {
    if (type !== 'email' && type !== 'sms') {
      throw new Error('type is not email or sms')
    }
    if (!language || !typeChecker(language, 'string')) {
      throw new Error('language has to be in non-empty string format')
    }
    if (!templateName || !typeChecker(templateName, 'string')) {
      throw new Error('templateName has to be in non-empty string format')
    }
    if (type === 'email') {
      if (!typeChecker(newTemplate.subject, 'string', true)) {
        throw new Error('newTemplate.subject is required and must be a string')
      }
      if (!typeChecker(newTemplate.html, 'string', true)) {
        throw new Error('newTemplate.html is required and must be a string')
      }
    }
    if (!typeChecker(newTemplate.text, 'string', true)) {
      throw new Error('newTemplate.text is required and must be a string')
    }
    await this._http(true).post(`${basePath}/templates/${type}/${language}/${templateName}`, newTemplate)
  }

  /**
   * Reset a template by template type, language and name.
   *
   * @param {string} type Template type ('email'/'sms').
   * @param {string} language Language string.
   * @param {string} templateName Template name.
   * @returns {boolean} Status represents the action success or not.
   */
  async resetTemplate (type, language, templateName) {
    if (type !== 'email' && type !== 'sms') {
      throw new Error('type is not email or sms')
    }
    if (!language || !typeChecker(language, 'string')) {
      throw new Error('language has to be in string format')
    }
    if (!templateName || !typeChecker(templateName, 'string')) {
      throw new Error('templateName has to be in string format')
    }
    const resp = await this._http(true).delete(`${basePath}/templates/${type}/${language}/${templateName}`)
    return (resp.status === 200)
  }

  /**
   * List users.
   *
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} limit Number of users return in a page.
   * @param {string} sortBy Optional, sort string used to sort results.
   * @param {object} options Object for the following query parameters.
   * @param {string} options.search Optional, search string for email / phoneNumber / name / username.
   * @param {string} options.email Optional, email used to filter results.
   * @param {string} options.phoneNumber Optional, phone number used to filter results.
   * @param {string} options.name Optional, name used to filter results.
   * @param {string} options.preferredUsername Optional, preferred username used to filter results.
   * @returns {object} Result includes the users list, page token for previous and next page and number of total items.
   */
  async listUsers (pageToken, limit, sortBy = '', options = {}) {
    if (!typeChecker(pageToken, 'string')) {
      throw new Error('pageToken has to be in string format')
    }

    const params = {
      limit: limit,
      page_token: pageToken,
      sort_by: sortBy,
      search: options.search,
      email: options.email,
      phone_number: options.phoneNumber,
      name: options.name,
      preferred_username: options.preferredUsername
    }
    const resp = await this._http(true).get(`${basePath}/users`, { params })
    return resp.data
  }

  /**
   * Get a user by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} A user object.
   */
  async getUser (userId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}`)
    return resp.data
  }

  /**
   * Delete a user by user ID.
   *
   * @param {number} userId The user's ID.
   */
  async deleteUser (userId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    await this._http(true).delete(`${basePath}/users/${userId}`)
  }

  /**
   * Update a user specified by user ID and updated fields.
   *
   * @param {number} userId The user's ID.
   * @param {object} user An user object contains the following parameters.
   * @param {string} user.name Optional, new name of user.
   * @param {string} user.preferred_username Optional, new preferred username of user.
   * @param {string} user.email Optional, new email of user.
   * @param {string} user.phone_number Optional, new phone number of user.
   * @param {boolean} user.email_verified Optional, new email verified status of user.
   * @param {boolean} user.phone_number_verified Optional, new phone number verified status of user.
   * @param {object} user.app_metadata Optional, new application metadata of user.
   * @param {object} user.user_metadata Optional, new user metadata.
   * @param {boolean} user.is_locked Optional, new lock state of user.
   * @returns {object} The updated user object.
   */
  async updateUser (userId, user) {
    if (!typeChecker(userId, 'number')) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(user, 'object')) {
      throw new Error('user is required and has to be an object')
    }
    if (!typeChecker(user.name, 'string')) {
      throw new Error('user.name has to be a string')
    }
    if (!typeChecker(user.preferred_username, 'string')) {
      throw new Error('user.preferred_username has to be a string')
    }
    if (!typeChecker(user.email, 'string')) {
      throw new Error('user.email has to be a string')
    }
    if (!typeChecker(user.phone_number, 'string')) {
      throw new Error('user.phone_number has to be a string')
    }
    if (!typeChecker(user.email_verified, 'boolean')) {
      throw new Error('user.email_verified has to be a boolean')
    }
    if (!typeChecker(user.phone_number_verified, 'boolean')) {
      throw new Error('user.phone_number_verified has to be a boolean')
    }
    if (!typeChecker(user.app_metadata, 'object')) {
      throw new Error('user.app_metadata has to be an object')
    }
    if (!typeChecker(user.user_metadata, 'object')) {
      throw new Error('user.user_metadata has to be an object')
    }
    if (!typeChecker(user.is_locked, 'boolean')) {
      throw new Error('user.is_locked has to be a boolean')
    }
    const resp = await this._http(true).put(`${basePath}/users/${userId}`, user)
    return resp.data
  }

  /**
   * Update password of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} verifier The new password verifier of user.
   */
  async updateUserPassword (userId, verifier) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(verifier, 'object', true)) {
      throw new Error('verifier is required and has to be an object')
    }
    await this._http(true).post(`${basePath}/users/${userId}/password`, verifier)
  }

  /**
   * Get roles of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} List of user roles.
   */
  async getUserRoles (userId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/roles`)
    return resp.data
  }

  /**
   * Assign a role to a user specified by user ID and role ID.
   *
   * @param {number} userId The user's ID.
   * @param {number} roleId The role's ID.
   * @returns {object} List of user's new roles.
   */
  async assignUserRole (userId, roleId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(roleId, 'number', true)) {
      throw new Error('roleId is required and has to be number format')
    }
    const req = {
      role_id: roleId
    }
    const resp = await this._http(true).post(`${basePath}/users/${userId}/roles`, req)
    return resp.data
  }

  /**
   * Unassign a role for a user specified by user ID and role ID.
   *
   * @param {number} userId The user's ID.
   * @param {number} roleId The role's ID.
   */
  async unassignUserRole (userId, roleId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(roleId, 'number', true)) {
      throw new Error('roleId is required and has to be number format')
    }
    const req = {
      role_id: roleId
    }
    await this._http(true).delete(`${basePath}/users/${userId}/roles`, req)
  }

  /**
   * List IDP of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} List of user's IDP.
   */
  async listUserIDP (userId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/idp`)
    return resp.data
  }

  /**
   * Delete a IDP of an user specified by user ID and service.
   *
   * @param {number} userId The user's ID.
   * @param {string} service A IDP service name to be deleted.
   */
  async deleteUserIDP (userId, service) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    if (!typeChecker(service, 'string', true)) {
      throw new Error('service is required and has to be in string format')
    }
    await this._http(true).delete(`${basePath}/users/${userId}/idp/${service}`)
  }

  /**
   * List MFA of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} List of user's MFA.
   */
  async listUserMFA (userId) {
    if (!typeChecker(userId, 'number', true)) {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/mfa`)
    return resp.data
  }

  /**
   * List current user's MFA.
   *
   * @returns {object} List of user's MFA.
   */
  async listCurrentUserMFA () {
    const resp = await this._http(true).get(`${basePath}/users/current/mfa`)
    return resp.data
  }

  /**
   * Register a MFA factor for current user.
   *
   * @param {object} req A request to create MFA factor.
   * @param {string} req.type Type of the MFA factor.
   * @param {string} req.secret Secret of the MFA factor.
   * @param {string} req.verifier Verifier to confirm the MFA factor.
   * @returns {object} List of user's MFA.
   */
  async createCurrentUserMFA (req) {
    if (!typeChecker(req, 'object', true)) {
      throw new Error('req must be an object')
    }
    if (!typeChecker(req.type, 'string', true)) {
      throw new Error('req.type is required')
    }
    if (!typeChecker(req.secret, 'string', true)) {
      throw new Error('req.secret is required')
    }
    if (!typeChecker(req.verifier, 'string', true)) {
      throw new Error('req.verifier is required')
    }
    const resp = await this._http(true).post(`${basePath}/users/current/mfa`, req)
    return resp.data
  }

  /**
   * Delete a current user's MFA factor.
   *
   * @param {number} id The MFA factor's ID.
   */
  async deleteCurrentUserMFA (id) {
    if (!typeChecker(id, 'number', true)) {
      throw new Error('id is required and has to be number format')
    }
    await this._http(true).delete(`${basePath}/users/current/mfa/${id}`)
  }

  /**
   * Create a new user with identifier such as email or phone number.
   *
   * @param {object} data A object contains the following data.
   * @param {string} data.username Optional, Username of the user to be created.
   * @param {string} data.email Optional, Email of the user to be created.
   * @param {string} data.phone_number Optional, Phone number of the user to be created.
   * @param {object} data.verifier Optional, password verifier of the user to be created.
   * @returns {object} User object and the refresh token of the user.
   */
  async createUser (data) {
    if (!typeChecker(data, 'object', true)) {
      throw new Error('data is required and has to be an object')
    }
    if (!typeChecker(data.username, 'string')) {
      throw new Error('data.username has to be a string')
    }
    if (!typeChecker(data.email, 'string')) {
      throw new Error('data.email has to be a string')
    }
    if (!typeChecker(data.phone_number, 'string')) {
      throw new Error('data.phone_number has to be a string')
    }
    if (!typeChecker(data.verifier, 'object')) {
      throw new Error('data.verifier is required and has to be an object')
    }
    const resp = await this._http(true).post(`${basePath}/users`, data)
    return resp.data
  }

  /**
   * Get an IDP specified by IDP ID.
   *
   * @param {number} idpId The IDP's ID.
   * @returns {object} An IDP object.
   */
  async getIDP (idpId) {
    if (!typeChecker(idpId, 'number', true)) {
      throw new Error('idpId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/idp/${idpId}`)
    return resp.data
  }

  /**
   * List current user sessions.
   *
   * @returns {object} Current user's sessions.
   */
  async listCurrentUserSessions () {
    const resp = await this._http(true).get(basePath + '/users/current/sessions')
    return resp.data
  }

  /**
   * Delete current user session.
   *
   * @param {number} sessionId A session ID.
   */
  async deleteCurrentUserSession (sessionId) {
    if (!typeChecker(sessionId, 'number', true)) {
      throw new Error('sessionId is required and has to be number format')
    }
    await this._http(true).delete(basePath + '/users/current/sessions/' + sessionId)
  }

  /**
   * Update current user password.
   *
   * @param {object} passwordVerifier The password verifier generated from user's password.
   */
  async updateCurrentUserPassword (passwordVerifier) {
    if (!typeChecker(passwordVerifier, 'object')) {
      throw new Error('passwordVerifier must be an object')
    }
    await this._http(true).put(basePath + '/users/current/password', passwordVerifier)
  }

  /**
   * Get current session.
   *
   * @returns {object} Current session.
   */
  async getCurrentSession () {
    const resp = await this._http(true).get(basePath + '/sessions/current')
    return resp.data
  }

  /**
   * Delete current session.
   */
  async deleteCurrentSession () {
    await this._http(true).delete(basePath + '/sessions/current')
  }

  _http (authenticated) {
    const headers = {}
    if (authenticated) {
      const accessToken = this.authcore.tokenManager.get('access_token')
      // Let server reject the request if an access token is not available to unify the error handling.
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`
      }
    }
    const http = axios.create({ baseURL: this.authcore.baseURL.toString(), headers })
    http.interceptors.response.use(response => response, error => this.errorHandler(error))
    return http
  }
}

/**
 * Default error handler function.
 *
 * @param {object} e An error.
 * @returns {Promise} A promise.
 */
function defaultErrorHandler (e) {
  console.error('Authcore client: ', e)
  return Promise.reject(e)
}

export default Client
