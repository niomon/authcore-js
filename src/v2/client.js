import axios from 'axios'
import spake2 from '../crypto/spake2.js'

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
    const resp = await this._http(false).post(basePath + '/authn', {
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
    if (typeof stateToken !== 'string') {
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
    if (typeof redirectURI !== 'string') {
      throw new Error('redirectURI is required')
    }
    if (typeof user !== 'object') {
      throw new Error('user must be an object')
    }
    if (user.email && typeof user.email !== 'string') {
      throw new Error('user.email must be a string')
    }
    if (user.phone && typeof user.phone !== 'string') {
      throw new Error('user.phone must be a string')
    }
    if (user.name && typeof user.name !== 'string') {
      throw new Error('user.name must be a string')
    }
    if (typeof user.password_verifier !== 'object') {
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
   * @returns {object} An authentication state.
   */
  async startIDP (idp, redirectURI, options = {}) {
    if (typeof idp !== 'string') {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
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
    const resp = await this._http(false).post(basePath + '/authn/idp/' + encodeURIComponent(idp), {
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
    if (typeof idp !== 'string') {
      throw new Error('idp is required')
    }
    if (!/^\w+$/.test(idp)) {
      throw new Error('invalid idp')
    }
    if (typeof idp !== 'string') {
      throw new Error('idp is required')
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
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    if (typeof code !== 'string') {
      throw new Error('code is required')
    }
    const resp = await this._http(true).post(basePath + '/authn/idp_binding/-/verify', {
      'state_token': stateToken,
      'code': code
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
    if (typeof stateToken !== 'string') {
      throw new Error('stateToken is required')
    }
    const resp = await this._http(true).post(basePath + '/authn/get_state', {
      'state_token': stateToken
    })
    return resp.data
  }

  // Returns a URL to Authcore's OAuth 2.0 sign in page.
  authCodeURL (state, redirectURI, options = {}) {
    if (typeof state !== 'string') {
      throw new Error('state is required')
    }
    if (typeof redirectURI !== 'string') {
      throw new Error('redirectURI is required')
    }
    if (typeof options !== 'object') {
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
    if (typeof type !== 'string') {
      throw new Error('type is required')
    }
    if (typeof token !== 'string') {
      throw new Error('token is required')
    }
    if (typeof options !== 'object') {
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
    if (typeof idp !== 'string') {
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
   * @param {number} rowsPerPage The number of events returns in a page.
   * @returns {object} Result including the event logs list, page token for previous and next page and number of total items.
   */
  async listUserEvents (userId, pageToken, rowsPerPage) {
    if (typeof userId !== 'number') {
      throw new Error('userId has to be number format')
    }
    if ((pageToken !== undefined && pageToken !== null) && typeof pageToken !== 'string') {
      throw new Error('pageToken has to be in string format')
    }
    const params = new URLSearchParams()
    params.append('user_id', userId)
    params.append('limit', rowsPerPage)
    params.append('page_token', pageToken)
    const url = new URL(basePath + '/audit_logs?' + params.toString(), this.authcore.baseURL)
    const resp = await this._http(true).get(url.toString())
    return resp.data
  }

  /**
   * List all events logs.
   *
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} rowsPerPage The number of events returns in a page.
   * @returns {object} Result including the event logs list, page token for previous and next page and number of total items.
   */
  async listEvents (pageToken, rowsPerPage) {
    if ((pageToken !== undefined && pageToken !== null) && typeof pageToken !== 'string') {
      throw new Error('pageToken has to be in string format')
    }
    const params = new URLSearchParams()
    params.append('limit', rowsPerPage)
    params.append('page_token', pageToken)
    const url = new URL(basePath + '/audit_logs?' + params.toString(), this.authcore.baseURL)
    const resp = await this._http(true).get(url.toString())
    return resp.data
  }

  /**
   * List the sessions of a user from user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {number} rowsPerPage The number of events returns in a page.
   * @returns {object} Result including the sessions list, page token for previous and next page and number of total items.
   */
  async listUserSessions (userId, pageToken, rowsPerPage) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if ((pageToken !== undefined && pageToken !== null) && typeof pageToken !== 'string') {
      throw new Error('pageToken has to be in string format')
    }
    const params = new URLSearchParams()
    params.append('limit', rowsPerPage)
    params.append('page_token', pageToken)
    const url = `${basePath}/users/${userId}/sessions?${params.toString()}`
    const resp = await this._http(true).get(url)
    return resp.data
  }

  /**
   * Get a session by session ID.
   *
   * @param {number} sessionId The session's ID.
   * @returns {object} A session object.
   */
  async getSession (sessionId) {
    if (typeof sessionId !== 'number') {
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
    if (typeof sessionId !== 'number') {
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
    if (typeof language !== 'string') {
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
    if (typeof language !== 'string') {
      throw new Error('language has to be in string format')
    }
    if (typeof templateName !== 'string') {
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
    if (typeof language !== 'string') {
      throw new Error('language has to be in string format')
    }
    if (typeof templateName !== 'string') {
      throw new Error('templateName has to be in string format')
    }
    if (type === 'email') {
      if (!newTemplate.subject || typeof newTemplate.subject !== 'string') {
        throw new Error('newTemplate.subject is required and must be a string')
      }
      if (!newTemplate.html || typeof newTemplate.html !== 'string') {
        throw new Error('newTemplate.html is required and must be a string')
      }
    }
    if (!newTemplate.text || typeof newTemplate.text !== 'string') {
      throw new Error('newTemplate.text is required and must be a string')
    }
    await this._http(true).put(`${basePath}/templates/${type}/${language}/${templateName}`, newTemplate)
  }

  /**
   * Reset a template by template type, language and name.
   *
   * @param {string} type Template type ('email'/'sms').
   * @param {string} language Language string.
   * @param {string} templateName Template name.
   * @returns {object} A template object.
   */
  async resetTemplate (type, language, templateName) {
    if (type !== 'email' && type !== 'sms') {
      throw new Error('type is not email or sms')
    }
    if (typeof language !== 'string') {
      throw new Error('language has to be in string format')
    }
    if (typeof templateName !== 'string') {
      throw new Error('templateName has to be in string format')
    }
    const resp = await this._http(true).delete(`${basePath}/templates/${type}/${language}/${templateName}`)
    return (resp.status === 200)
  }

  /**
   * List users.
   *
   * @param {number} rowsPerPage Number of users return in a page.
   * @param {string} pageToken The page token for the page result. If it is empty it returns the first page.
   * @param {boolean} ascending Boolean specify whether results is sorted ascending or not. If it is true result is sorted in ascending order.
   * @param {string} sortKey Optional, key used to sort results.
   * @param {object} options Object for the following query parameters.
   * @param {string} options.email Optional, email used to filter results.
   * @param {string} options.phoneNumber Optional, phone number used to filter results.
   * @param {string} options.name Optional, name used to filter results.
   * @param {string} options.preferredUsername Optional, preferred username used to filter results.
   * @returns {object} Result includes the users list, page token for previous and next page and number of total items.
   */
  async listUsers (rowsPerPage, pageToken, ascending, sortKey = '', options = {}) {
    let sortBy = ''
    if (sortKey) {
      const asc = ascending ? 'asc' : 'desc'
      sortBy = `${sortKey} ${asc}`
    }
    if ((pageToken !== undefined && pageToken !== null) && typeof pageToken !== 'string') {
      throw new Error('pageToken has to be in string format')
    }

    const params = new URLSearchParams()
    params.append('limit', rowsPerPage)
    params.append('page_token', pageToken)
    params.append('sort_by', sortBy)
    params.append('email', email)
    params.append('phone_number', phoneNumber)
    params.append('name', name)
    params.append('preferred_username', preferredUsername)
    const url = `${basePath}/users?${params.toString()}`
    const resp = await this._http(true).get(url)
    return resp.data
  }

  /**
   * Get a user by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} A user object.
   */
  async getUser (userId) {
    if (typeof userId !== 'number') {
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
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    await this._http(true).delete(`${basePath}/users/${userId}`)
  }

  /**
   * Update a user specified by user ID and updated fields.
   *
   * @param {number} userId The user's ID.
   * @param {object} options An object contains the following parameters.
   * @param {string} options.name Optional, new name of user.
   * @param {string} options.preferred_username Optional, new preferred username of user.
   * @param {string} options.email Optional, new email of user.
   * @param {string} options.phone_number Optional, new phone number of user.
   * @param {boolean} options.email_verified Optional, new email verified status of user.
   * @param {boolean} options.phone_number_verified Optional, new phone number verified status of user.
   * @returns {object} The updated user object.
   */
  async updateUser (userId, options) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if (typeof options !== 'object') {
      throw new Error('options is required and has to be an object')
    }
    if (options.name !== undefined && typeof options.name !== 'string') {
      throw new Error('options.name has to be a string')
    }
    if (options.preferred_username !== undefined && typeof options.preferred_username !== 'string') {
      throw new Error('options.preferred_username has to be a string')
    }
    if (options.email !== undefined && typeof options.email !== 'string') {
      throw new Error('options.email has to be a string')
    }
    if (options.phone_number !== undefined && typeof options.phone_number !== 'string') {
      throw new Error('options.phoneNumber has to be a string')
    }
    if (options.email_verified !== undefined && typeof options.email_verified !== 'boolean') {
      throw new Error('options.emailVerified has to be a boolean')
    }
    if (options.phone_number_verified !== undefined && typeof options.phone_number_verified !== 'boolean') {
      throw new Error('options.phoneNumberVerified has to be a boolean')
    }
    const resp = await this._http(true).put(`${basePath}/users/${userId}`, options)
    return resp.data
  }

  /**
   * Update password of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @param {string} password The new password of user.
   */
  async updateUserPassword (userId, password) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if (typeof password !== 'string') {
      throw new Error('password is required and has to be in string format')
    }
    const state = await spake2.createVerifier(password)
    const req = {
      salt: state.salt,
      l: state.verifier.l,
      w0: state.verifier.w0
    }
    await this._http(true).post(`${basePath}/users/${userId}/password`, req)
  }

  /**
   * Get roles of a user specified by user ID.
   *
   * @param {number} userId The user's ID.
   * @returns {object} List of user roles.
   */
  async getUserRoles (userId) {
    if (typeof userId !== 'number') {
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
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if (typeof roleId !== 'number') {
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
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if (typeof roleId !== 'number') {
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
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/idp`)
    return resp.data
  }

  /**
   * Delete a IDP of an user specified by user ID and service.
   *
   * @param {number} userId The user's ID.
   * @param {strint} service A IDP service name to be deleted.
   */
  async deleteUserIDP (userId, service) {
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    if (typeof service !== 'string') {
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
    if (typeof userId !== 'number') {
      throw new Error('userId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/users/${userId}/mfa`)
    return resp.data
  }

  /**
   * Create a new user with identifier such as email or phone number.
   *
   * @param {object} data A object contains the following data.
   * @param {string} data.username Optional, Username of the user to be created.
   * @param {string} data.email Optional, Email of the user to be created.
   * @param {string} data.phone_number Optional, Phone number of the user to be created.
   * @returns {object} User object and the refresh token of the user.
   */
  async createUser (data) {
    if (typeof data !== 'object') {
      throw new Error('data is required and has to be an object')
    }
    if (data.username !== undefined || typeof data.username !== 'string') {
      throw new Error('data.username has to be a string')
    }
    if (data.email !== undefined || typeof data.email !== 'string') {
      throw new Error('data.email has to be a string')
    }
    if (data.phone_number !== undefined || typeof data.phone_number !== 'string') {
      throw new Error('data.phone_number has to be a string')
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
    if (typeof idpId !== 'number') {
      throw new Error('idpId is required and has to be number format')
    }
    const resp = await this._http(true).get(`${basePath}/idp/${idpId}`)
    return resp.data
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
