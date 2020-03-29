/**
 * API client for Authcore OAuth API.
 */
class OAuth {
  constructor (authcore) {
    this.authcore = authcore
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
    const resp = await this.authcore._http.post('/oauth/token', req)
    return resp.data
  }
}

export default OAuth
