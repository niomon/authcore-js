import Authn from './authn'
import Client from './client'
import TokenManager from './tokenManager'
import * as utils from './utils'

export class Authcore {
  constructor (options = {}) {
    if (typeof options.clientId !== 'string') {
      throw new Error('clientId is required')
    }
    if (typeof options.baseURL !== 'string') {
      throw new Error('baseURL is required')
    }
    if (options.accessToken && typeof options.accessToken !== 'string') {
      throw new Error('accessToken must be a string')
    }

    this.clientId = options.clientId
    this.baseURL = new URL(options.baseURL)

    this.authn = new Authn(this)
    this.client = new Client(this, options.client || {})
    this.tokenManager = new TokenManager(this.clientId, options.tokenManager || {})
    this.utils = utils
    if (options.accessToken) {
      this.tokenManager.add('access_token', options.accessToken)
    }
  }
}
