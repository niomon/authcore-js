import axios from 'axios'

import AuthnAPI from './authn/api'
import AuthnTransaction from './authn/transaction'
import Utils from './utils'

export class Authcore {
  constructor (config = {}) {
    if (typeof config.clientId !== 'string') {
      throw new Error('clientId is required')
    }
    if (typeof config.baseURL !== 'string') {
      throw new Error('clientId is required')
    }
    if (config.accessToken && typeof config.accessToken !== 'string') {
      throw new Error('accessToken must be a string')
    }

    this.clientId = config.clientId
    this.accessToken = config.accessToken
    this.baseURL = config.baseURL

    this.authn = new AuthnAPI(this)
    this.authnTransaction = new AuthnTransaction(this)
    this.utils = new Utils(this)
  }

  _http () {
    return axios.create({
      baseURL: this.baseURL
    })
  }
}
