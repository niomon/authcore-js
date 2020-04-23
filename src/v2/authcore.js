import axios from 'axios'

import AuthnAPI from './authn/api'
import AuthnTransaction from './authn/transaction'
import Utils from './utils'
import OAuth from './oauth'

export class Authcore {
  constructor (config = {}) {
    if (typeof config.clientId !== 'string') {
      throw new Error('clientId is required')
    }
    if (typeof config.baseURL !== 'string') {
      throw new Error('baseURL is required')
    }
    if (config.accessToken && typeof config.accessToken !== 'string') {
      throw new Error('accessToken must be a string')
    }

    this.clientId = config.clientId
    this.accessToken = config.accessToken
    this.baseURL = new URL(config.baseURL)

    this._http = axios.create({ baseURL: config.baseURL })

    this.authn = new AuthnAPI(this)
    this.authnTransaction = new AuthnTransaction(this)
    this.oauth = new OAuth(this)
    this.utils = new Utils(this)
  }
}
