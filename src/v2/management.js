import axios from 'axios'

import User from './management/user'

export class AuthcoreManagement {
  constructor (config = {}) {
    if (typeof config.baseURL !== 'string') {
      throw new Error('baseURL is required')
    }
    if (config.accessToken && typeof config.accessToken !== 'string') {
      throw new Error('accessToken must be a string')
    }

    this.accessToken = config.accessToken
    this.baseURL = new URL(config.baseURL)

    this._http = axios.create({ baseURL: config.baseURL })
    this._http.defaults.headers.common['Authorization'] = `Bearer ${this.accessToken}`

    this.user = new User(this)
  }
}
