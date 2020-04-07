/**
 * API client for Authcore Settings API.
 */
class Settings {
  constructor (authcore) {
    this.authcore = authcore
  }

  // Returns a URL to Authcore's Settings 2.0 page
  settingsURL (options = {}) {
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    const params = new URLSearchParams()
    params.append('clientId', this.authcore.clientId)
    const paramsObj = {
      logo: options.logo,
      company: options.company,
      primaryColour: options.primaryColour,
      successColour: options.successColour,
      dangerColour: options.dangerColour,
      language: options.language
    }
    // Remove key with `undefined` as value
    Object.keys(paramsObj).forEach((key) => {
      if (paramsObj[key] !== undefined) {
        params.append(key, paramsObj[key])
      }
    })
    return new URL('/widgets/settings?' + params.toString(), this.authcore.baseURL).toString()
  }
}

export default Settings
