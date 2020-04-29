class TokenManager {
  /**
   * Create a TokenManager.
   *
   * @param {string} clientId Client ID.
   * @param {object} options Token manager options.
   * @param {string} options.storage Name of the token store. Default is 'localStorage'.
   */
  constructor (clientId, options = {}) {
    if (typeof clientId !== 'string') {
      throw new Error('clientId is required')
    }
    if (typeof options !== 'object') {
      throw new Error('options must be an object')
    }
    if (!options.storage) {
      options.storage = 'localStorage'
    }
    if (typeof options.storage !== 'string') {
      throw new Error('options.storage must be a string')
    }
    this.storage = resolveStorage(options.storage)
    this.keyPrefix = `authcore.tokenManager.${this.clientId}.`
  }

  /**
   * Add a token to the token manager.
   *
   * @param {string} key A unique key to identify The token.
   * @param {object} token The token.
   */
  add (key, token) {
    if (typeof token === 'object') {
      token = JSON.stringify(token)
    }
    this.storage.setItem(this.keyPrefix + key, token)
  }

  /**
   * Get a token from the token manager.
   *
   * @param {string} key A unique key to identify the token.
   * @param {boolean} json Whether the value is a JSON string.
   * @returns {string|object} A token string, or a token object if json is set to true.
   */
  get (key, json = false) {
    let value = this.storage.getItem(this.keyPrefix + key)
    if (json) {
      value = JSON.parse(value)
    }
    return value
  }

  /**
   * Remove a token from the token manager.
   *
   * @param {string} key A unique key to identify the token.
   */
  remove (key) {
    this.storage.removeItem(this.keyPrefix + key)
  }

  /**
   * Clear all tokens under this client ID.
   */
  clear () {
    Object.keys(this.storage).forEach(key => {
      console.log(key)
      if (key.startsWith(this.keyPrefix)) {
        this.storage.removeItem(key)
      }
    })
  }
}

const STORAGE_TEST_KEY = 'authcore.__storage_test__'

/**
 * Resolves storage instance. If the specified storage is not available, this method will fallback
 * to another storage mechanism.
 *
 * @param {string} storage Name of the storage method.
 * @returns {object} A storage instance.
 */
function resolveStorage (storage) {
  storage = storage.toLowerCase()
  if (storage === 'localstorage') {
    if (isSupported('localStorage')) {
      return window.localStorage
    } else if (isSupported('sessionStorage')) {
      return window.sessionStorage
    }
  } else if (storage === 'sessionstorage') {
    if (isSupported('sessionStorage')) {
      return window.sessionStorage
    }
  }
  throw new Error(`storage ${storage} is not available`)
}

/**
 * Tests whether the given storage method is supported.
 *
 * @param {string} name Name of the storage method.
 * @returns {boolean} Whether the storage method is supported.
 */
function isSupported (name) {
  try {
    const storage = window[name]
    storage.setItem(STORAGE_TEST_KEY, 'ok')
    storage.removeItem(STORAGE_TEST_KEY)
    return true
  } catch (e) {
    return false
  }
}

export default TokenManager
