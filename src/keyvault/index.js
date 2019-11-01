// swagger wrapper
const Swagger = require('swagger-client')

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * The class interacting between web client and AuthCore KeyVaultAPI server.
 *
 * @public
 * @param {object} config
 * @param {string} config.apiBaseURL The base URL for the Authcore instance.
 * @param {object} config.callbacks The set of callback functions to-be called.
 * @param {Function} config.callbacks.unauthenticated The callback function when a user is
 *        unauthenticated.
 * @param {string} config.accessToken The access token of the user.
 * @returns {Promise<AuthCoreKeyVaultClient>} The key vault client.
 * @example
 * const mgmtClient = await new AuthCoreKeyVaultClient({
 *   apiBaseURL: 'https://auth.example.com',
 *   callbacks: {
 *     unauthenticated: function () {
 *       alert('unauthenticated!')
 *     }
 *   },
 *   accessToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJle...'
 * })
 */
class AuthCoreKeyVaultClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => { // eslint-disable-line no-async-promise-executor
      this.config = config

      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      resolve(this)
    })
  }

  /**
   * Sets the access token and refreshes the Swagger client.
   *
   * @public
   * @param {string} accessToken The access token of the user.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async setAccessToken (accessToken) {
    this.config.accessToken = accessToken
    await this._getSwaggerClient()
  }

  /**
   * Gets the access token.
   *
   * @public
   * @returns {string} The access token of the user.
   */
  getAccessToken () {
    return this.config.accessToken
  }

  /**
   * Creates a secret.
   *
   * @param {string} type The type of the secret.
   * @param {number} size The size (in bytes) of the secret.
   * @returns {Promise<object>} The secret object. Contains only the secret id.
   */
  async createSecret (type, size) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'create_secret': {
          'type': type,
          'size': size
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody
  }

  /**
   * Lists the hierarchical determistic (HD) child public keys of the current user, defined by
   * [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
   * [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and
   * [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).
   *
   * @param {string} pathPrefix The prefix of the derivation path.
   * @returns {Promise<string[]>} The HD child public keys.
   */
  async listHDChildPublicKeys (pathPrefix) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'list_hd_child_public_keys': {
          'path': `${pathPrefix}`
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody['hd_child_public_keys'] || []
  }

  /**
   * Signs an Ethereum payload (transaction / message).
   *
   * @param {string} objectId The object ID.
   * @param {string} walletPath The path of the wallet.
   * @param {Buffer} data The payload to be signed.
   * @param {string} type The type of the payload (`transaction` / `message` / `personal_message` /
   *        `typed_message`).
   * @returns {Promise<string>} The signature of the given payload.
   */
  async ethereumSign (objectId, walletPath, data, type) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'ethereum_sign': {
          'type': type,
          'object_id': objectId,
          'wallet_path': walletPath,
          'data': formatBuffer.toHex(data)
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody['signature']
  }

  /**
   * Signs an Cosmos payload.
   *
   * @param {string} objectId The object ID.
   * @param {string} walletPath The path of the wallet.
   * @param {string} data The payload to be signed.
   * @returns {Promise<string>} The signature of the given payload.
   */
  async cosmosSign (objectId, walletPath, data) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'cosmos_sign': {
          'object_id': objectId,
          'wallet_path': walletPath,
          'data': formatBuffer.toHex(formatBuffer.fromString(data))
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody['signature']
  }

  /**
   * Constructs key vault client including interceptor for unauthorized and unauthenticated cases
   * to run callbacks from client implementation.
   *
   * @private
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async _getSwaggerClient () {
    let authorizations
    if (this.config.accessToken) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${this.config.accessToken}`
        }
      }
    }

    if (this.config !== undefined) {
      await new Promise((resolve, reject) => {
        const swaggerJsonURL = `${this.config.apiBaseURL}/api/keyvaultapi/keyvault.swagger.json`
        Swagger({
          url: swaggerJsonURL,
          authorizations,
          requestInterceptor: (req) => {
            // Hijack the scheme to match the origin request
            const schemePos = req.url.indexOf(':')
            const urlWithoutScheme = req.url.slice(schemePos)
            req.url = this.config.apiBaseURL.split(':')[0] + urlWithoutScheme
            return req
          },
          responseInterceptor: (res) => {
            if (res.status === 401) {
              // For status 401 from api server(Unauthorized in HTTP status), it means unauthenticated in our case
              if (typeof this.config.callbacks.unauthenticated === 'function') {
                this.config.callbacks.unauthenticated()
              }
            }
            if (res.status === 403) {
              // For status 403 from api server(Forbidden in HTTP status), it means unauthorized in our case
              if (typeof this.config.callbacks.unauthorized === 'function') {
                this.config.callbacks.unauthorized()
              }
            }
            return res
          }
        })
          .then(client => {
            this.KeyVaultService = client.apis.KeyVaultService
            resolve(client.apis)
          })
          .catch(err => {
            return reject(err)
          })
      })
    }
  }
}

exports.AuthCoreKeyVaultClient = AuthCoreKeyVaultClient
