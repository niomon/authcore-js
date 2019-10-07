const { SecretdGatewayClient } = require('../secretd/gateway.js')
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
 * const kvClient = await new AuthCoreKeyVaultClient({
 *   apiBaseURL: 'https://auth.example.com',
 *   callbacks: {
 *     unauthenticated: function () {
 *       alert('unauthenticated!')
 *     }
 *   },
 *   accessToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJle...',
 *   userPrefix: '12345/',
 * })
 */
class AuthCoreKeyVaultClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => { // eslint-disable-line no-async-promise-executor
      this.config = config

      this.setAccessToken(config.accessToken)

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
    this.gateway = new SecretdGatewayClient({
      apiBaseURL: this.config.apiBaseURL,
      accessToken: this.config.accessToken
    })
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
    var args = [`${this.config.userPrefix}/keyvault/hdwallet`, 24]
    var resp = await this.gateway.sendRequest('hdwallet_generate', args)
    return {
      object_id: resp
    }
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
    var args = [`${this.config.userPrefix}/keyvault/hdwallet`, pathPrefix]
    var resp = await this.gateway.sendRequest('hdwallet_get_extended_public_key', args)
    if (!Array.isArray(resp) || resp.length < 1) {
      throw new Error('invalid resposne')
    }
    return [resp[0]]
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
}

exports.AuthCoreKeyVaultClient = AuthCoreKeyVaultClient
