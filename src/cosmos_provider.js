import hdKey from 'hdkey'
import bech32 from 'bech32'
import stringify from 'fast-json-stable-stringify'
import pick from 'lodash/pick'
import cloneDeep from 'lodash/cloneDeep'

import { AuthCoreKeyVaultClient } from './keyvault/index'
import { AuthCoreWidgets } from './widgets'
import { fromHex, toHex, toBase64 } from './utils/formatBuffer'

/**
 * The Cosmos wallet provider.
 *
 * @public
 * @param {object} config
 * @param {AuthCoreKeyVaultClient} config.authcoreClient The KeyVaultClient instance for the API
 *        calls.
 * @param {string} config.authcoreWidgetsUrl The base URL for the Authcore widgets.
 * @param {string} [config.pathPrefix=m/44'/118'/0'/0] The prefix of the derivation path.
 * @param {number} [config.accountCount=1] The number of accounts.
 * @param {string} config.chainId The chain ID of the Cosmos network.
 * @param {string} config.container The ID of the DOM element that injects the widget.
 * @returns {AuthCoreCosmosProvider} The Cosmos wallet provider integrated with AuthCore.
 */
class AuthCoreCosmosProvider {
  constructor (config) {
    this.authcoreClient = config.authcoreClient
    this.authcoreWidgetsUrl = config.authcoreWidgetsUrl
    this.pathPrefix = config.pathPrefix || `m/44'/118'/0'/0`
    this.accountCount = config.accountCount || 1
    this.chainId = config.chainId
    this.container = config.container

    this.wallets = []
  }

  /**
   * Lists the wallets.
   *
   * @private
   * @returns {Promise<string[]>} The list of wallets.
   */
  async _getWallets () {
    if (this.wallets.length > 0) return this.wallets

    const { pathPrefix, authcoreClient, accountCount } = this
    const publicKeys = await authcoreClient.listHDChildPublicKeys(pathPrefix)
    let wallets = []
    for (let keyId = 0; keyId < publicKeys.length; keyId++) {
      const publicKey = publicKeys[keyId]
      const hdkey = hdKey.fromExtendedKey(publicKey['extended_public_key'])

      for (let childId = 0; childId < accountCount; childId++) {
        const childKey = hdkey.derive(`m/${childId}`)
        wallets.push({
          objectId: publicKey['id'],
          childId,
          publicKey: toHex(childKey.publicKey),
          address: bech32.encode('cosmos', bech32.toWords(childKey.identifier))
        })
      }
    }
    this.wallets = wallets
    return wallets
  }

  /**
   * Lists the owned addresses.
   *
   * @returns {Promise<string[]>} The list of owned accounts.
   */
  async getAddresses () {
    const wallets = await this._getWallets()
    const addresses = wallets.map(wallet => wallet.address)
    return addresses
  }

  /**
   * Lists the owned public keys.
   *
   * @returns {Promise<string[]>} The list of owned public keys.
   */
  async getPublicKeys () {
    const wallets = await this._getWallets()
    const publicKeys = wallets.map(wallet => wallet.publicKey)
    return publicKeys
  }

  /**
   * Creates an Authcore widget for the user to approve signing an Cosmos payload.
   *
   * @param {object} data The payload to be broadcasted, with signature missing.
   * @param {object[]} data.msgs The message object.
   * @param {object} data.fee The fee object.
   * @param {string} data.memo The memo.
   * @param {string} data.chain_id The chain id for the Cosmos network.
   * @param {string} data.account_number The account number.
   * @param {string} data.sequence The nonce for the wallet.
   * @param {object[]} data.signatures The signatures.
   * @param {string} address The address of that wallet that is used to sign the message. Must be one of the owned addresses.
   * @returns {Promise<object>} The signed payload that is ready to be broadcasted.
   */
  async approve (data, address) {
    const { authcoreClient, authcoreWidgetsUrl, container } = this
    const that = this

    const dataWithSign = await new Promise((resolve, reject) => {
      new AuthCoreWidgets.CosmosSignApproval({ // eslint-disable-line no-new
        container,
        root: authcoreWidgetsUrl,
        accessToken: authcoreClient.getAccessToken(),
        approve: () => resolve(that.sign(data, address)),
        reject: () => reject(new Error('user has rejected the signing request'))
      })
    })
    return dataWithSign
  }

  /**
   * Signs a payload.
   *
   * @param {object} data The payload to be broadcasted, with signature missing.
   * @param {object[]} data.msgs The message object.
   * @param {object} data.fee The fee object.
   * @param {string} data.memo The memo.
   * @param {string} data.chain_id The chain id for the Cosmos network.
   * @param {string} data.account_number The account number.
   * @param {string} data.sequence The nonce for the wallet.
   * @param {object[]} data.signatures The signatures.
   * @param {string} address The address of that wallet that is used to sign the message. Must be one of the owned addresses.
   * @returns {Promise<object>} The signed payload that is ready to be broadcasted.
   */
  async sign (data, address) {
    const { authcoreClient, pathPrefix } = this
    const wallets = await this._getWallets()

    const wallet = wallets.find(wallet => wallet.address === address)
    if (!wallet) throw new Error('account not found')

    const { objectId, childId } = wallet
    const path = `${pathPrefix}/${childId}`
    const dataToSign = stringify(
      pick(data, [ 'fee', 'msgs', 'chain_id', 'account_number', 'sequence', 'memo' ])
    )
    const sign = await authcoreClient.cosmosSign(objectId, path, dataToSign)

    let dataWithSign = cloneDeep(data)
    dataWithSign['signatures'] = dataWithSign['signatures'] || []

    const signature = {
      'pub_key': {
        'type': 'tendermint/PubKeySecp256k1',
        'value': toBase64(fromHex(wallet.publicKey))
      },
      'signature': toBase64(fromHex(sign))
    }
    dataWithSign['signatures'].push(signature)
    return dataWithSign
  }
}

export { AuthCoreCosmosProvider }
