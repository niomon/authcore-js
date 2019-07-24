const crypto = require('crypto')
const color = require('color')
const formatBuffer = require('./utils/formatBuffer')

/**
 * Clears the children of a DOM element.
 *
 * @private
 * @param {*} id The ID of the DOM element.
 */
function clearChildren (id) {
  const elm = document.getElementById(id)
  while (elm.firstChild) {
    elm.removeChild(elm.firstChild)
  }
}

/**
 * An class for Authcore widgets. Every Authcore widget would be an extension of this class.
 *
 * @param {object} options
 * @param {string} options.container The ID of the DOM element that injects the widget.
 * @param {string} options.company The company name used for the widget.
 * @param {string} options.logo The URL for the logo used for the widget.
 * @param {object} options.primary The primary colour for the widget.
 * @param {object} options.success The success colour for the widget.
 * @param {object} options.danger The danger colour for the widget.
 * @param {object} options.callbacks The set of callback functions to-be called.
 * @param {string} options.root The hostname for Authcore widgets.
 * @param {boolean} [options.display=true] Boolean flag indicating if the widget is visible.
 * @param {boolean} [options.internal=false] Boolean flag indicating if the widget is internally
 *        used. If set to internal, the logo and the footer will not appear.
 */
class AuthCoreWidget {
  constructor (options) {
    if (!options.root) {
      options.root = window.location.origin + '/widgets'
    }

    const { container, callbacks, root, display = true } = options

    this.root = root
    this.containerId = formatBuffer.toHex(crypto.randomBytes(8))

    const widget = document.createElement('iframe')
    widget.style.height = '0px'
    widget.style.width = '100%'
    widget.style.overflow = 'hidden'
    widget.style.border = '0'
    widget.scrolling = 'no'

    if (!display) {
      widget.id = this.containerId
      widget.style.width = '0px'
      widget.style.display = 'none'
      document.body.appendChild(widget)
    } else {
      // For Safari, Webkit creates scrollbar with `overflow: auto` and if the content
      // scroll size is larger than the padding box size.
      const containerElement = document.getElementById(container)
      // Provide `overflow: auto` to ensure scroll behaviour, parent in client side should
      // also be set if necessary(Mainly case for modal dialog)
      containerElement.style['overflow'] = 'auto'
      containerElement.appendChild(widget)
    }

    this.container = container

    this.widget = widget
    this.callbacks = callbacks || {}

    this.callbacks['_updateHeight'] = data => {
      this.widget.style.height = `${data.height}px`
    }
    this.callbacks['_onSuccess'] = (data) => {
    }
    // Callback to be called from widget component to notify the widget is loaded
    this.callbacks['_onLoaded'] = () => {
      // Sends the access token to the widget
      this.widget.contentWindow.postMessage({
        type: 'AuthCore_accessToken',
        data: options.accessToken
      }, options.root)
    }
    this.callbacks['_unauthenticated_widget'] = () => {
    }

    // We are writing arrow functions as we want a specific scope for `this`.
    // This handles the messages sent from the widget to the parent.
    window.addEventListener('message', e => {
      // Upon receiving a message of type 'AuthCore_*', callback functions will be called.
      // For example, if AuthCore_getCurrentUser is received, `getCurrentUser` and `_getCurrentUser` will be called.
      if (typeof e.data !== 'object') return
      const { type, data } = e.data
      if (typeof type !== 'string' || !(type.startsWith('AuthCore_'))) return
      if (typeof data !== 'object' || data.containerId !== this.containerId) return
      const cbName = type.substr(9)
      const privCbName = `_${cbName}`
      if (typeof this.callbacks[cbName] === 'function') {
        this.callbacks[cbName](data)
      }
      if (typeof this.callbacks[privCbName] === 'function') {
        this.callbacks[privCbName](data)
      }
    })
  }

  /**
   * Self-destructs the instance.
   **/
  destroy () {
    const { container } = this
    clearChildren(container)
    this.widget = undefined
    this.callbacks = {}
  }

  /**
   * Passes the access token into the widget.
   *
   * @param {string} accessToken The access token.
   **/
  updateAccessToken (accessToken) {
    this.widget.contentWindow.postMessage({
      type: 'AuthCore_accessToken',
      data: accessToken
    }, this.root)
  }

  /**
   * Build colour code in encodeURI format.
   *
   * @private
   * @param {string} colour The colour to be built.
   * @returns {string} The encodeURI colour code.
   **/
  buildColourCode (colour) {
    if (typeof colour === 'string') {
      try {
        return encodeURIComponent(`#${color(colour).hex().slice(1)}`)
      } catch (err) {
        throw new Error('colour parameters have to be correct format')
      }
    }
    return undefined
  }

  /**
   * Build widget src with extra parameters.
   *
   * @private
   * @param {object} options The options object.
   * @param {string} name The name of the widget.
   **/
  buildWidgetSrc (options, name) {
    let {
      logo,
      company,
      primary = undefined,
      success = undefined,
      danger = undefined,
      internal = false
    } = options

    if (logo === undefined) {
      logo = ''
    } else {
      logo = encodeURIComponent(logo)
    }
    if (company !== undefined) {
      company = encodeURIComponent(company)
    }
    if (typeof internal !== 'boolean') {
      throw new Error('internal must be boolean')
    }
    primary = this.buildColourCode(primary)
    success = this.buildColourCode(success)
    danger = this.buildColourCode(danger)
    this.widget.src = `${options.root}/${name}?logo=${logo}&company=${company}&cid=${this.containerId}&primary=${primary}&success=${success}&danger=${danger}&internal=${internal}`
  }
}


/**
 * The register widget.
 *
 * @augments AuthCoreWidget
 */
class Register extends AuthCoreWidget {
  constructor (options) {
    super(options)
    // Assume required verification in registration
    let {
      logo,
      company,
      primary = undefined,
      success = undefined,
      danger = undefined,
      privacyLink = undefined,
      privacyCheckbox = false,
      verification = true,
      internal = false
    } = options

    if (logo === undefined) {
      logo = ''
    } else {
      logo = encodeURIComponent(logo)
    }
    if (company !== undefined) {
      company = encodeURIComponent(company)
    }
    if (typeof internal !== 'boolean') {
      throw new Error('internal must be boolean')
    }
    if (privacyLink !== undefined) {
      privacyLink = encodeURIComponent(privacyLink)
    }
    if (typeof privacyCheckbox !== 'boolean') {
      throw new Error('privacyCheckbox must be boolean')
    }
    primary = this.buildColourCode(primary)
    success = this.buildColourCode(success)
    danger = this.buildColourCode(danger)

    if (typeof verification !== 'boolean') {
      throw new Error('verification must be boolean')
    }
    this.callbacks['_successRegister'] = (data) => {
      this.widget.src = `${options.root}/verification?logo=${logo}&company=${company}&cid=${this.containerId}&primary=${primary}&success=${success}&danger=${danger}&internal=${internal}&verification=${verification}`
    }
    this.widget.src = `${options.root}/register?logo=${logo}&company=${company}&cid=${this.containerId}&primary=${primary}&success=${success}&danger=${danger}&privacyLink=${privacyLink}&privacyCheckbox=${privacyCheckbox}&internal=${internal}`
  }
}

/**
 * The login widget.
 *
 * @augments AuthCoreWidget
 */
class Login extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'signin')
  }
}

/**
 * The verification widget.
 *
 * @augments AuthCoreWidget
 */
class Verification extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'verification')
  }
}

/**
 * The contacts widget.
 *
 * @augments AuthCoreWidget
 */
class Contacts extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'contacts')
  }
}

/**
 * The profile widget.
 *
 * @augments AuthCoreWidget
 */
class Profile extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'profile')
  }
}

/**
 * The security widget.
 *
 * @augments AuthCoreWidget
 */
class Security extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'security')
  }
}

/**
 * The sessions widget.
 *
 * @augments AuthCoreWidget
 */
class Sessions extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'sessions')
  }
}

/**
 * The ethereum sign approval widget.
 *
 * @augments AuthCoreWidget
 */
class EthereumSignApproval extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'ethereum-sign-approval')
    this.callbacks['_onEthereumSignApproved'] = () => {
      options.approve()
      this.destroy()
    }
    this.callbacks['_onEthereumSignRejected'] = () => {
      options.reject()
      this.destroy()
    }
  }
}

/**
 * The Cosmos sign approval widget.
 * 
 * @augments AuthCoreWidget
 */
class CosmosSignApproval extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.buildWidgetSrc(options, 'cosmos-sign-approval')
    this.callbacks['_onCosmosSignApproved'] = () => {
      options.approve()
      this.destroy()
    }
    this.callbacks['_onCosmosSignRejected'] = () => {
      options.reject()
      this.destroy()
    }
  }
}

/**
 * The refresh token widget that is used to refresh an access token.
 *
 * @augments AuthCoreWidget
 */
class RefreshToken extends AuthCoreWidget {
  constructor (options) {
    options.display = false
    super(options)
    let containerClass = 'refresh-token'
    this.widget.className = containerClass
    this.widget.src = `${options.root}/refresh-token?cid=${this.containerId}`
    this.callbacks['_unauthenticated_tokenUpdated'] = () => {
      // Remove all refresh token widgets
      const elms = document.getElementsByClassName(containerClass)
      while (elms.length > 0) {
        elms[0].remove()
      }
    }
    this.callbacks['_unauthenticated_tokenUpdatedFail'] = () => {
      const elms = document.getElementsByClassName(containerClass)
      while (elms.length > 0) {
        elms[0].remove()
      }
    }
  }
}

const AuthCoreWidgets = {
  Register,
  Login,
  Verification,
  Contacts,
  Profile,
  Security,
  Sessions,
  EthereumSignApproval,
  CosmosSignApproval,
  RefreshToken
}

exports.AuthCoreWidgets = AuthCoreWidgets
