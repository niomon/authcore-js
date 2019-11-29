const pick = require('lodash/pick')

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
 * @param {object} options.primaryColour The primary colour for the widget.
 * @param {object} options.successColour The success colour for the widget.
 * @param {object} options.dangerColour The danger colour for the widget.
 * @param {string} options.root The hostname for Authcore widgets.
 * @param {boolean} [options.display=true] Boolean flag indicating if the widget is visible.
 * @param {boolean} [options.internal=false] Boolean flag indicating if the widget is internally
 *        used. If set to internal, the logo and the footer will not appear.
 * @param {boolean} [options.requireUsername=false] Boolean flag indicating whether username is included in registration and sign in.
 * @param {string} options.language Widget language when it is loaded, default to be English when it is not set or the value is invalid or unavailable.
 * @param {Function} options.onSuccess Callback function when the corresponding action has successfully completed.
 * @param {Function} options.onLoaded Callback function when the widget page is loaded.
 * @param {Function} options.unauthenticated Callback function when the widget returns unauthenticated status, most likely to occur due to expired access token.
 * @param {Function} options.successRegister Callback function when the corresponding action has successfully completed.
 * @param {Function} options.onCosmosSignApproved Callback function when the Cosmos signing is approved.
 * @param {Function} options.onCosmosSignRejected Callback function when the Cosmos Signing is rejected.
 * @param {Function} options.onTokenUpdated Callback function when the access token is updated successfully.
 * @param {Function} options.onTokenUpdatedFail Callback function when the access token cannot be updated.
 * @returns {AuthCoreWidget} The widget.
 */
class AuthCoreWidget {
  constructor (options) {
    // Provide keyframes animation in widgets
    let animationStyle = document.createElement('style')
    animationStyle.type = 'text/css'
    document.head.appendChild(animationStyle)
    animationStyle.sheet.insertRule(`@keyframes --widgets-spin { 100% { -webkit-transform: rotate(360deg); transform: rotate(360deg); } }`, animationStyle.length)

    if (!options.root) {
      options.root = new URL('widgets/', window.location.origin)
    } else {
      options.root = new URL(options.root)
    }
    // Make sure '/' exists at the end of the pathname
    options.root.pathname = options.root.pathname.replace(/\/?$/, '/')

    const {
      container,
      display = true,
      primaryColour = '#3051e3' // Primary colour to be referenced from blocksq/bootstrap-vue library
    } = options
    // Get default callback
    const allowedCallbacks = [
      'onSuccess',
      'onLoaded',
      'unauthenticated',
      'successRegister',
      'onCosmosSignApproved',
      'onCosmosSignRejected',
      'onTokenUpdated',
      'onTokenUpdatedFail'
    ]
    const callbacks = pick(options, allowedCallbacks)

    this.origin = options.root.origin.toString()
    this.containerId = formatBuffer.toHex(crypto.randomBytes(8))
    this.accessToken = options.accessToken

    // Set transition time in milliseconds
    const transitionTime = 400

    const widget = document.createElement('iframe')
    widget.style.height = '0px'
    widget.style.width = '100%'
    widget.style.overflow = 'hidden'
    widget.style.border = '0'
    widget.scrolling = 'no'
    // Set animation for hide and show behaviour
    widget.style['transition'] = `opacity ${transitionTime}ms ease`
    // Hide the widget at the beginning
    widget.style['opacity'] = 0

    // SVG information refers to Load.svg in authcore-widgets
    let path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttributeNS(null, 'd', 'M31.5,0A31.473,31.473,0,1,0,43.467,2.353')
    path.setAttributeNS(null, 'transform', 'translate(1.5 1.5)')
    path.setAttributeNS(null, 'fill', 'none')
    path.setAttributeNS(null, 'stroke', primaryColour)
    path.setAttributeNS(null, 'stroke-linecap', 'round')
    path.setAttributeNS(null, 'stroke-width', 3)

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttributeNS(null, 'width', 66)
    svg.setAttributeNS(null, 'height', 66)
    svg.style['animation'] = `--widgets-spin 1.5s cubic-bezier(0, 0.6, 0.36, 1) infinite`
    svg.style['animation-delay'] = '0.4s'
    svg.style['opacity'] = 0
    svg.style['transition'] = `opacity ${transitionTime}ms ease`
    svg.appendChild(path)

    if (!display) {
      widget.id = this.containerId
      widget.style.width = '0px'
      widget.style.display = 'none'
      document.body.appendChild(widget)
    } else {
      // For Safari, Webkit creates scrollbar with `overflow: auto` and if the content
      // scroll size is larger than the padding box size.
      const containerElement = document.getElementById(container)
      containerElement.style['text-align'] = 'center'
      // Append the loading spinner and with transition time to show
      containerElement.appendChild(svg)
      setTimeout(() => {
        svg.style['opacity'] = 1
      }, transitionTime)
      containerElement.appendChild(widget)
    }

    this.container = container

    this.widget = widget
    this.callbacks = callbacks

    this.callbacks['_updateHeight'] = data => {
      this.widget.style.height = `${data.height}px`
    }
    this.callbacks['_onSuccess'] = (data) => {
    }
    // Callback to be called from widget component to notify the widget is loaded
    this.callbacks['_onLoaded'] = () => {
      // Set to hide the loading spinner
      svg.style['opacity'] = 0
      setTimeout(() => {
        // Show the widget instance and remove loading spinner
        widget.style['opacity'] = 1
        svg.remove()
        // Provide `overflow: auto` to ensure scroll behaviour, parent in client side should
        // also be set if necessary(Mainly case for modal dialog)
        document.getElementById(container).style['overflow'] = 'auto'
      }, transitionTime)
      // Sends the access token to the widget
      this.widget.contentWindow.postMessage({
        type: 'AuthCore_accessToken',
        data: this.accessToken
      }, this.origin)
    }
    this.callbacks['_unauthenticated'] = () => {
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
    this.accessToken = accessToken
    this.widget.contentWindow.postMessage({
      type: 'AuthCore_accessToken',
      data: accessToken
    }, this.origin)
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
        return `#${color(colour).hex().slice(1)}`
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
   * @returns {string} The URL for the widget.
   **/
  buildWidgetSrc (options, name) {
    let {
      logo,
      company,
      primaryColour = undefined,
      successColour = undefined,
      dangerColour = undefined,
      internal = false,
      verification = true,
      requireUsername = false,
      language = undefined,
      // For Login widget only
      contact = undefined,
      fixedContact = undefined,
      privacyLink = undefined,
      privacyCheckbox = undefined,
      setRefreshToken = false,
      // For Profile widget only
      showAvatar = undefined
    } = options

    if (typeof internal !== 'boolean') {
      throw new Error('internal must be boolean')
    }
    if (typeof verification !== 'boolean') {
      throw new Error('verification must be boolean')
    }
    if (typeof requireUsername !== 'boolean') {
      throw new Error('requireUsername must be boolean')
    }
    switch (name) {
      case 'signin':
      case 'register':
        if (!contact && fixedContact) {
          throw new Error('fixedContact is set to be true and contact is empty. Register/sign process cannot perform as the handle value must be empty. Please fix the parameter setting.')
        }
        if (fixedContact === undefined) {
          fixedContact = false
        } else if (typeof fixedContact !== 'boolean') {
          throw new Error('fixedContact must be either undefined or a boolean')
        }
        if (typeof privacyLink !== 'undefined' && typeof privacyLink !== 'string') {
          throw new Error('privacyLink must be a string')
        }
        if (typeof privacyCheckbox !== 'undefined' && typeof privacyCheckbox !== 'boolean') {
          throw new Error('privacyCheckbox must be a boolean')
        }
        if (typeof setRefreshToken !== 'boolean') {
          throw new Error('setRefreshToken must be a boolean')
        }
        break
      case 'profile':
        if (showAvatar === undefined) {
          showAvatar = false
        } else if (typeof showAvatar !== 'boolean') {
          throw new Error('fixedContact must be boolean')
        }
    }
    primaryColour = this.buildColourCode(primaryColour)
    successColour = this.buildColourCode(successColour)
    dangerColour = this.buildColourCode(dangerColour)
    const paramsObj = {
      cid: this.containerId,
      logo: logo,
      company: company,
      primaryColour: primaryColour,
      successColour: successColour,
      dangerColour: dangerColour,
      internal: internal,
      verification: verification,
      requireUsername: requireUsername,
      language: language,
      contact: contact,
      fixedContact: fixedContact,
      privacyLink: privacyLink,
      privacyCheckbox: privacyCheckbox,
      setRefreshToken: setRefreshToken,
      showAvatar: showAvatar
    }
    const params = new URLSearchParams()
    // Remove key with `undefined` as value
    Object.keys(paramsObj).forEach((key) => {
      if (paramsObj[key] !== undefined) {
        params.append(key, paramsObj[key])
      }
    })
    const widgetSrc = new URL(options.root)
    widgetSrc.pathname = widgetSrc.pathname + `${name}/`
    widgetSrc.search = params.toString()
    return widgetSrc.toString()
  }
}

/**
 * The login widget.
 *
 * @param {string} [options.initialScreen] The screen that will be shown when the widget is opened. Only accept `signin` or `register` value.
 * @param {string} [options.contact] The contact value to be pre-filled into contact field in Registration page or handle field in Sign In page.
 * @param {boolean} [options.fixedContact] Boolean flag whether the contact or handle field is fixed which cannot be changed. If it is set to be `true`, contact has to have value.
 * @augments AuthCoreWidget
 */
class Login extends AuthCoreWidget {
  constructor (options) {
    super(options)
    const {
      initialScreen = 'signin'
    } = options
    const allowedInitialScreen = [
      'signin',
      'register'
    ]

    if (!allowedInitialScreen.includes(initialScreen)) {
      throw new Error('initialScreen only support signin and register as input')
    }
    this.widget.src = this.buildWidgetSrc(options, initialScreen)
    this.callbacks['_successRegister'] = (flags) => {
      if (flags.verification !== undefined) {
        options.verification = flags.verification
      }
      this.widget.src = this.buildWidgetSrc(options, 'verification')
    }
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
    this.widget.src = this.buildWidgetSrc(options, 'verification')
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
    this.widget.src = this.buildWidgetSrc(options, 'contacts')
  }
}

/**
 * The profile widget.
 *
 * @param {boolean} [options.showAvatar=false] Boolean flag indicating to show avatar in profile.
 *
 * @augments AuthCoreWidget
 */
class Profile extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.widget.src = this.buildWidgetSrc(options, 'profile')
  }
}

/**
 * The settings widget.
 *
 * @augments AuthCoreWidget
 */
class Settings extends AuthCoreWidget {
  constructor (options) {
    super(options)
    this.widget.src = this.buildWidgetSrc(options, 'settings')
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
    this.widget.src = this.buildWidgetSrc(options, 'ethereum-sign-approval')
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
    this.widget.src = this.buildWidgetSrc(options, 'cosmos-sign-approval')
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
    this.widget.src = this.buildWidgetSrc(options, 'refresh-token')
    this.callbacks['_onTokenUpdated'] = () => {
      // Remove all refresh token widgets
      const elms = document.getElementsByClassName(containerClass)
      while (elms.length > 0) {
        elms[0].remove()
      }
    }
    this.callbacks['_onTokenUpdatedFail'] = () => {
      const elms = document.getElementsByClassName(containerClass)
      while (elms.length > 0) {
        elms[0].remove()
      }
    }
  }
}

const AuthCoreWidgets = {
  Login,
  Verification,
  Contacts,
  Profile,
  Settings,
  EthereumSignApproval,
  CosmosSignApproval,
  RefreshToken
}

exports.AuthCoreWidgets = AuthCoreWidgets
