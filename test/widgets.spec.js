/* global suite, test, localStorage, beforeEach, teardown */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const { assert } = chai
const { JSDOM } = require('jsdom')
const { AuthCoreWidgets } = require('../src/index.js')

const REFRESH_TOKEN_KEY = 'io.authcore.refreshToken'

suite('widgets.js', function () {
  suite('AuthCoreWidget', function () {
    beforeEach(function () {
      const { window } = new JSDOM(`
        <html>
          <body>
            <div id="authcore-register-widget"></div>
            <div id="authcore-sign-in-widget"></div>
            <div id="authcore-profile-widget"></div>
            <div id="authcore-contacts-widget"></div>
            <div id="authcore-settings-widget"></div>
          </body>
        </html>
      `)
      const { document } = window
      global.window = window
      global.document = document
    })
    teardown(function () {
      localStorage.clear()
    })

    test('should be able to mount an iframe with basic attributes', async function () {
      // Preparing
      new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      // Testing
      const iframes = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')
      assert.equal(iframes.length, 1)

      const iframe = iframes[0]
      assert.equal(iframe.style.width, '100%')
      assert.equal(iframe.style.overflow, 'hidden')

      const svg = document.getElementById('authcore-sign-in-widget').getElementsByTagName('svg')[0]
      assert.equal(svg.style.opacity, '0')
      assert.match(svg.style.transition, /opacity/)
      assert.match(svg.style.animation, /--widgets-spin/)
      assert.equal(svg.style['animation-delay'], '0.4s')
      assert.equal(svg.style['margin-top'], '1.5rem')

      const path = svg.getElementsByTagName('path')[0]
      assert.equal(path.getAttribute('fill'), 'none')
      assert.equal(path.getAttribute('stroke-linecap'), 'round')
      assert.equal(path.getAttribute('stroke-width'), 3)
    })

    test('should be able to update height when `AuthCore__updateHeight` message is posted', function (done) {
      // Preparing
      const widget = new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })
      const { containerId } = widget
      window.addEventListener('message', e => {
        const { type } = e.data
        if (type === 'AuthCore__updateHeight') {
          assert.equal(iframe.style.height, '256px')
          done()
        }
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      window.postMessage({
        type: 'AuthCore__updateHeight',
        data: {
          height: 256,
          containerId
        }
      }, '*')
    })

    test('should be able to perform registered callbacks', function (done) {
      // Preparing
      let callbackToken

      const widget = new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337',
        testCallback: ({ token }) => { callbackToken = token }
      })
      const { containerId } = widget
      window.addEventListener('message', e => {
        const { type } = e.data
        if (type === 'AuthCore_testCallback') {
          done()
        }
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      window.postMessage({
        type: 'AuthCore_testCallback',
        data: {
          token: 42,
          containerId
        }
      }, '*')
    })

    test('should not be able to postMessage if the event data is malformed', async function () {
      // Preparing
      new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      // 1. Data is not an object
      window.postMessage('Hello world!', '*')
      // 2. Callback is not from AuthCore
      window.postMessage({
        type: 'MetaMask_testCallback'
      }, '*')
      // 3. Callback is not defined
      window.postMessage({
        type: 'AuthCore_testCallback'
      }, '*')
    })

    test('should be able to delete the widget upon calling', async function () {
      // Preparing
      const widget = new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      assert.isAbove(document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe').length, 0)
      widget.destroy()
      assert.equal(document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe').length, 0)
    })

    test('should be able to set internal flag for widget', async function () {
      // Preparing
      const widget = new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337',
        internal: true
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
      assert.match(iframe.src, /internal=true/)
    })

    test('should be able to set language flag for widget', async function () {
      // Preparing
      const widget = new AuthCoreWidgets.Login({
        clientId: 'example-client',
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337',
        language: 'zh-hk'
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
      assert.match(iframe.src, /language=zh-hk/)
    })

    test('should be able to post access token to the widget using onLoaded callback', function (done) {
      // Preparing
      const widget = new AuthCoreWidgets.Profile({
        clientId: 'example-client',
        container: 'authcore-profile-widget',
        root: 'http://0.0.0.0:1337',
        accessToken: 'accessToken'
      })
      const { containerId } = widget

      window.addEventListener('message', e => {
        const { type, data } = e.data
        assert.equal(type, 'AuthCore__onLoaded')
      })

      // Check accessToken callback in widget, which is triggered by onLoaded message posted inside the widget.
      const iframe = document.getElementById('authcore-profile-widget').getElementsByTagName('iframe')[0]
      iframe.contentWindow.addEventListener('message', e => {
        const { type, data } = e.data
        if (type === 'AuthCore_accessToken') {
          // Testing
          assert.equal(data, 'accessToken')
          done()
        }
      })

      // Testing
      assert.equal(widget.accessToken, 'accessToken')

      window.postMessage({
        type: 'AuthCore__onLoaded',
        data: {
          containerId
        }
      }, '*')
    })

    test('should be able to post new access token to the widget', function (done) {
      // Preparing
      const widget = new AuthCoreWidgets.Profile({
        clientId: 'example-client',
        container: 'authcore-profile-widget',
        root: 'http://0.0.0.0:1337',
        accessToken: 'oldAccessToken'
      })

      // Check accessToken callback in widget, which is triggered by updateAccessToken function from widget instance.
      const iframe = document.getElementById('authcore-profile-widget').getElementsByTagName('iframe')[0]
      iframe.contentWindow.addEventListener('message', e => {
        const { type, data } = e.data
        if (type === 'AuthCore_accessToken') {
          // Testing
          assert.equal(data, 'newAccessToken')
          done()
        }
      })

      // Testing
      assert.equal(widget.accessToken, 'oldAccessToken')
      // Update to new access token
      widget.updateAccessToken('newAccessToken')
      assert.equal(widget.accessToken, 'newAccessToken')
    })

    suite('ensure \'/\' should still exists for the result', function () {
      test('no pathname no slash at the end', function () {
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin\//)
      })

      test('no pathname with slash at the end', function () {
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337/'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin\//)
      })

      test('with pathname no slash at the end', function () {
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337/widgets'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/widgets\/signin\//)
      })

      test('with pathname with slash at the end', function () {
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337/widgets/'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/widgets\/signin\//)
      })
    })

    suite('requireUsername parameter setting for widget', function () {
      test('should not require username by default', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /requireUsername=false/)
      })

      test('should all to require username', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337',
          requireUsername: true
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /requireUsername=true/)
      })
    })

    suite('Colour parameters setting for widget', function () {
      test('should be able to set primary colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          primaryColour: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primaryColour=%230088FF/)
      })
      test('should be able to set success colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          successColour: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /successColour=%230088FF/)
      })
      test('should be able to set danger colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          dangerColour: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /dangerColour=%230088FF/)
      })

      test('should be able to set primary colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          primaryColour: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primaryColour=%230000FF/)
      })
      test('should be able to set success colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          successColour: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /successColour=%230000FF/)
      })
      test('should be able to set danger colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          dangerColour: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /dangerColour=%230000FF/)
      })

      test('should not be able to set primary colour with wrong format', async function () {
        // Testing
        assert.throws(() => {new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          primaryColour: '0088ff',
          root: 'http://0.0.0.0:1337'
        })}, Error, 'colour parameters have to be correct format')
      })
      test('should not be able to set success colour with wrong format', async function () {
        // Testing
        assert.throws(() => {new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          successColour: '0088ff',
          root: 'http://0.0.0.0:1337'
        })}, Error, 'colour parameters have to be correct format')
      })
      test('should not be able to set danger colour with wrong format', async function () {
        // Testing
        assert.throws(() => {
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-sign-in-widget',
            dangerColour: '0088ff',
            root: 'http://0.0.0.0:1337'
          })
        }, Error, 'colour parameters have to be correct format')
      })
    })

    suite('Login widget', function () {
      test('should be able to have register widget with successRegister callback', function (done) {
        // Preparing
        const register = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          initialScreen: 'register',
          root: 'http://0.0.0.0:1337'
        })

        window.addEventListener('message', e => {
          const { type } = e.data
          if (type === 'AuthCore_successRegister') {
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)
        assert.typeOf(register.callbacks['_successRegister'], 'function')

        window.postMessage({
          type: 'AuthCore_successRegister',
          data: {}
        }, '*')
      })

      test('should be able to mount an iframe with verification attribute', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          initialScreen: 'register',
          root: 'http://0.0.0.0:1337',
          verification: false
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/register/)
        assert.match(iframe.src, /internal=false/)
      })

      test('should return error with non-boolean verification attribute', async function () {
        // Testing
        assert.throws(() => {
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-register-widget',
            root: 'http://0.0.0.0:1337',
            verification: 'test'
          })
        }, Error)
      })

      test('should be able to set primary colour for Register widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-register-widget',
          initialScreen: 'register',
          primaryColour: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primaryColour=%230088FF/)
      })

      test('should be able to pre-set contact', async function () {
        // Preparing
        const login = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          contact: 'test@example.com',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
        assert.match(iframe.src, /contact=test%40example.com/)
      })

      suite('Related socialLoginPaneStyle parameter', function () {
        test('should have default bottom socialLoginPaneStyle parameter', async function () {
          // Preparing
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-sign-in-widget',
            root: 'http://0.0.0.0:1337'
          })

          // Testing
          const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
          assert.exists(iframe)

          assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
          assert.match(iframe.src, /socialLoginPaneStyle=bottom/)
        })
        test('should be able to set socialLoginPaneStyle parameter to top', async function () {
          // Preparing
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-sign-in-widget',
            root: 'http://0.0.0.0:1337',
            socialLoginPaneStyle: 'top'
          })

          // Testing
          const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
          assert.exists(iframe)

          assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
          assert.match(iframe.src, /socialLoginPaneStyle=top/)
        })
        test('should be able to set socialLoginPaneStyle parameter to bottom', async function () {
          // Preparing
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-sign-in-widget',
            root: 'http://0.0.0.0:1337',
            socialLoginPaneStyle: 'bottom'
          })

          // Testing
          const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
          assert.exists(iframe)

          assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
          assert.match(iframe.src, /socialLoginPaneStyle=bottom/)
        })
        test('should throw error if socialLoginPaneStyle parameter is not top or bottom', async function () {
          assert.throws(() => {
            new AuthCoreWidgets.Login({
              clientId: 'example-client',
              container: 'authcore-sign-in-widget',
              socialLoginPaneStyle: 'notallow',
              root: 'http://0.0.0.0:1337'
            })
          }, Error, 'socialLoginPaneStyle only support top and bottom as input')
        })
      })

      test('default Login widget to have login as initial screen', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
      })

      test('allow to set signin as initial screen using initialScreen parameter', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          initialScreen: 'signin',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
      })

      test('allow to set register as initial screen using initialScreen parameter', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          initialScreen: 'register',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/register/)
      })

      test('not allow to set other parameter as initial screen', async function () {
        assert.throws(() => {
          new AuthCoreWidgets.Login({
            clientId: 'example-client',
            container: 'authcore-sign-in-widget',
            initialScreen: 'notallow',
            root: 'http://0.0.0.0:1337'
          })
        }, Error, 'initialScreen only support signin and register as input')
      })

      test('should be able to have login widget with successRegister callback', function (done) {
        // Preparing
        const login = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })
        window.addEventListener('message', e => {
          const { type } = e.data
          if (type === 'AuthCore_successRegister') {
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
        assert.typeOf(login.callbacks['_successRegister'], 'function')

        window.postMessage({
          type: 'AuthCore_successRegister',
          data: {}
        }, '*')
      })

      test('should be able to call customised callback when `AuthCore_onSuccess` is message is posted', function (done) {
        // Preparing
        let callbackToken

        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        const widget = new AuthCoreWidgets.Login({
          clientId: 'example-client',
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337',
          onSuccess: () => { callbackToken = 42 }
        })
        const { containerId } = widget
        window.addEventListener('message', e => {
          const { type, data } = e.data
          if (type === 'AuthCore_onSuccess') {
            assert.deepEqual(data['current_user'], {
              'id': '1',
              'username': 'samuel',
              'email': 'samuel@blocksq.com',
              'phone': '+85299965536',
              'display_name': 'Samuel',
              'updated_at': '2018-12-07T10:58:58Z',
              'created_at': '2018-12-07T10:58:57Z'
            })
            assert.equal(data['refresh_token'], refreshToken)
            assert.equal(callbackToken, 42) // Customized callback is performed
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        window.postMessage({
          type: 'AuthCore_onSuccess',
          data: {
            'current_user': {
              'id': '1',
              'username': 'samuel',
              'email': 'samuel@blocksq.com',
              'phone': '+85299965536',
              'display_name': 'Samuel',
              'updated_at': '2018-12-07T10:58:58Z',
              'created_at': '2018-12-07T10:58:57Z'
            },
            'refresh_token': refreshToken,
            containerId
          }
        }, '*')
      })
    })

    suite('Profile widget', function () {
      test('default value of showAvatar should be false', async function () {
        // Preparing
        new AuthCoreWidgets.Profile({
          clientId: 'example-client',
          container: 'authcore-profile-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-profile-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/profile/)
        assert.match(iframe.src, /showAvatar=false/)
      })

      test('should be able to set showAvatar parameter', async function () {
        // Preparing
        new AuthCoreWidgets.Profile({
          clientId: 'example-client',
          container: 'authcore-profile-widget',
          showAvatar: true,
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-profile-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/profile/)
        assert.match(iframe.src, /showAvatar=true/)
      })
    })

    suite('Contacts widget', function () {
      test('should be able to mount an iframe with additional attributes', async function () {
        // Preparing
        new AuthCoreWidgets.Contacts({
          clientId: 'example-client',
          container: 'authcore-contacts-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-contacts-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/contacts/)
      })
    })

    suite('Settings widget', function () {
      test('should be able to monut an iframe', async function () {
        // Preparing
        new AuthCoreWidgets.Settings({
          clientId: 'example-client',
          container: 'authcore-settings-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-settings-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/settings/)
      })
    })

    suite('RefreshToken widget', function () {
      test('should be able to mount an iframe', async function () {
        // Preparing
        new AuthCoreWidgets.RefreshToken({
          clientId: 'example-client',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementsByTagName('iframe')[0]
        assert.exists(iframe)
        assert.equal(iframe.style.display, 'none')
      })
    })
  })
})
