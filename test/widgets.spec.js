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
            <div id="authcore-contacts-widget"></div>
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
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      // Testing
      const container = document.getElementById('authcore-sign-in-widget')
      assert.equal(container.style.overflow, 'auto')

      const iframes = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')
      assert.equal(iframes.length, 1)

      const iframe = iframes[0]
      assert.equal(iframe.style.width, '100%')
      assert.equal(iframe.style.overflow, 'hidden')
    })

    test('should be able to update height when `AuthCore__updateHeight` message is posted', function (done) {
      // Preparing
      const widget = new AuthCoreWidgets.Login({
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
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337',
        callbacks: {
          testCallback: ({ token }) => { callbackToken = token }
        }
      })
      const { containerId } = widget
      window.addEventListener('message', e => {
        const { type } = e.data
        if (type === 'AuthCore_testCallback') {
          assert.equal(callbackToken, 42)
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

    suite('Colour parameters setting for widget', function () {
      test('should be able to set primary colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          primary: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primary=%230088FF/)
      })
      test('should be able to set success colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          success: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /success=%230088FF/)
      })
      test('should be able to set danger colour for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          danger: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /danger=%230088FF/)
      })

      test('should be able to set primary colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          primary: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primary=%230000FF/)
      })
      test('should be able to set success colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          success: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /success=%230000FF/)
      })
      test('should be able to set danger colour using colour word for widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          danger: 'blue',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /danger=%230000FF/)
      })

      test('should not be able to set primary colour with wrong format', async function () {
        // Testing
        assert.throws(() => {new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          primary: '0088ff',
          root: 'http://0.0.0.0:1337'
        })}, Error, 'colour parameters have to be correct format')
      })
      test('should not be able to set success colour with wrong format', async function () {
        // Testing
        assert.throws(() => {new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          success: '0088ff',
          root: 'http://0.0.0.0:1337'
        })}, Error, 'colour parameters have to be correct format')
      })
      test('should not be able to set danger colour with wrong format', async function () {
        // Testing
        assert.throws(() => {
          new AuthCoreWidgets.Login({
            container: 'authcore-sign-in-widget',
            danger: '0088ff',
            root: 'http://0.0.0.0:1337'
          })
        }, Error, 'colour parameters have to be correct format')
      })
    })

    suite('Register widget', function () {
      test('should be able to have register widget with successRegister callback', function (done) {
        // Preparing
        new AuthCoreWidgets.Register({
          container: 'authcore-register-widget',
          root: 'http://0.0.0.0:1337'
        })

        window.addEventListener('message', e => {
          const { type, data } = e.data
          if (type === 'AuthCore_successRegister') {
            assert.deepEqual(data.accessToken, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        window.postMessage({
          type: 'AuthCore_successRegister',
          data: {
            accessToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw'
          }
        }, '*')
      })

      test('should be able to mount an iframe with verification attribute', async function () {
        // Preparing
        new AuthCoreWidgets.Register({
          container: 'authcore-register-widget',
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
          new AuthCoreWidgets.Register({
            container: 'authcore-register-widget',
            root: 'http://0.0.0.0:1337',
            verification: 'test'
          })
        }, Error)
      })

      test('should be able to set primary colour for Register widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Register({
          container: 'authcore-register-widget',
          primary: '#0088ff',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /primary=%230088FF/)
      })

      test('should be able to set privacyLink for Register widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Register({
          container: 'authcore-register-widget',
          privacyLink: 'http://0.0.0.0:1337',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /privacyLink=http%3A%2F%2F0.0.0.0%3A1337/)
        assert.match(iframe.src, /privacyCheckbox=false/)
      })

      test('should be able to set privacyCheckbox for Register widget', async function () {
        // Preparing
        const widget = new AuthCoreWidgets.Register({
          container: 'authcore-register-widget',
          privacyLink: 'http://0.0.0.0:1337',
          privacyCheckbox: true,
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-register-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /privacyCheckbox=true/)
      })
    })

    suite('Login widget', function () {
      test('should be able to mount an iframe with additional attributes', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/signin/)
      })

      test('should be able to call customised callback when `AuthCore_onSuccess` is message is posted', function (done) {
        // Preparing
        let callbackToken

        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        const widget = new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337',
          callbacks: {
            onSuccess: () => { callbackToken = 42 }
          }
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

    suite('Contacts widget', function () {
      test('should be able to mount an iframe with additional attributes', async function () {
        // Preparing
        new AuthCoreWidgets.Contacts({
          container: 'authcore-contacts-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-contacts-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.match(iframe.src, /^http:\/\/0.0.0.0:1337\/contacts/)
      })
    })

    suite('RefreshToken widget', function () {
      test('should be able to mount an iframe', async function () {
        // Preparing
        new AuthCoreWidgets.RefreshToken({})

        // Testing
        const iframe = document.getElementsByTagName('iframe')[0]
        assert.exists(iframe)
        assert.equal(iframe.style.display, 'none')
      })
    })
  })
})