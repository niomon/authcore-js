/* global suite, test */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const nock = require('nock')

const { mockAPI } = require('./api_helpers/mock.js')
const { AuthCoreAuthClient } = require('../../src/auth/index.js')

chai.use(chaiAsPromised)
const { assert } = chai


suite('auth/index.js', function () {
  suite('AuthCoreAuthClient', function () {
    test('should be able to get and set access tokens', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authClient.setAccessToken(
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw'
      )
      const accessToken = authClient.getAccessToken()
      assert.equal(accessToken, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')
    })

    test('should be able to create an account', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateUser' },
        { type: 'CreateAccessToken' },
        { type: 'FinishChangePassword' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authClient.createUser({
        username: 'samuel',
        email: 'samuel@blocksq.com',
        phone: '+85298765432',
        displayName: 'Samuel',
        password: 'password'
      })
      assert.isTrue(nock.isDone())
    })

    test('should not be able to create without displayName', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 }
      ])
     // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      // Trial: Create a user without display name (throws without calling an API) 
      await assert.isRejected(authClient.createUser({
        password: 'password'
      }))
    })

    test('should not be able to create without password', async function () {
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      // Trial: Create a user without a password (throws without calling an API)
      await assert.isRejected(authClient.createUser({
        displayName: 'Samuel'
      }))
    })

    test('should be able to change password', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreatePasswordChallenge' },
        { type: 'ChangePasswordKeyExchange' },
        { type: 'FinishChangePassword' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.changePassword('old_password', 'new_password')
      assert.isTrue(nock.isDone())
    })

    test('should be able to sign in to an account with username', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartPasswordAuthn' },
        { type: 'PasswordAuthnKeyExchange' },
        { type: 'FinishPasswordAuthn' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_salt'])
      const authenticateResponse = await authClient.authenticateWithPassword('password')
      assert.isTrue(authenticateResponse['authenticated'])
      assert.isTrue(nock.isDone())
    })

    test('should not be able to sign in to an account with a wrong password', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartPasswordAuthn' },
        { type: 'PasswordAuthnKeyExchange' },
        { type: 'FinishPasswordAuthnWrong' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_salt'])
      await assert.isRejected(authClient.authenticateWithPassword('password?'))
      assert.isTrue(nock.isDone())
    })

    test('should be able to sign in to an account with username, with TOTP enabled', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartPasswordAuthn' },
        { type: 'PasswordAuthnKeyExchange' },
        { type: 'FinishPasswordAuthnTOTP' },
        { type: 'AuthenticateSecondFactor' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authClient.startAuthentication('samuel')
      const authenticateResponse = await authClient.authenticateWithPassword('password')
      assert.include(authenticateResponse['challenges'], 'TIME_BASED_ONE_TIME_PASSWORD')
      assert.exists(authenticateResponse['temporary_token'])
      const authenticateSecondFactorResponse = await authClient.authenticateWithTOTP('131072')
      assert.isTrue(authenticateSecondFactorResponse['authenticated'])
      assert.isTrue(nock.isDone())
    })

    test('should be able to sign in to an account with username, with SMS authentication enabled', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartPasswordAuthn' },
        { type: 'PasswordAuthnKeyExchange' },
        { type: 'FinishPasswordAuthnTOTP' },
        { type: 'StartAuthenticateSMS' },
        { type: 'AuthenticateSecondFactor' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authClient.startAuthentication('samuel')
      const authenticateResponse = await authClient.authenticateWithPassword('password')
      assert.include(authenticateResponse['challenges'], 'TIME_BASED_ONE_TIME_PASSWORD')
      assert.exists(authenticateResponse['temporary_token'])
      await authClient.startAuthenticateSMS()
      const authenticateSecondFactorResponse = await authClient.authenticateWithSMS('2147483647')
      assert.isTrue(authenticateSecondFactorResponse['authenticated'])
      assert.isTrue(nock.isDone())
    })

    test('should be able to obtain the current user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetCurrentUser' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.getCurrentUser()
      assert.isTrue(nock.isDone())
    })

    test('should be able to update current user profile', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'UpdateCurrentUser' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.updateCurrentUser()
      assert.isTrue(nock.isDone())
    })

    test('should be able to obtain the user metadata for the current user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetMetadata' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const metadata = await authClient.getMetadata()
      assert.equal(metadata.userMetadata, '{"favourite_links":["https://github.com","https://blocksq.com"]}')
      assert.isTrue(nock.isDone())
    })

    test('should be able update obtain the user metadata for the current user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'UpdateMetadata' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const metadata = await authClient.updateMetadata('{"favourite_links":["https://github.com","https://blocksq.com"]}')
      assert.equal(metadata.userMetadata, '{"favourite_links":["https://github.com","https://blocksq.com"]}')
      assert.isTrue(nock.isDone())
    })

    test('should be able to list sessions of a user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'ListSessions' }
      ])
      // Test
      const authcoreClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const listSessionsResponse = await authcoreClient.listSessions(10, '', false)
      assert.equal(listSessionsResponse['total_size'], 10)
      assert.exists(listSessionsResponse['sessions'])
      assert.isArray(listSessionsResponse['sessions'])
    })

    test('should be able to delete a given session', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'DeleteSession' }
      ])
      // Test
      const authcoreClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authcoreClient.deleteSession(1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to list contacts', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'ListContacts' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const listContactsResponse = await authClient.listContacts()
      assert.exists(listContactsResponse['contacts'])
      assert.typeOf(listContactsResponse['contacts'], 'array')
      assert.isTrue(nock.isDone())
    })

    test('should be able to create an email contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateContact_Email' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.createEmailContact('example@example.com')
      assert.isTrue(nock.isDone())
    })

    test('should be able to create an phone contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateContact_Phone' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.createPhoneContact('+85299965536')
      assert.isTrue(nock.isDone())
    })

    test('should be able to delete a contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'DeleteContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.deleteContact(1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to verify a contact by token', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartVerifyContact' },
        { type: 'CompleteVerifyContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.startVerifyContact(1)
      await authClient.verifyContactByToken('MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA')
      assert.isTrue(nock.isDone())
    })

    test('should be able to verify a contact by code', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartVerifyContact' },
        { type: 'CompleteVerifyContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.startVerifyContact(1)
      await authClient.verifyContactByCode('0133765536')
      assert.isTrue(nock.isDone())
    })

    test('should be able to set primary contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'UpdatePrimaryContact' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.updatePrimaryContact(1)
      assert.isTrue(nock.isDone())
    })

    test('should be able to reset password', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartResetPasswordAuthentication' },
        { type: 'AuthenticateResetPasswordWithContact' },
        { type: 'ResetPassword' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authClient.startResetPasswordAuthentication('samuel@blocksq.com')
      assert.include(startAuthenticationResponse['challenges'], 'CONTACT_TOKEN')
      assert.exists(startAuthenticationResponse['temporary_token'])

      const authenticateResetPasswordWithContactResponse = await authClient.authenticateResetPasswordWithContact('MvAm2Bn1I0KRn5RHdn1Sha9mA1q28DWkdfu480tMk8k')
      assert.isTrue(authenticateResetPasswordWithContactResponse['authenticated'])

      await authClient.resetPassword('d9DUOZdCwYGv2H_X3WJNmz-WQa56Z5s1KvnX0JgEG70', 'passw0rd')
      assert.isTrue(nock.isDone())
    })

    test('should be able to trigger the 401 callback successfully', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetCurrentUser401' }
      ])
      // Test
      let callbackCounts = 0
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        callbacks: {
          unauthenticated: function () {
            callbackCounts += 1
          }
        }
      })
      await assert.isRejected(authClient.getCurrentUser())
      assert.equal(callbackCounts, 1)
      assert.isTrue(nock.isDone())
    })

    test('should not throw another error if there are no 401 callbacks', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetCurrentUser401' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337'
      })
      await assert.isRejected(authClient.getCurrentUser())
      assert.isTrue(nock.isDone())
    })

    test('should be able to trigger the 403 callback successfully', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetCurrentUser403' }
      ])
      // Test
      let callbackCounts = 0
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        callbacks: {
          unauthorized: function (accessToken) {
            callbackCounts += 1
            assert.equal(callbackCounts, 1)
          }
        }
      })
      await assert.isRejected(authClient.getCurrentUser())
      window.postMessage({
        type: 'AuthCore_unauthenticated_tokenUpdated',
        data: {
          accessToken: 'AN_ACCESS_TOKEN'
        }
      }, '*')
      assert.isTrue(nock.isDone())
    })

    test('should not throw another error if there are no 403 callbacks', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'GetCurrentUser403' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'http://0.0.0.0:13337'
      })
      await assert.isRejected(authClient.getCurrentUser())
      assert.isTrue(nock.isDone())
    })

    test('should be able to process HTTPS requests', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClientForHTTPS' },
        { type: 'GetCurrentUserForHTTPS' }
      ])
      // Test
      const authClient = await new AuthCoreAuthClient({
        apiBaseURL: 'https://0.0.0.0:13338',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      await authClient.getCurrentUser()
      assert.isTrue(nock.isDone())
    })
  })
})
