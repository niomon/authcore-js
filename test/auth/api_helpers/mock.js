const nock = require('nock')

/**
 * @param {*} steps The steps.
 */
function mockAPI(steps) {
  nock.cleanAll()
  steps.forEach(function (step) {
    let { type, count } = step
    if (count === undefined) count = 1
    switch (type) {
      case 'SwaggerClient':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json?v=0.3.12').times(count)
          .replyWithFile(
            200, `${__dirname}/../../authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClient404':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json?v=0.3.12').times(count)
          .reply(404, '404 page not found')
        break
      case 'SwaggerMgmtClient404':
        nock('http://0.0.0.0:13337').get('/api/managementapi/management.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'GeneralAuthFail':
        nock('http://0.0.0.0:13337').get('/api/auth/users/current').times(count)
          .reply(
            400, { code: 3, error: 'InvalidArgument', message: 'InvalidArgument' }
          )
        break
      case 'GeneralMgmtFail':
        nock('http://0.0.0.0:13337').post('/api/management/users').times(count)
          .reply(
            403, { code: 7, error: 'unauthorized', message: 'unauthorized' }
          )
        break
      case 'CreateUser':
        nock('http://0.0.0.0:13337').post('/api/auth/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreatePasswordChallenge':
        nock('http://0.0.0.0:13337').get('/api/auth/users/current/password/start').times(count)
          .replyWithFile(
            200, `${__dirname}/create_password_challenge.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePasswordKeyExchange':
        nock('http://0.0.0.0:13337').post('/api/auth/users/current/password/key_exchange').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password_key_exchange.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'FinishChangePassword':
        nock('http://0.0.0.0:13337').post('/api/auth/users/current/password/finish').times(count)
          .reply(200, {})
        break
      case 'CreateAccessToken':
        nock('http://0.0.0.0:13337').post('/api/auth/tokens').times(count)
          .replyWithFile(
            200, `${__dirname}/create_access_token.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePassword':
        nock('http://0.0.0.0:13337', { reqheaders: { authorization: /^Bearer/ } })
          .post('/api/auth/users/current/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartAuthentication':
        nock('http://0.0.0.0:13337').post('/api/auth/auth').times(count)
          .replyWithFile(
            200, `${__dirname}/start_authentication.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartPasswordAuthn':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/start').times(count)
          .replyWithFile(
            200, `${__dirname}/start_password_authn.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'PasswordAuthnKeyExchange':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/key_exchange').times(count)
          .replyWithFile(
            200, `${__dirname}/password_authn_key_exchange.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'FinishPasswordAuthn':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/finish').times(count)
          .replyWithFile(
            200, `${__dirname}/finish_password_authn.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'FinishPasswordAuthnTOTP':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/finish').times(count)
          .replyWithFile(
            200, `${__dirname}/finish_password_authn_totp.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'FinishPasswordAuthnSMS':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/finish').times(count)
          .replyWithFile(
            200, `${__dirname}/finish_password_authn_sms.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'FinishPasswordAuthnWrong':
        nock('http://0.0.0.0:13337').post('/api/auth/authn/password/finish').times(count)
          .replyWithFile(
            500, `${__dirname}/finish_password_authn_wrong.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartAuthenticateSMS':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/second/start').times(count)
          .replyWithFile(
            200, `${__dirname}/start_authenticate_sms.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'Authenticate':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateWrong':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            500, `${__dirname}/authenticate_wrong.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateTOTP':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_totp.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateSMS':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_sms.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateSecondFactor':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/second').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_second_factor.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetCurrentUser':
        nock('http://0.0.0.0:13337', { reqheaders: { authorization: /^Bearer/ } })
          .get('/api/auth/users/current').times(count)
          .replyWithFile(
            200, `${__dirname}/get_current_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateCurrentUser':
        nock('http://0.0.0.0:13337', { reqheaders: { authorization: /^Bearer/ } })
          .put('/api/auth/users/current').times(count)
          .replyWithFile(
            200, `${__dirname}/update_current_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateProofOfWorkChallenge':
        nock('http://0.0.0.0:13337').post('/api/auth/challenges/proof_of_work').times(count)
          .replyWithFile(
            200, `${__dirname}/create_proof_of_work_challenge.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateTOTPAuthenticator':
        nock('http://0.0.0.0:13337', { reqheaders: { authorization: /^Bearer/ } })
          .post('/api/auth/totp_authenticators').times(count)
          .replyWithFile(
            200, `${__dirname}/create_totp_authenticator.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteTOTPAuthenticator':
        nock('http://0.0.0.0:13337', { reqheaders: { authorization: /^Bearer/ } })
          .delete('/api/auth/totp_authenticators/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_totp_authenticator.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_Email':
        nock('http://0.0.0.0:13337').post('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_email.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_Phone':
        nock('http://0.0.0.0:13337').post('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_phone.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetContact':
        nock('http://0.0.0.0:13337').get('/api/auth/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/get_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListContacts':
        nock('http://0.0.0.0:13337').get('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteContact':
        nock('http://0.0.0.0:13337').delete('/api/auth/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdatePrimaryContact':
        nock('http://0.0.0.0:13337').put('/api/auth/contacts/1/primary').times(count)
          .replyWithFile(
            200, `${__dirname}/update_primary_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartVerifyContact':
        nock('http://0.0.0.0:13337').post('/api/auth/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/start_verify_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CompleteVerifyContact':
        nock('http://0.0.0.0:13337').put('/api/auth/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/complete_verify_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListSessions':
        nock('http://0.0.0.0:13337').get('/api/auth/sessions?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_sessions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteSession':
        nock('http://0.0.0.0:13337').delete('/api/auth/sessions/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_session.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetMetadata':
        nock('http://0.0.0.0:13337').get('/api/auth/users/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/get_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateMetadata':
        nock('http://0.0.0.0:13337').put('/api/auth/users/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/update_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetCurrentUser401':
        nock('http://0.0.0.0:13337').get('/api/auth/users/current').times(count)
          .replyWithFile(
            401, `${__dirname}/get_current_user_401.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetCurrentUser403':
        nock('http://0.0.0.0:13337').get('/api/auth/users/current').times(count)
          .replyWithFile(
            403, `${__dirname}/get_current_user_403.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateContactAuthentication':
        nock('http://0.0.0.0:13337').put('/api/auth/contacts/auth').times(count)
          .replyWithFile(
            200, `${__dirname}/update_contact_authentication.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartResetPasswordAuthentication':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/reset_password').times(count)
          .replyWithFile(
            200, `${__dirname}/start_reset_password_authentication.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateResetPasswordWithContact':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/reset_password/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_reset_password.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ResetPassword':
        nock('http://0.0.0.0:13337').post('/api/auth/users/reset_password').times(count)
          .reply(200, {})
        break
      case 'SwaggerClientForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/authapi/authcore.swagger.json?v=0.3.12').times(count)
          .replyWithFile(
            200, `${__dirname}/../../authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetCurrentUserForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/auth/users/current').times(count)
          .replyWithFile(
            200, `${__dirname}/get_current_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
    }
  })
}

exports.mockAPI = mockAPI
