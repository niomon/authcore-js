const nock = require('nock')

function mockAPI (steps) {
  nock.cleanAll()
  steps.forEach(function (step) {
    let { type, count } = step
    if (count === undefined) count = 1
    switch (type) {
      case 'SwaggerClient':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../../authcore/api/authapi/authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerMgmtClient':
        nock('http://0.0.0.0:13337').get('/api/managementapi/management.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../../authcore/api/managementapi/management.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerKeyVaultClient':
        nock('http://0.0.0.0:13337').get('/api/keyvaultapi/keyvault.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../../authcore/api/keyvaultapi/keyvault.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClient404':
        nock('http://0.0.0.0:13337').get('/api/authapi/authcore.swagger.json').times(count)
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
        nock('http://0.0.0.0:13337').post('/api/auth/users/current/password/challenge').times(count)
          .replyWithFile(
            200, `${__dirname}/create_password_challenge.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateAccessToken':
        nock('http://0.0.0.0:13337').post('/api/auth/tokens').times(count)
          .replyWithFile(
            200, `${__dirname}/create_access_token.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePassword':
        nock('http://0.0.0.0:13337').post('/api/auth/users/current/password').times(count)
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
      case 'StartAuthenticateSMS':
        nock('http://0.0.0.0:13337').post('/api/auth/auth/second/contact').times(count)
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
        nock('http://0.0.0.0:13337').get('/api/auth/users/current').times(count)
          .replyWithFile(
            200, `${__dirname}/get_current_user.json`,
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
        nock('http://0.0.0.0:13337').post('/api/auth/totp_authenticators').times(count)
          .replyWithFile(
            200, `${__dirname}/create_totp_authenticator.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteTOTPAuthenticator':
        nock('http://0.0.0.0:13337').delete('/api/auth/totp_authenticators/1').times(count)
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
      case 'ListOwnContacts':
        nock('http://0.0.0.0:13337').get('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteOwnContact':
        nock('http://0.0.0.0:13337').delete('/api/auth/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_contact.json`,
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
      case 'GetOwnMetadata':
        nock('http://0.0.0.0:13337').get('/api/auth/users/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/get_own_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateOwnMetadata':
        nock('http://0.0.0.0:13337').put('/api/auth/users/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/update_own_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ValidateOAuthParameters':
        nock('http://0.0.0.0:13337').get('/api/auth/oauth/validate_params?scope=email&client_id=authcore.io&state=a-valid-state&redirect_uri=http%3A%2F%2F0.0.0.0%3A8080&response_type=code').times(count)
          .reply(200, {})
        break
      case 'ValidateOAuthParameters400':
        nock('http://0.0.0.0:13337').get('/api/auth/oauth/validate_params?scope=email&client_id=authcore.io&state=a-valid-state&redirect_uri=http%3A%2F%2Fevil.com&response_type=code').times(count)
          .reply(400, { 'error': 'invalid redirect_uri', 'message': 'invalid redirect_uri', 'code': 3 })
        break
      case 'ListUsers':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_users.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers401':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            401, `${__dirname}/list_users_401.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers403':
        nock('http://0.0.0.0:13337').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            403, `${__dirname}/list_users_403.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetUser':
        nock('http://0.0.0.0:13337').get('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/get_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateUser':
        nock('http://0.0.0.0:13337').put('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/update_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_EmailByAdmin':
        nock('http://0.0.0.0:13337').post('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_email_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_PhoneByAdmin':
        nock('http://0.0.0.0:13337').post('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_phone_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteContact':
        nock('http://0.0.0.0:13337').delete('/api/management/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListContacts':
        nock('http://0.0.0.0:13337').get('/api/management/users/1/contacts?type=email').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartVerifyContactByAdmin':
        nock('http://0.0.0.0:13337').post('/api/management/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/start_verify_contact.json`,
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
      case 'ListAuditLogs':
        nock('http://0.0.0.0:13337').get('/api/management/audit_logs?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUserAuditLogs':
        nock('http://0.0.0.0:13337').get('/api/management/audit_logs?page_size=10&ascending=false&user_id=1').times(count)
          .replyWithFile(
            200, `${__dirname}/list_user_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoles':
        nock('http://0.0.0.0:13337').get('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_roles.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateRole':
        nock('http://0.0.0.0:13337').post('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/create_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteRole':
        nock('http://0.0.0.0:13337').delete('/api/management/roles/5').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AssignRole':
        nock('http://0.0.0.0:13337').post('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/assign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UnassignRole':
        nock('http://0.0.0.0:13337').delete('/api/management/users/5/roles/3').times(count)
          .replyWithFile(
            200, `${__dirname}/unassign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoleAssignments':
        nock('http://0.0.0.0:13337').get('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_role_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListPermissionAssignments':
        nock('http://0.0.0.0:13337').get('/api/management/roles/1/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_permission_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListCurrentUserPermissions':
        nock('http://0.0.0.0:13337').get('/api/management/users/current/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_current_user_permissions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetMetadata':
        nock('http://0.0.0.0:13337').get('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/get_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateMetadata':
        nock('http://0.0.0.0:13337').put('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/update_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateUserByAdmin':
        nock('http://0.0.0.0:13337').post('/api/management/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePasswordByAdmin':
        nock('http://0.0.0.0:13337').post('/api/management/users/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetMetadataByAdmin':
        nock('http://0.0.0.0:13337').get('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/get_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateMetadataByAdmin':
        nock('http://0.0.0.0:13337').put('/api/management/users/1/metadata').times(count)
          .replyWithFile(
            200, `${__dirname}/update_metadata.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'OperationListHDChildPublicKeys':
        nock('http://0.0.0.0:13337').post('/api/keyvault/operation').times(count)
          .replyWithFile(
            200, `${__dirname}/operation_list_hd_child_public_keys.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'OperationEthereumSignTx':
        nock('http://0.0.0.0:13337').post('/api/keyvault/operation').times(count)
          .replyWithFile(
            200, `${__dirname}/operation_ethereum_sign_tx.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'OperationEthereumSignMessage':
        nock('http://0.0.0.0:13337').post('/api/keyvault/operation').times(count)
          .replyWithFile(
            200, `${__dirname}/operation_ethereum_sign_message.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClientForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/authapi/authcore.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../../authcore/api/authapi/authcore.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerMgmtClientForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/managementapi/management.swagger.json').times(count)
          .replyWithFile(
            200, `${__dirname}/../../../authcore/api/managementapi/management.swagger.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'SwaggerClient404ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/authapi/authcore.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'SwaggerMgmtClient404ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/managementapi/management.swagger.json').times(count)
          .reply(404, '404 page not found')
        break
      case 'CreateUserForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateAccessTokenForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/tokens').times(count)
          .replyWithFile(
            200, `${__dirname}/create_access_token.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePasswordForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/users/current/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartAuthenticationForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth').times(count)
          .replyWithFile(
            200, `${__dirname}/start_authentication.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartAuthenticateSMSForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/second/contact').times(count)
          .replyWithFile(
            200, `${__dirname}/start_authenticate_sms.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateWrongForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            500, `${__dirname}/authenticate_wrong.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateTOTPForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_totp.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateSMSForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/first').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_sms.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AuthenticateSecondFactorForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/auth/second').times(count)
          .replyWithFile(
            200, `${__dirname}/authenticate_second_factor.json`,
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
      case 'CreateProofOfWorkChallengeForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/challenges/proof_of_work').times(count)
          .replyWithFile(
            200, `${__dirname}/create_proof_of_work_challenge.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateTOTPAuthenticatorForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/totp_authenticators').times(count)
          .replyWithFile(
            200, `${__dirname}/create_totp_authenticator.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteTOTPAuthenticatorForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/auth/totp_authenticators/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_totp_authenticator.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_EmailForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_email.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateContact_PhoneForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/create_contact_phone.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListOwnContactsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/auth/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteOwnContactForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/auth/contacts/1').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'StartVerifyContactForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/auth/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/start_verify_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CompleteVerifyContactForHTTPS':
        nock('https://0.0.0.0:13338').put('/api/auth/contacts/verify').times(count)
          .replyWithFile(
            200, `${__dirname}/complete_verify_contact.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsersForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_users.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers401ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            401, `${__dirname}/list_users_401.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUsers403ForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users?page_size=10&ascending=false').times(count)
          .replyWithFile(
            403, `${__dirname}/list_users_403.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'GetUserForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/get_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateUserForHTTPS':
        nock('https://0.0.0.0:13338').put('/api/management/users/1').times(count)
          .replyWithFile(
            200, `${__dirname}/update_user.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListContactsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/1/contacts').times(count)
          .replyWithFile(
            200, `${__dirname}/list_contacts.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UpdateContactAuthenticationForHTTPS':
        nock('https://0.0.0.0:13338').put('/api/auth/contacts/auth').times(count)
          .replyWithFile(
            200, `${__dirname}/update_contact_authentication.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListAuditLogsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/audit_logs?page_size=10&ascending=false').times(count)
          .replyWithFile(
            200, `${__dirname}/list_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListUserAuditLogsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/audit_logs?page_size=10&ascending=false&user_id=1').times(count)
          .replyWithFile(
            200, `${__dirname}/list_user_audit_logs.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRolesForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_roles.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateRoleForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/create_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'DeleteRoleForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/management/roles/5').times(count)
          .replyWithFile(
            200, `${__dirname}/delete_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'AssignRoleForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/assign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'UnassignRoleForHTTPS':
        nock('https://0.0.0.0:13338').delete('/api/management/users/5/roles/3').times(count)
          .replyWithFile(
            200, `${__dirname}/unassign_role.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListRoleAssignmentsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/5/roles').times(count)
          .replyWithFile(
            200, `${__dirname}/list_role_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListPermissionAssignmentsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/roles/1/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_permission_assignments.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ListCurrentUserPermissionsForHTTPS':
        nock('https://0.0.0.0:13338').get('/api/management/users/current/permissions').times(count)
          .replyWithFile(
            200, `${__dirname}/list_current_user_permissions.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'CreateUserByAdminForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users').times(count)
          .replyWithFile(
            200, `${__dirname}/create_user_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
      case 'ChangePasswordByAdminForHTTPS':
        nock('https://0.0.0.0:13338').post('/api/management/users/password').times(count)
          .replyWithFile(
            200, `${__dirname}/change_password_by_admin.json`,
            { 'Content-Type': 'application/json' }
          )
        break
    }
  })
}

exports.mockAPI = mockAPI
